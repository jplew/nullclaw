const std = @import("std");
const AtomicBool = std.atomic.Value(bool);

threadlocal var thread_interrupt_flag: ?*const AtomicBool = null;

pub fn setThreadInterruptFlag(flag: ?*const AtomicBool) void {
    thread_interrupt_flag = flag;
}

/// Result of a child process execution.
pub const RunResult = struct {
    stdout: []u8,
    stderr: []u8,
    success: bool,
    exit_code: ?u32 = null,
    interrupted: bool = false,
    timed_out: bool = false,

    /// Free both stdout and stderr buffers.
    pub fn deinit(self: *const RunResult, allocator: std.mem.Allocator) void {
        if (self.stdout.len > 0) allocator.free(self.stdout);
        if (self.stderr.len > 0) allocator.free(self.stderr);
    }
};

/// Options for running a child process.
pub const RunOptions = struct {
    cwd: ?[]const u8 = null,
    env_map: ?*std.process.EnvMap = null,
    max_output_bytes: usize = 1_048_576,
    cancel_flag: ?*const AtomicBool = null,
    timeout_ns: ?u64 = null,
};

const TerminationWatcherCtx = struct {
    child: *std.process.Child,
    cancel_flag: ?*const AtomicBool,
    timeout_deadline_ns: ?i128,
    done: *AtomicBool,
    timed_out: *AtomicBool,
};

fn terminateChild(child: *std.process.Child) void {
    if (comptime @import("builtin").os.tag == .windows) {
        std.os.windows.TerminateProcess(child.id, 1) catch {};
    } else {
        std.posix.kill(child.id, std.posix.SIG.TERM) catch {};
    }
}

fn terminationWatcherMain(ctx: *TerminationWatcherCtx) void {
    while (!ctx.done.load(.acquire)) {
        if (ctx.cancel_flag) |cancel_flag| {
            if (cancel_flag.load(.acquire)) {
                terminateChild(ctx.child);
                break;
            }
        }
        if (ctx.timeout_deadline_ns) |deadline_ns| {
            if (std.time.nanoTimestamp() >= deadline_ns) {
                ctx.timed_out.store(true, .release);
                terminateChild(ctx.child);
                break;
            }
        }
        std.Thread.sleep(20 * std.time.ns_per_ms);
    }
}

/// Run a child process, capture stdout and stderr, and return the result.
///
/// The caller owns the returned stdout and stderr buffers.
/// Use `result.deinit(allocator)` to free them.
pub fn run(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    opts: RunOptions,
) !RunResult {
    var child = std.process.Child.init(argv, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    if (opts.cwd) |cwd| child.cwd = cwd;
    if (opts.env_map) |env| child.env_map = env;

    try child.spawn();

    const effective_cancel_flag = opts.cancel_flag orelse thread_interrupt_flag;
    const timeout_deadline_ns: ?i128 = if (opts.timeout_ns) |timeout_ns|
        std.time.nanoTimestamp() + @as(i128, @intCast(timeout_ns))
    else
        null;
    var cancel_done = AtomicBool.init(false);
    var timed_out = AtomicBool.init(false);
    var termination_watcher: ?std.Thread = null;
    var watcher_ctx: TerminationWatcherCtx = undefined;
    if (effective_cancel_flag != null or timeout_deadline_ns != null) {
        watcher_ctx = .{
            .child = &child,
            .cancel_flag = effective_cancel_flag,
            .timeout_deadline_ns = timeout_deadline_ns,
            .done = &cancel_done,
            .timed_out = &timed_out,
        };
        termination_watcher = std.Thread.spawn(.{}, terminationWatcherMain, .{&watcher_ctx}) catch null;
    }
    defer {
        cancel_done.store(true, .release);
        if (termination_watcher) |t| t.join();
    }

    var stdout_buf: std.ArrayList(u8) = .empty;
    defer stdout_buf.deinit(allocator);
    var stderr_buf: std.ArrayList(u8) = .empty;
    defer stderr_buf.deinit(allocator);

    std.process.Child.collectOutput(child, allocator, &stdout_buf, &stderr_buf, opts.max_output_bytes) catch |err| {
        const canceled = effective_cancel_flag != null and effective_cancel_flag.?.load(.acquire);
        if (canceled or timed_out.load(.acquire)) {
            // Process was intentionally terminated; swallow stream read errors.
        } else {
            return err;
        }
    };

    const stdout = try stdout_buf.toOwnedSlice(allocator);
    errdefer allocator.free(stdout);
    const stderr = try stderr_buf.toOwnedSlice(allocator);
    errdefer allocator.free(stderr);

    const term = try child.wait();
    const interrupted = if (effective_cancel_flag) |flag| flag.load(.acquire) else false;
    const was_timed_out = timed_out.load(.acquire);

    return switch (term) {
        .Exited => |code| .{
            .stdout = stdout,
            .stderr = stderr,
            .success = code == 0,
            .exit_code = code,
            .interrupted = interrupted,
            .timed_out = was_timed_out,
        },
        else => .{
            .stdout = stdout,
            .stderr = stderr,
            .success = false,
            .exit_code = null,
            .interrupted = interrupted,
            .timed_out = was_timed_out,
        },
    };
}

// ── Tests ───────────────────────────────────────────────────────────

const builtin = @import("builtin");

test "run echo returns stdout" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const result = try run(allocator, &.{ "echo", "hello" }, .{});
    defer result.deinit(allocator);

    try std.testing.expect(result.success);
    try std.testing.expectEqual(@as(u32, 0), result.exit_code.?);
    try std.testing.expect(std.mem.indexOf(u8, result.stdout, "hello") != null);
}

test "run failing command returns exit code" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const result = try run(allocator, &.{ "ls", "/nonexistent_dir_xyz_42" }, .{});
    defer result.deinit(allocator);

    try std.testing.expect(!result.success);
    try std.testing.expect(result.exit_code.? != 0);
    try std.testing.expect(result.stderr.len > 0);
}

test "run with cwd" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const result = try run(allocator, &.{"pwd"}, .{ .cwd = "/tmp" });
    defer result.deinit(allocator);

    try std.testing.expect(result.success);
    // /tmp may resolve to /private/tmp on macOS
    try std.testing.expect(result.stdout.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, result.stdout, "tmp") != null);
}

test "run honors cancel flag and interrupts child" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    var cancel = AtomicBool.init(false);

    const ThreadResult = struct {
        res: ?RunResult = null,
        err: ?anyerror = null,
    };
    var thread_result = ThreadResult{};

    const Runner = struct {
        fn runThread(
            allocator_inner: std.mem.Allocator,
            cancel_flag: *const AtomicBool,
            out: *ThreadResult,
        ) void {
            out.res = run(allocator_inner, &.{ "sh", "-c", "sleep 5; echo done" }, .{
                .cancel_flag = cancel_flag,
            }) catch |err| {
                out.err = err;
                return;
            };
        }
    };

    const t = try std.Thread.spawn(.{}, Runner.runThread, .{ allocator, &cancel, &thread_result });
    std.Thread.sleep(100 * std.time.ns_per_ms);
    cancel.store(true, .release);
    t.join();

    try std.testing.expect(thread_result.err == null);
    const result = thread_result.res orelse return error.TestUnexpectedResult;
    defer result.deinit(allocator);
    try std.testing.expect(!result.success);
    try std.testing.expect(result.interrupted);
}

test "run honors timeout and terminates child" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    const result = try run(allocator, &.{ "sh", "-c", "sleep 5; echo done" }, .{
        .timeout_ns = 150 * std.time.ns_per_ms,
    });
    defer result.deinit(allocator);

    try std.testing.expect(!result.success);
    try std.testing.expect(result.timed_out);
}

test "RunResult deinit frees buffers" {
    const allocator = std.testing.allocator;
    const stdout = try allocator.dupe(u8, "output");
    const stderr = try allocator.dupe(u8, "error");
    const result = RunResult{
        .stdout = stdout,
        .stderr = stderr,
        .success = true,
        .exit_code = 0,
    };
    result.deinit(allocator);
}

test "RunResult deinit with empty buffers" {
    const allocator = std.testing.allocator;
    const result = RunResult{
        .stdout = "",
        .stderr = "",
        .success = true,
        .exit_code = 0,
    };
    result.deinit(allocator); // should not crash or attempt to free ""
}
