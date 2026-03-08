const std = @import("std");
const platform = @import("../platform.zig");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const isResolvedPathAllowed = @import("path_security.zig").isResolvedPathAllowed;
const SecurityPolicy = @import("../security/policy.zig").SecurityPolicy;
const audit_mod = @import("../security/audit.zig");
const json_miniparse = @import("../json_miniparse.zig");
const UNAVAILABLE_WORKSPACE_SENTINEL = "/__nullclaw_workspace_unavailable__";

/// Default maximum shell command execution time (nanoseconds).
const DEFAULT_SHELL_TIMEOUT_NS: u64 = 60 * std.time.ns_per_s;
/// Default maximum output size in bytes (1MB).
const DEFAULT_MAX_OUTPUT_BYTES: usize = 1_048_576;
/// Environment variables safe to pass to shell commands.
const SAFE_ENV_VARS = [_][]const u8{
    "PATH", "HOME", "TERM", "LANG", "LC_ALL", "LC_CTYPE", "USER", "SHELL", "TMPDIR",
};

fn normalizeCommandInput(command: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, command, " \t\r\n");
    if (unwrapMarkdownFence(trimmed)) |unfenced| {
        return std.mem.trim(u8, unfenced, " \t\r\n");
    }
    return trimmed;
}

fn unwrapMarkdownFence(command: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, command, "```")) return null;
    const after_open = command[3..];
    const close_idx = std.mem.lastIndexOf(u8, after_open, "```") orelse return null;
    const trailing = std.mem.trim(u8, after_open[close_idx + 3 ..], " \t\r\n");
    if (trailing.len != 0) return null;

    const fenced_body = after_open[0..close_idx];
    const content = if (std.mem.indexOfScalar(u8, fenced_body, '\n')) |first_newline|
        fenced_body[first_newline + 1 ..]
    else
        fenced_body;
    const trimmed_content = std.mem.trim(u8, content, " \t\r\n");
    if (trimmed_content.len == 0) return null;
    return trimmed_content;
}

/// Shell command execution tool with workspace scoping.
pub const ShellTool = struct {
    workspace_dir: []const u8,
    allowed_paths: []const []const u8 = &.{},
    timeout_ns: u64 = DEFAULT_SHELL_TIMEOUT_NS,
    max_output_bytes: usize = DEFAULT_MAX_OUTPUT_BYTES,
    policy: ?*const SecurityPolicy = null,
    audit_logger: ?*const audit_mod.AuditLogger = null,
    audit_channel: []const u8 = "runtime",
    audit_capture_output: bool = false,
    audit_max_output_bytes: usize = 2048,

    pub const tool_name = "shell";
    pub const tool_description = "Execute a shell command in the workspace directory";
    pub const tool_params =
        \\{"type":"object","properties":{"command":{"type":"string","description":"The shell command to execute"},"cwd":{"type":"string","description":"Working directory (absolute path within allowed paths; defaults to workspace)"}},"required":["command"]}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *ShellTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *ShellTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const started_ms = std.time.milliTimestamp();
        // Parse the command from the pre-parsed JSON object
        const command_input = root.getString(args, "command") orelse
            return ToolResult.fail("Missing 'command' parameter");
        const command = normalizeCommandInput(command_input);

        var risk_level: []const u8 = "none";

        // Validate command against security policy
        if (self.policy) |pol| {
            _ = pol.validateCommandExecution(command, false) catch |err| {
                const elapsed_ms = elapsedMillis(started_ms);
                risk_level = pol.commandRiskLevel(command).toString();
                self.logCommandEvent(command, risk_level, false, false, false, elapsed_ms, null, null, false, false);
                self.logPolicyViolationEvent(command, risk_level, elapsed_ms, @errorName(err));
                return switch (err) {
                    error.CommandNotAllowed => ToolResult.fail("Command not allowed by security policy"),
                    error.HighRiskBlocked => ToolResult.fail("High-risk command blocked by security policy"),
                    error.ApprovalRequired => blk: {
                        const msg = try std.fmt.allocPrint(allocator, "Command requires approval (medium/high risk): {s}", .{command});
                        break :blk ToolResult{ .success = false, .output = "", .error_msg = msg };
                    },
                };
            };
            risk_level = pol.commandRiskLevel(command).toString();
        }

        // Determine working directory
        const effective_cwd = if (root.getString(args, "cwd")) |cwd| blk: {
            // cwd must be absolute
            if (cwd.len == 0 or !std.fs.path.isAbsolute(cwd))
                return ToolResult.fail("cwd must be an absolute path");
            // Resolve and validate
            const resolved_cwd = std.fs.cwd().realpathAlloc(allocator, cwd) catch |err| {
                const msg = try std.fmt.allocPrint(allocator, "Failed to resolve cwd: {}", .{err});
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            };
            defer allocator.free(resolved_cwd);

            const ws_resolved: ?[]const u8 = std.fs.cwd().realpathAlloc(allocator, self.workspace_dir) catch null;
            defer if (ws_resolved) |wr| allocator.free(wr);
            if (ws_resolved == null and self.allowed_paths.len == 0)
                return ToolResult.fail("cwd not allowed (workspace unavailable and no allowed_paths configured)");

            if (!isResolvedPathAllowed(allocator, resolved_cwd, ws_resolved orelse UNAVAILABLE_WORKSPACE_SENTINEL, self.allowed_paths))
                return ToolResult.fail("cwd is outside allowed areas");

            break :blk cwd;
        } else self.workspace_dir;

        // Clear environment to prevent leaking API keys (CWE-200),
        // then re-add only safe, functional variables.
        var env = std.process.EnvMap.init(allocator);
        defer env.deinit();
        for (&SAFE_ENV_VARS) |key| {
            if (platform.getEnvOrNull(allocator, key)) |val| {
                defer allocator.free(val);
                try env.put(key, val);
            }
        }

        // Execute via platform shell
        const proc = @import("process_util.zig");
        const result = try proc.run(allocator, &.{ platform.getShell(), platform.getShellFlag(), command }, .{
            .cwd = effective_cwd,
            .env_map = &env,
            .max_output_bytes = self.max_output_bytes,
            .timeout_ns = self.timeout_ns,
        });
        defer allocator.free(result.stderr);
        const elapsed_ms = elapsedMillis(started_ms);
        const capture_output = self.audit_capture_output and self.audit_logger != null and self.audit_max_output_bytes > 0;

        var audit_stdout: ?[]u8 = null;
        var audit_stderr: ?[]u8 = null;
        var stdout_truncated = false;
        var stderr_truncated = false;
        defer if (audit_stdout) |s| allocator.free(s);
        defer if (audit_stderr) |s| allocator.free(s);

        if (capture_output) {
            if (result.stdout.len > 0) {
                const capped = try sanitizeOutputForAudit(allocator, result.stdout, self.audit_max_output_bytes);
                audit_stdout = capped.text;
                stdout_truncated = capped.truncated;
            }
            if (result.stderr.len > 0) {
                const capped = try sanitizeOutputForAudit(allocator, result.stderr, self.audit_max_output_bytes);
                audit_stderr = capped.text;
                stderr_truncated = capped.truncated;
            }
        }

        if (result.success) {
            self.logCommandEvent(command, risk_level, false, true, true, elapsed_ms, audit_stdout, audit_stderr, stdout_truncated, stderr_truncated);
            if (result.stdout.len > 0) return ToolResult{ .success = true, .output = result.stdout };
            allocator.free(result.stdout);
            return ToolResult{ .success = true, .output = try allocator.dupe(u8, "(no output)") };
        }
        self.logCommandEvent(command, risk_level, false, true, false, elapsed_ms, audit_stdout, audit_stderr, stdout_truncated, stderr_truncated);
        defer allocator.free(result.stdout);
        if (result.interrupted) {
            return ToolResult{ .success = false, .output = "", .error_msg = "Interrupted by /stop" };
        }
        if (result.timed_out) {
            const timeout_secs = self.timeout_ns / std.time.ns_per_s;
            const msg = try std.fmt.allocPrint(
                allocator,
                "Command timed out after {d} second{s}",
                .{ timeout_secs, if (timeout_secs == 1) "" else "s" },
            );
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }
        if (result.exit_code != null) {
            const err_out = try allocator.dupe(u8, if (result.stderr.len > 0) result.stderr else "Command failed with non-zero exit code");
            return ToolResult{ .success = false, .output = "", .error_msg = err_out };
        }
        return ToolResult{ .success = false, .output = "", .error_msg = "Command terminated by signal" };
    }

    fn elapsedMillis(started_ms: i64) u64 {
        const now_ms = std.time.milliTimestamp();
        if (now_ms <= started_ms) return 0;
        return @intCast(now_ms - started_ms);
    }

    fn logCommandEvent(
        self: *const ShellTool,
        command: []const u8,
        risk_level: []const u8,
        approved: bool,
        allowed: bool,
        success: bool,
        duration_ms: u64,
        stdout: ?[]const u8,
        stderr: ?[]const u8,
        stdout_truncated: bool,
        stderr_truncated: bool,
    ) void {
        const logger = self.audit_logger orelse return;
        logger.logCommand(.{
            .channel = self.audit_channel,
            .command = command,
            .risk_level = risk_level,
            .approved = approved,
            .allowed = allowed,
            .success = success,
            .duration_ms = duration_ms,
            .stdout = stdout,
            .stderr = stderr,
            .stdout_truncated = stdout_truncated,
            .stderr_truncated = stderr_truncated,
        }) catch {};
    }

    fn logPolicyViolationEvent(
        self: *const ShellTool,
        command: []const u8,
        risk_level: []const u8,
        duration_ms: u64,
        err_msg: []const u8,
    ) void {
        const logger = self.audit_logger orelse return;
        var event = audit_mod.AuditEvent.init(.policy_violation)
            .withActor(self.audit_channel, null, null)
            .withAction(command, risk_level, false, false)
            .withResult(false, null, duration_ms, err_msg);
        event.security.policy_violation = true;
        logger.log(&event) catch {};
    }

    const SanitizedOutput = struct {
        text: []u8,
        truncated: bool,
    };

    fn sanitizeOutputForAudit(allocator: std.mem.Allocator, input: []const u8, max_bytes: usize) !SanitizedOutput {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(allocator);
        var truncated = false;

        for (input) |c| {
            if (out.items.len >= max_bytes) {
                truncated = true;
                break;
            }
            const mapped: u8 = switch (c) {
                '\n', '\r', '\t' => c,
                else => if (c < 0x20 or c == 0x7f) ' ' else c,
            };
            try out.append(allocator, mapped);
        }

        if (containsSensitiveContent(out.items)) {
            return .{
                .text = try allocator.dupe(u8, "[REDACTED_POTENTIAL_SECRET]"),
                .truncated = false,
            };
        }
        return .{
            .text = try out.toOwnedSlice(allocator),
            .truncated = truncated,
        };
    }

    fn containsSensitiveContent(text: []const u8) bool {
        return std.mem.indexOf(u8, text, "BEGIN PRIVATE KEY") != null or
            std.mem.indexOf(u8, text, "BEGIN RSA PRIVATE KEY") != null or
            std.mem.indexOf(u8, text, "Authorization: Bearer ") != null or
            std.mem.indexOf(u8, text, "AWS_SECRET_ACCESS_KEY") != null or
            std.mem.indexOf(u8, text, "OPENAI_API_KEY") != null or
            std.mem.indexOf(u8, text, "ANTHROPIC_API_KEY") != null or
            std.mem.indexOf(u8, text, "sk-or-") != null or
            std.mem.indexOf(u8, text, "sk-ant-") != null or
            std.mem.indexOf(u8, text, "sk-proj-") != null;
    }
};

/// Extract a string field value from a JSON blob (minimal parser — no allocations).
/// NOTE: Prefer root.getString() with pre-parsed ObjectMap for tool implementations.
pub fn parseStringField(json: []const u8, key: []const u8) ?[]const u8 {
    return json_miniparse.parseStringField(json, key);
}

/// Extract a boolean field value from a JSON blob.
pub fn parseBoolField(json: []const u8, key: []const u8) ?bool {
    return json_miniparse.parseBoolField(json, key);
}

/// Extract an integer field value from a JSON blob.
pub fn parseIntField(json: []const u8, key: []const u8) ?i64 {
    return json_miniparse.parseIntField(json, key);
}

// ── Tests ───────────────────────────────────────────────────────────

test "shell tool name" {
    var st = ShellTool{ .workspace_dir = "/tmp" };
    const t = st.tool();
    try std.testing.expectEqualStrings("shell", t.name());
}

test "shell tool schema has command" {
    var st = ShellTool{ .workspace_dir = "/tmp" };
    const t = st.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "command") != null);
}

test "shell executes echo" {
    var st = ShellTool{ .workspace_dir = "." };
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"command\": \"echo hello\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "hello") != null);
}

test "shell captures failing command" {
    var st = ShellTool{ .workspace_dir = "." };
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"command\": \"ls /nonexistent_dir_xyz_42\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
}

test "shell reports interruption when cancel flag is set" {
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;

    var st = ShellTool{ .workspace_dir = "." };
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"command\": \"sleep 5\"}");
    defer parsed.deinit();

    var cancel = std.atomic.Value(bool).init(true);
    @import("process_util.zig").setThreadInterruptFlag(&cancel);
    defer @import("process_util.zig").setThreadInterruptFlag(null);

    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);

    try std.testing.expect(!result.success);
    try std.testing.expect(result.error_msg != null);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Interrupted") != null);
}

test "shell times out long-running command" {
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;

    var st = ShellTool{
        .workspace_dir = ".",
        .timeout_ns = 200 * std.time.ns_per_ms,
    };
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"command\": \"sleep 5\"}");
    defer parsed.deinit();

    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(!result.success);
    try std.testing.expect(result.error_msg != null);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "timed out") != null);
}

test "shell missing command param" {
    var st = ShellTool{ .workspace_dir = "." };
    const t = st.tool();
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(result.error_msg != null);
}

test "parseStringField basic" {
    const json = "{\"command\": \"echo hello\", \"other\": \"val\"}";
    const val = parseStringField(json, "command");
    try std.testing.expect(val != null);
    try std.testing.expectEqualStrings("echo hello", val.?);
}

test "parseStringField missing" {
    const json = "{\"other\": \"val\"}";
    try std.testing.expect(parseStringField(json, "command") == null);
}

test "parseBoolField true" {
    const json = "{\"cached\": true}";
    try std.testing.expectEqual(@as(?bool, true), parseBoolField(json, "cached"));
}

test "parseBoolField false" {
    const json = "{\"cached\": false}";
    try std.testing.expectEqual(@as(?bool, false), parseBoolField(json, "cached"));
}

test "parseIntField positive" {
    const json = "{\"limit\": 42}";
    try std.testing.expectEqual(@as(?i64, 42), parseIntField(json, "limit"));
}

test "parseIntField negative" {
    const json = "{\"offset\": -5}";
    try std.testing.expectEqual(@as(?i64, -5), parseIntField(json, "offset"));
}

test "shell cwd inside workspace works without allowed_paths" {
    const builtin = @import("builtin");
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest; // pwd not available on Windows

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    var args_buf: [512]u8 = undefined;
    const args = try std.fmt.bufPrint(&args_buf, "{{\"command\": \"pwd\", \"cwd\": \"{s}\"}}", .{tmp_path});

    var st = ShellTool{ .workspace_dir = tmp_path };
    const parsed = try root.parseTestArgs(args);
    defer parsed.deinit();
    const result = try st.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, tmp_path) != null);
}

test "shell cwd outside workspace without allowed_paths is rejected" {
    const builtin = @import("builtin");
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest; // pwd not available on Windows

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try tmp_dir.dir.makeDir("ws");
    try tmp_dir.dir.makeDir("other");
    const root_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const ws_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "ws" });
    defer std.testing.allocator.free(ws_path);
    const other_path = try std.fs.path.join(std.testing.allocator, &.{ root_path, "other" });
    defer std.testing.allocator.free(other_path);

    var args_buf: [768]u8 = undefined;
    const args = try std.fmt.bufPrint(&args_buf, "{{\"command\": \"pwd\", \"cwd\": \"{s}\"}}", .{other_path});

    var st = ShellTool{ .workspace_dir = ws_path };
    const parsed = try root.parseTestArgs(args);
    defer parsed.deinit();
    const result = try st.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "outside allowed areas") != null);
}

test "shell cwd relative path is rejected" {
    var st = ShellTool{ .workspace_dir = "/tmp", .allowed_paths = &.{"/tmp"} };
    const parsed = try root.parseTestArgs("{\"command\": \"pwd\", \"cwd\": \"relative\"}");
    defer parsed.deinit();
    const result = try st.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "absolute") != null);
}

test "shell cwd with allowed_paths runs in cwd" {
    const builtin = @import("builtin");
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest; // pwd not available on Windows

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    var args_buf: [512]u8 = undefined;
    const args = try std.fmt.bufPrint(&args_buf, "{{\"command\": \"pwd\", \"cwd\": \"{s}\"}}", .{tmp_path});

    const parsed = try root.parseTestArgs(args);
    defer parsed.deinit();

    var st = ShellTool{ .workspace_dir = ".", .allowed_paths = &.{tmp_path} };
    const result = try st.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, tmp_path) != null);
}

test "shell ApprovalRequired error includes command name" {
    const policy_mod = @import("../security/policy.zig");
    var tracker = policy_mod.RateTracker.init(std.testing.allocator, 100);
    defer tracker.deinit();
    const allowed = [_][]const u8{ "git", "ls", "cat", "grep", "echo", "touch" };
    var policy = policy_mod.SecurityPolicy{
        .autonomy = .supervised,
        .workspace_dir = "/tmp",
        .require_approval_for_medium_risk = true,
        .block_high_risk_commands = false,
        .tracker = &tracker,
        .allowed_commands = &allowed,
    };

    var st = ShellTool{ .workspace_dir = "/tmp", .policy = &policy };
    const parsed = try root.parseTestArgs("{\"command\": \"touch test.txt\"}");
    defer parsed.deinit();
    const result = try st.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);

    try std.testing.expect(!result.success);
    try std.testing.expect(result.error_msg != null);
    defer std.testing.allocator.free(result.error_msg.?);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "touch test.txt") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "approval") != null);
}

test "shell ApprovalRequired propagates oom for error message allocation" {
    const policy_mod = @import("../security/policy.zig");
    var tracker = policy_mod.RateTracker.init(std.testing.allocator, 100);
    defer tracker.deinit();
    const allowed = [_][]const u8{ "git", "ls", "cat", "grep", "echo", "touch" };
    var policy = policy_mod.SecurityPolicy{
        .autonomy = .supervised,
        .workspace_dir = "/tmp",
        .require_approval_for_medium_risk = true,
        .block_high_risk_commands = false,
        .tracker = &tracker,
        .allowed_commands = &allowed,
    };

    var st = ShellTool{ .workspace_dir = "/tmp", .policy = &policy };
    const parsed = try root.parseTestArgs("{\"command\": \"touch test.txt\"}");
    defer parsed.deinit();

    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(
        error.OutOfMemory,
        st.execute(failing.allocator(), parsed.value.object),
    );
}

test "shell wildcard policy permits command outside default allowlist" {
    const builtin = @import("builtin");
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;

    const policy_mod = @import("../security/policy.zig");
    var restrictive_tracker = policy_mod.RateTracker.init(std.testing.allocator, 10000);
    defer restrictive_tracker.deinit();
    var restrictive_policy = policy_mod.SecurityPolicy{
        .autonomy = .supervised,
        .workspace_dir = "/tmp",
        .allowed_commands = &policy_mod.default_allowed_commands,
        .block_high_risk_commands = false,
        .require_approval_for_medium_risk = false,
        .tracker = &restrictive_tracker,
    };

    var restrictive_tool = ShellTool{ .workspace_dir = "/tmp", .policy = &restrictive_policy };
    const restricted_args = try root.parseTestArgs("{\"command\": \"true\"}");
    defer restricted_args.deinit();
    const restricted = try restrictive_tool.execute(std.testing.allocator, restricted_args.value.object);
    defer if (restricted.output.len > 0) std.testing.allocator.free(restricted.output);
    try std.testing.expect(!restricted.success);
    try std.testing.expect(restricted.error_msg != null);
    try std.testing.expect(std.mem.indexOf(u8, restricted.error_msg.?, "Command not allowed") != null);

    var wildcard_tracker = policy_mod.RateTracker.init(std.testing.allocator, 10000);
    defer wildcard_tracker.deinit();
    var wildcard_policy = policy_mod.SecurityPolicy{
        .autonomy = .full,
        .workspace_dir = "/tmp",
        .allowed_commands = &.{"*"},
        .block_high_risk_commands = false,
        .require_approval_for_medium_risk = false,
        .tracker = &wildcard_tracker,
    };

    var st = ShellTool{ .workspace_dir = "/tmp", .policy = &wildcard_policy };

    const parsed = try root.parseTestArgs("{\"command\": \"true\"}");
    defer parsed.deinit();
    const result = try st.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(result.success);
}

test "shell wildcard policy allows stderr redirect to dev null" {
    const builtin = @import("builtin");
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;

    const policy_mod = @import("../security/policy.zig");
    var tracker = policy_mod.RateTracker.init(std.testing.allocator, 10000);
    defer tracker.deinit();
    var wildcard_policy = policy_mod.SecurityPolicy{
        .autonomy = .full,
        .workspace_dir = "/tmp",
        .allowed_commands = &.{"*"},
        .block_high_risk_commands = false,
        .require_approval_for_medium_risk = false,
        .tracker = &tracker,
    };

    var st = ShellTool{ .workspace_dir = "/tmp", .policy = &wildcard_policy };
    const parsed = try root.parseTestArgs("{\"command\": \"ls /definitely-missing-file 2>/dev/null || echo missing\"}");
    defer parsed.deinit();
    const result = try st.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "missing") != null);
}

test "shell accepts markdown-fenced command payload" {
    const builtin = @import("builtin");
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;

    const policy_mod = @import("../security/policy.zig");
    var tracker = policy_mod.RateTracker.init(std.testing.allocator, 1000);
    defer tracker.deinit();
    var policy = policy_mod.SecurityPolicy{
        .autonomy = .full,
        .workspace_dir = "/tmp",
        .allowed_commands = &.{"*"},
        .block_high_risk_commands = false,
        .require_approval_for_medium_risk = false,
        .tracker = &tracker,
    };

    var st = ShellTool{ .workspace_dir = "/tmp", .policy = &policy };
    const parsed = try root.parseTestArgs("{\"command\": \"```bash\\necho fenced\\n```\"}");
    defer parsed.deinit();
    const result = try st.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "fenced") != null);
}

test "shell keeps subshell backticks blocked after fenced markdown normalization" {
    const policy_mod = @import("../security/policy.zig");
    var tracker = policy_mod.RateTracker.init(std.testing.allocator, 1000);
    defer tracker.deinit();
    var policy = policy_mod.SecurityPolicy{
        .autonomy = .full,
        .workspace_dir = "/tmp",
        .allowed_commands = &.{"*"},
        .block_high_risk_commands = false,
        .require_approval_for_medium_risk = false,
        .tracker = &tracker,
    };

    var st = ShellTool{ .workspace_dir = "/tmp", .policy = &policy };
    const parsed = try root.parseTestArgs("{\"command\": \"```bash\\necho `whoami`\\n```\"}");
    defer parsed.deinit();
    const result = try st.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
    try std.testing.expect(result.error_msg != null);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Command not allowed") != null);
}

test "shell without policy executes command" {
    const builtin = @import("builtin");
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;

    var st = ShellTool{ .workspace_dir = "/tmp", .policy = null };

    const parsed = try root.parseTestArgs("{\"command\": \"echo no-policy\"}");
    defer parsed.deinit();
    const result = try st.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(result.success);
}

test "shell audit logger writes command execution events" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    var logger = try audit_mod.AuditLogger.init(std.testing.allocator, .{
        .enabled = true,
        .log_path = "shell_audit.log",
        .max_size_mb = 10,
    }, tmp_path);
    defer logger.deinit();

    var st = ShellTool{
        .workspace_dir = tmp_path,
        .audit_logger = &logger,
        .audit_channel = "runtime",
    };
    const parsed = try root.parseTestArgs("{\"command\": \"echo audit-test\"}");
    defer parsed.deinit();
    const result = try st.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(result.success);

    const content = try tmp_dir.dir.readFileAlloc(std.testing.allocator, "shell_audit.log", 4096);
    defer std.testing.allocator.free(content);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"event_type\":\"command_execution\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "audit-test") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"stdout\"") == null);
}

test "shell audit logger captures stdout when enabled" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    var logger = try audit_mod.AuditLogger.init(std.testing.allocator, .{
        .enabled = true,
        .log_path = "shell_audit_verbose.log",
        .max_size_mb = 10,
        .capture_shell_output = true,
        .max_output_bytes = 8,
    }, tmp_path);
    defer logger.deinit();

    var st = ShellTool{
        .workspace_dir = tmp_path,
        .audit_logger = &logger,
        .audit_channel = "runtime",
        .audit_capture_output = true,
        .audit_max_output_bytes = 8,
    };
    const parsed = try root.parseTestArgs("{\"command\": \"printf 'abcdefghijklmnop'\"}");
    defer parsed.deinit();
    const result = try st.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(result.success);

    const content = try tmp_dir.dir.readFileAlloc(std.testing.allocator, "shell_audit_verbose.log", 4096);
    defer std.testing.allocator.free(content);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"stdout\":\"abcdefgh\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"stdout_truncated\":true") != null);
}

test "shell audit logger redacts sensitive stdout" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    var logger = try audit_mod.AuditLogger.init(std.testing.allocator, .{
        .enabled = true,
        .log_path = "shell_audit_redact.log",
        .max_size_mb = 10,
        .capture_shell_output = true,
        .max_output_bytes = 256,
    }, tmp_path);
    defer logger.deinit();

    var st = ShellTool{
        .workspace_dir = tmp_path,
        .audit_logger = &logger,
        .audit_channel = "runtime",
        .audit_capture_output = true,
        .audit_max_output_bytes = 256,
    };
    const parsed = try root.parseTestArgs("{\"command\": \"echo sk-or-secret-value\"}");
    defer parsed.deinit();
    const result = try st.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(result.success);

    const content = try tmp_dir.dir.readFileAlloc(std.testing.allocator, "shell_audit_redact.log", 4096);
    defer std.testing.allocator.free(content);
    try std.testing.expect(std.mem.indexOf(u8, content, "[REDACTED_POTENTIAL_SECRET]") != null);
}

test "shell audit logger writes policy violation events" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    var logger = try audit_mod.AuditLogger.init(std.testing.allocator, .{
        .enabled = true,
        .log_path = "policy_audit.log",
        .max_size_mb = 10,
    }, tmp_path);
    defer logger.deinit();

    const policy_mod = @import("../security/policy.zig");
    var tracker = policy_mod.RateTracker.init(std.testing.allocator, 100);
    defer tracker.deinit();
    var policy = policy_mod.SecurityPolicy{
        .autonomy = .supervised,
        .workspace_dir = tmp_path,
        .allowed_commands = &policy_mod.default_allowed_commands,
        .block_high_risk_commands = true,
        .require_approval_for_medium_risk = true,
        .tracker = &tracker,
    };

    var st = ShellTool{
        .workspace_dir = tmp_path,
        .policy = &policy,
        .audit_logger = &logger,
        .audit_channel = "runtime",
    };
    const parsed = try root.parseTestArgs("{\"command\": \"rm -rf /tmp/never\"}");
    defer parsed.deinit();
    const result = try st.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);

    const content = try tmp_dir.dir.readFileAlloc(std.testing.allocator, "policy_audit.log", 8192);
    defer std.testing.allocator.free(content);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"event_type\":\"command_execution\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"event_type\":\"policy_violation\"") != null);
}
