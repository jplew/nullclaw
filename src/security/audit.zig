const std = @import("std");
const Allocator = std.mem.Allocator;
const audit_log = std.log.scoped(.audit);

/// Audit event types
pub const AuditEventType = enum {
    command_execution,
    tool_call,
    file_access,
    config_change,
    auth_success,
    auth_failure,
    policy_violation,
    security_event,

    pub fn toString(self: AuditEventType) []const u8 {
        return switch (self) {
            .command_execution => "command_execution",
            .tool_call => "tool_call",
            .file_access => "file_access",
            .config_change => "config_change",
            .auth_success => "auth_success",
            .auth_failure => "auth_failure",
            .policy_violation => "policy_violation",
            .security_event => "security_event",
        };
    }
};

/// Actor information (who performed the action)
pub const Actor = struct {
    channel: []const u8,
    user_id: ?[]const u8 = null,
    username: ?[]const u8 = null,
};

/// Action information (what was done)
pub const Action = struct {
    command: ?[]const u8 = null,
    risk_level: ?[]const u8 = null,
    tool_call_id: ?[]const u8 = null,
    approved: bool,
    allowed: bool,
};

pub const ToolCallContext = struct {
    name: []const u8,
    tool_call_id: ?[]const u8 = null,
};

/// Execution result
pub const ExecutionResult = struct {
    success: bool,
    exit_code: ?i32 = null,
    duration_ms: ?u64 = null,
    err_msg: ?[]const u8 = null,
    stdout: ?[]const u8 = null,
    stderr: ?[]const u8 = null,
    stdout_truncated: bool = false,
    stderr_truncated: bool = false,
};

/// Security context
pub const SecurityContext = struct {
    policy_violation: bool = false,
    rate_limit_remaining: ?u32 = null,
    sandbox_backend: ?[]const u8 = null,
};

/// Complete audit event
pub const AuditEvent = struct {
    /// Timestamp in seconds since epoch (UTC)
    timestamp_s: i64,
    /// Per-process session identifier (stable for process lifetime).
    session_id: u64,
    /// Monotonic event identifier scoped to session_id.
    event_id: u64,
    event_type: AuditEventType,
    actor: ?Actor = null,
    action: ?Action = null,
    tool_call: ?ToolCallContext = null,
    result: ?ExecutionResult = null,
    security: SecurityContext = .{},

    /// Global counter for session-scoped event IDs.
    var next_id: u64 = 0;
    /// Lazy-initialized process session identifier.
    var process_session_id: u64 = 0;

    /// Create a new audit event with current timestamp and unique IDs.
    pub fn init(event_type: AuditEventType) AuditEvent {
        const id = @atomicRmw(u64, &next_id, .Add, 1, .monotonic);
        return .{
            .timestamp_s = std.time.timestamp(),
            .session_id = getSessionId(),
            .event_id = id,
            .event_type = event_type,
        };
    }

    fn getSessionId() u64 {
        const existing = @atomicLoad(u64, &process_session_id, .monotonic);
        if (existing != 0) return existing;

        var generated = std.crypto.random.int(u64);
        if (generated == 0) generated = 1;

        if (@cmpxchgStrong(u64, &process_session_id, 0, generated, .seq_cst, .seq_cst)) |race_value| {
            return race_value;
        }
        return generated;
    }

    /// Set the actor
    pub fn withActor(self: AuditEvent, channel: []const u8, user_id: ?[]const u8, username: ?[]const u8) AuditEvent {
        var ev = self;
        ev.actor = .{
            .channel = channel,
            .user_id = user_id,
            .username = username,
        };
        return ev;
    }

    /// Set the action
    pub fn withAction(self: AuditEvent, command: []const u8, risk_level: []const u8, approved: bool, allowed: bool) AuditEvent {
        var ev = self;
        ev.action = .{
            .command = command,
            .risk_level = risk_level,
            .approved = approved,
            .allowed = allowed,
        };
        return ev;
    }

    pub fn withToolCall(self: AuditEvent, name: []const u8, tool_call_id: ?[]const u8) AuditEvent {
        var ev = self;
        ev.tool_call = .{
            .name = name,
            .tool_call_id = tool_call_id,
        };
        return ev;
    }

    /// Set the result
    pub fn withResult(self: AuditEvent, success: bool, exit_code: ?i32, duration_ms: u64, err_msg: ?[]const u8) AuditEvent {
        var ev = self;
        ev.result = .{
            .success = success,
            .exit_code = exit_code,
            .duration_ms = duration_ms,
            .err_msg = err_msg,
        };
        return ev;
    }

    /// Attach optional captured command output.
    pub fn withOutput(
        self: AuditEvent,
        stdout: ?[]const u8,
        stderr: ?[]const u8,
        stdout_truncated: bool,
        stderr_truncated: bool,
    ) AuditEvent {
        var ev = self;
        if (ev.result == null) {
            ev.result = .{ .success = false };
        }
        ev.result.?.stdout = stdout;
        ev.result.?.stderr = stderr;
        ev.result.?.stdout_truncated = stdout_truncated;
        ev.result.?.stderr_truncated = stderr_truncated;
        return ev;
    }

    /// Set security context sandbox backend
    pub fn withSecurity(self: AuditEvent, sandbox_backend: ?[]const u8) AuditEvent {
        var ev = self;
        ev.security.sandbox_backend = sandbox_backend;
        return ev;
    }

    /// Write a JSON representation of the event into a buffer.
    /// Returns the slice of the buffer that was written.
    pub fn writeJson(self: *const AuditEvent, buf: []u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();
        try writer.print(
            "{{\"timestamp_s\":{d},\"session_id\":\"{x:0>16}\",\"event_id\":{d},\"event_uid\":\"{x:0>16}-{x:0>16}\",\"event_type\":\"{s}\"",
            .{ self.timestamp_s, self.session_id, self.event_id, self.session_id, self.event_id, self.event_type.toString() },
        );

        if (self.actor) |a| {
            try writer.writeAll(",\"actor\":{\"channel\":");
            try writeJsonString(writer, a.channel);
            if (a.user_id) |uid| {
                try writer.writeAll(",\"user_id\":");
                try writeJsonString(writer, uid);
            }
            if (a.username) |uname| {
                try writer.writeAll(",\"username\":");
                try writeJsonString(writer, uname);
            }
            try writer.writeAll("}");
        }

        if (self.action) |act| {
            try writer.writeAll(",\"action\":{");
            var need_comma = false;
            if (act.command) |cmd| {
                try writer.writeAll("\"command\":");
                try writeJsonString(writer, cmd);
                need_comma = true;
            }
            if (act.risk_level) |rl| {
                if (need_comma) try writer.writeAll(",");
                try writer.writeAll("\"risk_level\":");
                try writeJsonString(writer, rl);
                need_comma = true;
            }
            if (act.tool_call_id) |tcid| {
                if (need_comma) try writer.writeAll(",");
                try writer.writeAll("\"tool_call_id\":");
                try writeJsonString(writer, tcid);
                need_comma = true;
            }
            if (need_comma) try writer.writeAll(",");
            try writer.print("\"approved\":{},\"allowed\":{}", .{ act.approved, act.allowed });
            try writer.writeAll("}");
        }

        if (self.tool_call) |tc| {
            try writer.writeAll(",\"tool_call\":{\"name\":");
            try writeJsonString(writer, tc.name);
            if (tc.tool_call_id) |tcid| {
                try writer.writeAll(",\"tool_call_id\":");
                try writeJsonString(writer, tcid);
            }
            try writer.writeAll("}");
        }

        if (self.result) |res| {
            try writer.print(",\"result\":{{\"success\":{}", .{res.success});
            if (res.exit_code) |ec| try writer.print(",\"exit_code\":{d}", .{ec});
            if (res.duration_ms) |ms| try writer.print(",\"duration_ms\":{d}", .{ms});
            if (res.err_msg) |em| {
                try writer.writeAll(",\"error\":");
                try writeJsonString(writer, em);
            }
            if (res.stdout) |out| {
                try writer.writeAll(",\"stdout\":");
                try writeJsonString(writer, out);
                try writer.print(",\"stdout_truncated\":{}", .{res.stdout_truncated});
            }
            if (res.stderr) |err_out| {
                try writer.writeAll(",\"stderr\":");
                try writeJsonString(writer, err_out);
                try writer.print(",\"stderr_truncated\":{}", .{res.stderr_truncated});
            }
            try writer.writeAll("}");
        }

        try writer.print(",\"security\":{{\"policy_violation\":{}", .{self.security.policy_violation});
        if (self.security.rate_limit_remaining) |rlr| try writer.print(",\"rate_limit_remaining\":{d}", .{rlr});
        if (self.security.sandbox_backend) |sb| {
            try writer.writeAll(",\"sandbox_backend\":");
            try writeJsonString(writer, sb);
        }
        try writer.writeAll("}}");
        return fbs.getWritten();
    }
};

/// Structured command execution details for audit logging.
pub const CommandExecutionLog = struct {
    channel: []const u8,
    command: []const u8,
    risk_level: []const u8,
    approved: bool,
    allowed: bool,
    success: bool,
    duration_ms: u64,
    stdout: ?[]const u8 = null,
    stderr: ?[]const u8 = null,
    stdout_truncated: bool = false,
    stderr_truncated: bool = false,
};

pub const ToolCallLog = struct {
    channel: []const u8,
    name: []const u8,
    tool_call_id: ?[]const u8 = null,
    success: bool,
    duration_ms: u64,
};

/// Audit logger configuration
pub const AuditConfig = struct {
    enabled: bool = true,
    log_path: []const u8 = "audit.log",
    max_size_mb: u32 = 10,
    capture_shell_output: bool = false,
    max_output_bytes: u32 = 2048,
};

/// Audit logger — writes JSON audit events to a log file.
pub const AuditLogger = struct {
    log_path: []const u8,
    config: AuditConfig,
    allocator: Allocator,

    /// Create a new audit logger
    pub fn init(allocator: Allocator, config: AuditConfig, base_dir: []const u8) !AuditLogger {
        const path = try std.fs.path.join(allocator, &.{ base_dir, config.log_path });
        return .{
            .log_path = path,
            .config = config,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *AuditLogger) void {
        self.allocator.free(self.log_path);
    }

    /// Log an event
    pub fn log(self: *const AuditLogger, event: *const AuditEvent) !void {
        if (!self.config.enabled) return;

        try self.rotateIfNeeded();

        // Write JSON line to file
        const file = try std.fs.cwd().createFile(self.log_path, .{
            .truncate = false,
        });
        defer file.close();

        try file.seekFromEnd(0);
        var json_buf: [4096]u8 = undefined;
        const json = try event.writeJson(&json_buf);
        try file.writeAll(json);
        try file.writeAll("\n");
        try file.sync();
    }

    /// Log a command execution event.
    pub fn logCommand(self: *const AuditLogger, entry: CommandExecutionLog) !void {
        var event = AuditEvent.init(.command_execution)
            .withActor(entry.channel, null, null)
            .withAction(entry.command, entry.risk_level, entry.approved, entry.allowed)
            .withResult(entry.success, null, entry.duration_ms, null)
            .withOutput(entry.stdout, entry.stderr, entry.stdout_truncated, entry.stderr_truncated);
        try self.log(&event);
    }

    pub fn logToolCall(self: *const AuditLogger, entry: ToolCallLog) !void {
        var event = AuditEvent.init(.tool_call)
            .withActor(entry.channel, null, null)
            .withToolCall(entry.name, entry.tool_call_id)
            .withResult(entry.success, null, entry.duration_ms, null);
        try self.log(&event);
    }

    /// Rotate log if it exceeds max size
    fn rotateIfNeeded(self: *const AuditLogger) !void {
        const stat = std.fs.cwd().statFile(self.log_path) catch return;
        const size_mb = stat.size / (1024 * 1024);
        if (size_mb >= self.config.max_size_mb) {
            try self.rotate();
        }
    }

    /// Rotate the log file
    fn rotate(self: *const AuditLogger) !void {
        var buf_old: [1024]u8 = undefined;
        var buf_new: [1024]u8 = undefined;

        // Shift existing rotated logs: .9 -> .10, .8 -> .9, ... .1 -> .2
        var i: u32 = 9;
        while (i >= 1) : (i -= 1) {
            const old_name = std.fmt.bufPrint(&buf_old, "{s}.{d}.log", .{ self.log_path, i }) catch continue;
            const new_name = std.fmt.bufPrint(&buf_new, "{s}.{d}.log", .{ self.log_path, i + 1 }) catch continue;
            std.fs.cwd().rename(old_name, new_name) catch |err| {
                // Not an error if old rotation file doesn't exist yet
                if (err != error.FileNotFound) {
                    audit_log.err("audit log rotation rename {s} -> {s}: {}", .{ old_name, new_name, err });
                }
            };
        }

        // Rename current log to .1
        const rotated = std.fmt.bufPrint(&buf_old, "{s}.1.log", .{self.log_path}) catch return;
        std.fs.cwd().rename(self.log_path, rotated) catch |err| {
            audit_log.err("audit log rotation failed to rename {s} -> {s}: {}", .{ self.log_path, rotated, err });
        };
    }
};

fn writeJsonString(writer: anytype, s: []const u8) !void {
    try writer.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            0x08 => try writer.writeAll("\\b"),
            0x0C => try writer.writeAll("\\f"),
            else => {
                if (c < 0x20) {
                    try writer.print("\\u00{x:0>2}", .{c});
                } else {
                    try writer.writeByte(c);
                }
            },
        }
    }
    try writer.writeByte('"');
}

// ── Tests ──────────────────────────────────────────────────────────────

test "audit event init creates unique ids" {
    const e1 = AuditEvent.init(.command_execution);
    const e2 = AuditEvent.init(.command_execution);
    try std.testing.expectEqual(e1.session_id, e2.session_id);
    try std.testing.expect(e1.event_id != e2.event_id);
}

test "audit event with actor" {
    const event = AuditEvent.init(.command_execution)
        .withActor("telegram", "123", "@alice");
    try std.testing.expect(event.actor != null);
    const actor = event.actor.?;
    try std.testing.expectEqualStrings("telegram", actor.channel);
    try std.testing.expectEqualStrings("123", actor.user_id.?);
    try std.testing.expectEqualStrings("@alice", actor.username.?);
}

test "audit event with action" {
    const event = AuditEvent.init(.command_execution)
        .withAction("ls -la", "low", false, true);
    try std.testing.expect(event.action != null);
    const action = event.action.?;
    try std.testing.expectEqualStrings("ls -la", action.command.?);
    try std.testing.expectEqualStrings("low", action.risk_level.?);
}

test "audit event serializes to json" {
    var event = AuditEvent.init(.command_execution)
        .withActor("telegram", null, null)
        .withAction("ls", "low", false, true)
        .withResult(true, 0, 15, null);

    var buf: [1024]u8 = undefined;
    const json = try event.writeJson(&buf);
    // Should contain key fields
    try std.testing.expect(std.mem.indexOf(u8, json, "command_execution") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "telegram") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"success\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"session_id\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"event_uid\":\"") != null);
}

test "audit event type toString" {
    try std.testing.expectEqualStrings("command_execution", AuditEventType.command_execution.toString());
    try std.testing.expectEqualStrings("tool_call", AuditEventType.tool_call.toString());
    try std.testing.expectEqualStrings("policy_violation", AuditEventType.policy_violation.toString());
    try std.testing.expectEqualStrings("auth_success", AuditEventType.auth_success.toString());
}

test "audit logger disabled does not create file" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    const config = AuditConfig{ .enabled = false };
    var logger = try AuditLogger.init(std.testing.allocator, config, tmp_path);
    defer logger.deinit();

    var event = AuditEvent.init(.command_execution);
    try logger.log(&event);

    // File should not exist since logging is disabled
    const result = tmp_dir.dir.statFile("audit.log");
    try std.testing.expectError(error.FileNotFound, result);
}

// ── Additional audit tests ──────────────────────────────────────

test "audit event types all have string representations" {
    const types = [_]AuditEventType{
        .command_execution, .tool_call,    .file_access,      .config_change,
        .auth_success,      .auth_failure, .policy_violation, .security_event,
    };
    for (types) |t| {
        const s = t.toString();
        try std.testing.expect(s.len > 0);
    }
}

test "audit event with result" {
    const event = AuditEvent.init(.command_execution)
        .withResult(true, 0, 42, null);
    try std.testing.expect(event.result != null);
    const r = event.result.?;
    try std.testing.expect(r.success);
    try std.testing.expectEqual(@as(?i32, 0), r.exit_code);
    try std.testing.expectEqual(@as(?u64, 42), r.duration_ms);
    try std.testing.expect(r.err_msg == null);
    try std.testing.expect(r.stdout == null);
    try std.testing.expect(r.stderr == null);
}

test "audit event with captured output" {
    const event = AuditEvent.init(.command_execution)
        .withResult(true, 0, 7, null)
        .withOutput("line1\nline2", null, true, false);
    const r = event.result.?;
    try std.testing.expectEqualStrings("line1\nline2", r.stdout.?);
    try std.testing.expect(r.stderr == null);
    try std.testing.expect(r.stdout_truncated);
    try std.testing.expect(!r.stderr_truncated);

    var buf: [2048]u8 = undefined;
    var ev = event;
    const json = try ev.writeJson(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"stdout\":\"line1\\nline2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"stdout_truncated\":true") != null);
}

test "audit event with tool call context" {
    const event = AuditEvent.init(.tool_call)
        .withActor("runtime", null, null)
        .withToolCall("memory_store", "tool-123")
        .withResult(true, null, 11, null);

    var buf: [2048]u8 = undefined;
    var ev = event;
    const json = try ev.writeJson(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"event_type\":\"tool_call\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"tool_call\":{\"name\":\"memory_store\",\"tool_call_id\":\"tool-123\"}") != null);
}

test "audit event with result error message" {
    const event = AuditEvent.init(.command_execution)
        .withResult(false, 1, 100, "command failed");
    const r = event.result.?;
    try std.testing.expect(!r.success);
    try std.testing.expectEqual(@as(?i32, 1), r.exit_code);
    try std.testing.expectEqualStrings("command failed", r.err_msg.?);
}

test "audit event with security context" {
    const event = AuditEvent.init(.security_event)
        .withSecurity("firejail");
    try std.testing.expectEqualStrings("firejail", event.security.sandbox_backend.?);
    try std.testing.expect(!event.security.policy_violation);
}

test "audit event chained builder" {
    const event = AuditEvent.init(.command_execution)
        .withActor("cli", "user1", "alice")
        .withAction("ls -la", "low", false, true)
        .withResult(true, 0, 5, null)
        .withSecurity("none");

    try std.testing.expect(event.actor != null);
    try std.testing.expect(event.action != null);
    try std.testing.expect(event.result != null);
    try std.testing.expectEqualStrings("none", event.security.sandbox_backend.?);
}

test "audit event json contains event type" {
    var event = AuditEvent.init(.auth_failure)
        .withActor("gateway", null, null);
    var buf: [2048]u8 = undefined;
    const json = try event.writeJson(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "auth_failure") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "gateway") != null);
}

test "audit event json contains security context" {
    var event = AuditEvent.init(.policy_violation);
    event.security.policy_violation = true;
    event.security.rate_limit_remaining = 5;
    var buf: [2048]u8 = undefined;
    const json = try event.writeJson(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "policy_violation") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "rate_limit_remaining") != null);
}

test "audit event default security context" {
    const event = AuditEvent.init(.command_execution);
    try std.testing.expect(event.session_id != 0);
    try std.testing.expect(!event.security.policy_violation);
    try std.testing.expect(event.security.rate_limit_remaining == null);
    try std.testing.expect(event.security.sandbox_backend == null);
}

test "audit config defaults" {
    const cfg = AuditConfig{};
    try std.testing.expect(cfg.enabled);
    try std.testing.expectEqualStrings("audit.log", cfg.log_path);
    try std.testing.expectEqual(@as(u32, 10), cfg.max_size_mb);
    try std.testing.expect(!cfg.capture_shell_output);
    try std.testing.expectEqual(@as(u32, 2048), cfg.max_output_bytes);
}

test "audit config custom" {
    const cfg = AuditConfig{
        .enabled = false,
        .log_path = "custom.log",
        .max_size_mb = 50,
        .capture_shell_output = true,
        .max_output_bytes = 1024,
    };
    try std.testing.expect(!cfg.enabled);
    try std.testing.expectEqualStrings("custom.log", cfg.log_path);
    try std.testing.expectEqual(@as(u32, 50), cfg.max_size_mb);
    try std.testing.expect(cfg.capture_shell_output);
    try std.testing.expectEqual(@as(u32, 1024), cfg.max_output_bytes);
}

test "audit logger enabled writes to file" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    const config = AuditConfig{ .enabled = true, .log_path = "test_audit.log" };
    var logger = try AuditLogger.init(std.testing.allocator, config, tmp_path);
    defer logger.deinit();

    var event = AuditEvent.init(.command_execution)
        .withAction("ls", "low", false, true);
    try logger.log(&event);

    // File should exist
    const stat = try tmp_dir.dir.statFile("test_audit.log");
    try std.testing.expect(stat.size > 0);
}

test "audit logger multiple events" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    const config = AuditConfig{ .enabled = true, .log_path = "multi_audit.log" };
    var logger = try AuditLogger.init(std.testing.allocator, config, tmp_path);
    defer logger.deinit();

    var e1 = AuditEvent.init(.command_execution);
    try logger.log(&e1);
    var e2 = AuditEvent.init(.auth_success);
    try logger.log(&e2);

    const stat = try tmp_dir.dir.statFile("multi_audit.log");
    try std.testing.expect(stat.size > 10); // more than one event
}

test "audit command execution log" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    const config = AuditConfig{ .enabled = true, .log_path = "cmd_audit.log" };
    var logger = try AuditLogger.init(std.testing.allocator, config, tmp_path);
    defer logger.deinit();

    try logger.logCommand(.{
        .channel = "cli",
        .command = "git status",
        .risk_level = "low",
        .approved = false,
        .allowed = true,
        .success = true,
        .duration_ms = 15,
        .stdout = "on branch main",
        .stderr = "warn",
        .stdout_truncated = false,
        .stderr_truncated = true,
    });

    const stat = try tmp_dir.dir.statFile("cmd_audit.log");
    try std.testing.expect(stat.size > 0);

    const content = try tmp_dir.dir.readFileAlloc(std.testing.allocator, "cmd_audit.log", 4096);
    defer std.testing.allocator.free(content);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"stdout\":\"on branch main\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"stderr\":\"warn\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"stderr_truncated\":true") != null);
}

test "audit tool call log" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    const config = AuditConfig{ .enabled = true, .log_path = "tool_audit.log" };
    var logger = try AuditLogger.init(std.testing.allocator, config, tmp_path);
    defer logger.deinit();

    try logger.logToolCall(.{
        .channel = "runtime",
        .name = "web_search",
        .tool_call_id = "call-42",
        .success = true,
        .duration_ms = 33,
    });

    const content = try tmp_dir.dir.readFileAlloc(std.testing.allocator, "tool_audit.log", 4096);
    defer std.testing.allocator.free(content);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"event_type\":\"tool_call\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"name\":\"web_search\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"tool_call_id\":\"call-42\"") != null);
}

test "audit event ids are sequential" {
    const e1 = AuditEvent.init(.command_execution);
    const e2 = AuditEvent.init(.command_execution);
    const e3 = AuditEvent.init(.command_execution);
    try std.testing.expectEqual(e1.session_id, e2.session_id);
    try std.testing.expectEqual(e2.session_id, e3.session_id);
    try std.testing.expect(e2.event_id > e1.event_id);
    try std.testing.expect(e3.event_id > e2.event_id);
}

test "audit event uid contains session and event ids" {
    var event = AuditEvent.init(.command_execution);
    var buf: [1024]u8 = undefined;
    const json = try event.writeJson(&buf);

    var expected_uid: [48]u8 = undefined;
    const expected_uid_text = try std.fmt.bufPrint(
        &expected_uid,
        "\"event_uid\":\"{x:0>16}-{x:0>16}\"",
        .{ event.session_id, event.event_id },
    );
    try std.testing.expect(std.mem.indexOf(u8, json, expected_uid_text) != null);
}

test "audit event timestamp is reasonable" {
    const event = AuditEvent.init(.command_execution);
    // Timestamp should be a positive number (after Unix epoch)
    try std.testing.expect(event.timestamp_s > 0);
    // And before year 2100 (reasonable upper bound)
    try std.testing.expect(event.timestamp_s < 4_102_444_800);
}
