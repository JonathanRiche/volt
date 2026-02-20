const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;

const Allocator = std.mem.Allocator;

const VoltSeedConfig = struct {
    meta: struct {
        lastTouchedVersion: []const u8,
        lastTouchedAt: []const u8,
    },
    wizard: struct {
        lastRunAt: []const u8,
        lastRunVersion: []const u8,
        lastRunCommand: []const u8,
        lastRunMode: []const u8,
    },
    channels: struct {
        telegram: struct {
            enabled: bool,
            dmPolicy: []const u8,
            botToken: []const u8,
            groupPolicy: []const u8,
            streamMode: []const u8,
        },
    },
    gateway: struct {
        mode: []const u8,
        port: u16,
        bind: []const u8,
        auth: struct {
            mode: []const u8,
            token: []const u8,
        },
        tailscale: struct {
            mode: []const u8,
            resetOnExit: bool,
        },
    },
    plugins: struct {
        entries: struct {
            telegram: struct {
                enabled: bool,
            },
        },
    },
};

const DEFAULT_VOLT_SEED = VoltSeedConfig{
    .meta = .{
        .lastTouchedVersion = "2026.1.30",
        .lastTouchedAt = "1970-01-01T00:00:00.000Z",
    },
    .wizard = .{
        .lastRunAt = "1970-01-01T00:00:00.000Z",
        .lastRunVersion = "2026.1.30",
        .lastRunCommand = "configure",
        .lastRunMode = "local",
    },
    .channels = .{
        .telegram = .{
            .enabled = true,
            .dmPolicy = "pairing",
            .botToken = "",
            .groupPolicy = "allowlist",
            .streamMode = "partial",
        },
    },
    .gateway = .{
        .mode = "local",
        .port = 18789,
        .bind = "loopback",
        .auth = .{
            .mode = "token",
            .token = "",
        },
        .tailscale = .{
            .mode = "off",
            .resetOnExit = false,
        },
    },
    .plugins = .{
        .entries = .{
            .telegram = .{
                .enabled = true,
            },
        },
    },
};

const VoltConfig = struct {
    channels: struct {
        telegram: struct {
            botToken: []const u8 = "",
        } = .{},
    } = .{},
};

const InitOptions = struct {
    mirror_volt: bool,
    force: bool,
    home_path: ?[]const u8,
    source_path: ?[]const u8,
};

const TelegramSetupOptions = struct {
    home_path: ?[]const u8,
    token: ?[]const u8,
    force: bool,
    account: ?[]const u8,
    allow_from: std.ArrayListUnmanaged([]const u8),
};

const TelegramRunOptions = struct {
    home_path: ?[]const u8,
    token: ?[]const u8,
    dispatch: ?[]const u8,
    zolt: bool,
    zolt_command: ?[]const u8,
    poll_ms: u64,
    account: ?[]const u8,
};

const GatewayRunOptions = struct {
    home_path: ?[]const u8,
    bind: []const u8,
    port: u16,
    account: ?[]const u8,
    dispatch: ?[]const u8,
    zolt: bool,
    zolt_command: ?[]const u8,
    auth_token: ?[]const u8,
};

const GatewayServiceAction = enum { run, install, uninstall, start, stop, restart, status };

const GatewayInvokePayload = struct {
    message: ?[]const u8 = null,
    text: ?[]const u8 = null,
    account: ?[]const u8 = null,
    chat_id: ?i64 = null,
    session: ?[]const u8 = null,
};

const GatewayRoute = enum { health, status, invoke, unknown };

const GatewayError = error{ GatewayAuthMissing, GatewayBadRequest };
const GatewayServiceError = error{ GatewayServiceUnsupportedPlatform, GatewayServiceCommandFailed };
const VoltError = error{ZoltSessionIdMissing};

const DefaultZoltDispatch = "zolt run --session {session} {message}";

const TelegramSlashCommand = struct {
    command: []const u8,
    args: []const u8,
};

const TelegramSlashCommandInfo = struct {
    command: []const u8,
    description: []const u8,
};

const VoltTelegramSlashCommands = [_]TelegramSlashCommandInfo{
    .{ .command = "help", .description = "Show Volt command help" },
    .{ .command = "commands", .description = "Show Volt command menu" },
    .{ .command = "sessions", .description = "Show the active zolt session for this chat" },
    .{ .command = "status", .description = "Show runtime status for this chat" },
    .{ .command = "reset", .description = "Reset the active zolt session for this chat" },
    .{ .command = "models", .description = "Show available model information (zolt mode)" },
};

const TelegramZoltSessionMapEntry = struct {
    key: []const u8,
    session: []const u8,
};

const TelegramZoltSessionMap = struct {
    version: u32 = 1,
    sessions: []const TelegramZoltSessionMapEntry = &.{},
};

const ZoltRunOutput = struct {
    session_id: []const u8,
    response: []const u8,
};

const DispatchMode = enum { shell, argv };

const DispatchPlan = struct {
    mode: DispatchMode = .shell,
    argv: []const []const u8 = &.{},
};

const TelegramDispatchContext = struct {
    message: []const u8,
    account: []const u8,
    chat_id: i64,
    session_key: []const u8,
};

const TelegramOffset = struct {
    version: u32 = 1,
    lastUpdateId: i64 = 0,
};

const TelegramAllowFrom = struct {
    version: u32 = 1,
    allowFrom: []const []const u8 = &.{},
};

const TelegramChat = struct {
    id: i64 = 0,
};

const TelegramMessage = struct {
    chat: ?TelegramChat = null,
    text: ?[]const u8 = null,
};

const TelegramUpdate = struct {
    update_id: i64 = 0,
    message: ?TelegramMessage = null,
};

const TelegramUpdates = struct {
    ok: bool = false,
    result: []const TelegramUpdate = &.{},
};

const TelegramCommandsResponse = struct {
    ok: bool = false,
    description: ?[]const u8 = null,
};

const TelegramUpdatesEnvelope = struct {
    payload: []u8,
    parsed: std.json.Parsed(TelegramUpdates),

    fn deinit(self: TelegramUpdatesEnvelope, allocator: Allocator) void {
        self.parsed.deinit();
        allocator.free(self.payload);
    }
};

const DefaultAllowFromJson = "{\"version\":1,\"allowFrom\":[]}";
const DefaultOffsetJson = "{\"version\":1,\"lastUpdateId\":0}";
const DefaultPairingJson = "{\"version\":1,\"requests\":[]}";
const DefaultUpdateCheckJson = "{\"lastCheckedAt\":\"1970-01-01T00:00:00.000Z\"}";
const DefaultTelegramZoltSessionsJson = "{\"version\":1,\"sessions\":[]}";
const DefaultGatewayToken = "volt-gateway-token";
const DefaultGatewayBind = "127.0.0.1";
const MaxGatewayRequestSize = 64 * 1024;
const GatewayServiceName = "volt-gateway";
const GatewaySystemdUnit = "volt-gateway.service";
const GatewayLaunchdLabel = "com.volt.gateway";
const DefaultAccountId = "default";
const DefaultCommandCheckArgv = [_][]const u8{ "--help", "-h" };
const DefaultVoltDebugOutputChars = 2048;
const VoltDebugEnvVar = "VOLT_DEBUG";

var g_debug_enabled: ?bool = null;

fn isHelp(arg: []const u8) bool {
    return std.mem.eql(u8, arg, "--help") or
        std.mem.eql(u8, arg, "-h") or
        std.mem.eql(u8, arg, "help");
}

fn isVoltDebugEnabled(allocator: Allocator) bool {
    if (g_debug_enabled) |cached| return cached;
    const value = std.process.getEnvVarOwned(allocator, VoltDebugEnvVar) catch |err| {
        if (err == error.EnvironmentVariableNotFound) {
            g_debug_enabled = false;
            return false;
        }
        g_debug_enabled = false;
        return false;
    };
    defer allocator.free(value);

    const trimmed = std.mem.trim(u8, value, " \t\r\n");
    const enabled = std.ascii.eqlIgnoreCase(trimmed, "1") or
        std.ascii.eqlIgnoreCase(trimmed, "true") or
        std.ascii.eqlIgnoreCase(trimmed, "yes") or
        std.ascii.eqlIgnoreCase(trimmed, "on") or
        std.ascii.eqlIgnoreCase(trimmed, "y");
    g_debug_enabled = enabled;
    return enabled;
}

fn debugPrint(allocator: Allocator, comptime format: []const u8, args: anytype) void {
    if (!isVoltDebugEnabled(allocator)) return;
    std.fs.File.stderr().deprecatedWriter().print("[volt debug] " ++ format ++ "\n", args) catch {};
}

fn debugArgv(allocator: Allocator, prefix: []const u8, argv: []const []const u8) void {
    if (!isVoltDebugEnabled(allocator)) return;

    var stderr = std.fs.File.stderr().deprecatedWriter();
    stderr.print("[volt debug] {s}: ", .{prefix}) catch {};
    for (argv, 0..) |arg, idx| {
        if (idx > 0) stderr.print(" ", .{}) catch {};
        stderr.print("\"{s}\"", .{arg}) catch {};
    }
    stderr.print("\n", .{}) catch {};
}

fn debugSnippet(allocator: Allocator, payload: []const u8) []const u8 {
    const max_len = DefaultVoltDebugOutputChars;
    if (!isVoltDebugEnabled(allocator) or payload.len <= max_len) return payload;
    return payload[0..max_len];
}

fn printUsage() !void {
    var out = std.fs.File.stderr().deprecatedWriter();

    try out.writeAll("volt: lightweight cli for local stdio + telegram gateway\n" ++
        "Usage:\n" ++
        "  volt init [--mirror-volt] [--source <path>] [--home <path>] [--force]\n" ++
        "  volt telegram setup --token <token> [--account <id>] [--allow-from <chat_id>]... [--home <path>] [--force]\n" ++
        "  volt --telegram [--token <token>] [--account <id>] [--home <path>] [--dispatch <command>] [--zolt] [--zolt-path <path>] [--poll-ms <ms>]\n" ++
        "  volt gateway [--home <path>] [--bind <ip>] [--port <port>] [--account <id>] [--dispatch <command>] [--zolt] [--zolt-path <path>] [--auth-token <token>]\n" ++
        "  volt gateway install|start|stop|restart|status|uninstall [--home <path>] [--bind <ip>] [--port <port>] [--account <id>] [--dispatch <command>] [--zolt] [--zolt-path <path>] [--auth-token <token>]\n" ++
        "\n" ++
        "Dispatch placeholders (for --dispatch args):\n" ++
        "  {message} / {text}, {chat_id}, {account}, {session}\n" ++
        "Allow list behavior:\n" ++
        "  omitting --allow-from allows all chats to use the bot.\n" ++
        "Use --zolt to run messages through: zolt run --session {session} {message}.\n" ++
        "Run `zolt run -h` (or `zolt run --help`) for current supported flags.\n" ++
        "Resolution order for --zolt is: --zolt-path/VOLT_ZOLT_PATH, bundled volt/zolt, then system PATH.\n" ++
        "Set --zolt-path explicitly or the `VOLT_ZOLT_PATH` env var to point at a specific binary.\n" ++
        "\n" ++
        "Examples:\n" ++
        "  volt init --home ~/.volt\n" ++
        "  volt telegram setup --home ~/.volt --token 123:ABC\n" ++
        "  volt telegram setup --token 123:ABC --account work --allow-from 8257801789\n" ++
        "  volt --telegram --dispatch \"zolt -s {session} {message}\"\n");
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len == 1) {
        try runLocalGateway(allocator);
        return;
    }

    if (isHelp(args[1])) {
        try printUsage();
        return;
    }

    if (std.mem.eql(u8, args[1], "init")) {
        const opts = try parseInitOptions(args[2..]);
        try runInit(allocator, opts);
        return;
    }

    if (std.mem.eql(u8, args[1], "telegram")) {
        if (args.len < 3 or !std.mem.eql(u8, args[2], "setup")) {
            try printUsage();
            return;
        }

        var opts = try parseTelegramSetupOptions(allocator, args[3..]);
        defer opts.allow_from.deinit(allocator);
        try runTelegramSetup(allocator, opts);
        return;
    }

    if (std.mem.eql(u8, args[1], "gateway")) {
        if (args.len >= 3) {
            const action = parseGatewayServiceAction(args[2]);
            if (action != .run) {
                const opts = try parseGatewayOptions(args[3..]);
                try runGatewayServiceAction(allocator, action, opts);
                return;
            }
        }

        const opts = try parseGatewayOptions(args[2..]);
        try runGateway(allocator, opts);
        return;
    }

    if (std.mem.eql(u8, args[1], "--telegram")) {
        const opts = try parseTelegramRunOptions(args[2..]);
        try runTelegramGateway(allocator, opts);
        return;
    }

    try printUsage();
}

fn runLocalGateway(allocator: Allocator) !void {
    const stdin = std.fs.File.stdin().deprecatedReader();
    var stdout = std.fs.File.stdout().deprecatedWriter();
    var stderr = std.fs.File.stderr().deprecatedWriter();

    while (true) {
        const maybe_line = try stdin.readUntilDelimiterOrEofAlloc(allocator, '\n', 64 * 1024);
        if (maybe_line == null) return;
        defer allocator.free(maybe_line.?);

        const line = trimLine(maybe_line.?);
        if (line.len == 0) continue;

        const output = executeShellCommand(allocator, line) catch |err| {
            try stderr.print("command failed: {s}\n", .{@errorName(err)});
            continue;
        };
        defer allocator.free(output);

        if (output.len == 0) {
            try stdout.writeAll("(no output)\n");
        } else {
            try stdout.writeAll(output);
            if (output[output.len - 1] != '\n') {
                try stdout.writeAll("\n");
            }
        }
    }
}

fn runGateway(allocator: Allocator, opts: GatewayRunOptions) !void {
    const root = try resolveHomePath(allocator, opts.home_path);
    defer allocator.free(root);

    const default_account = try normalizeAccountId(allocator, opts.account);
    defer allocator.free(default_account);

    const auth_token = try resolveGatewayAuthToken(allocator, root, opts.auth_token);
    defer allocator.free(auth_token);

    const dispatch = if (opts.zolt) dispatch_block: {
        const zolt_cmd = try resolveZoltCommand(allocator, opts.zolt_command);
        defer allocator.free(zolt_cmd);

        const zolt_dispatch = try std.fmt.allocPrint(
            allocator,
            "{s} run --session {s} {s}",
            .{ zolt_cmd, "{session}", "{message}" },
        );
        defer allocator.free(zolt_dispatch);

        validateDispatchExecutable(allocator, zolt_cmd) catch |err| {
            switch (err) {
                error.DispatchBinaryNotFound => {
                    try std.fs.File.stderr().deprecatedWriter().print(
                        "volt: dispatch binary not found: {s}\n",
                        .{zolt_cmd},
                    );
                },
                error.DispatchBinaryNotExecutable => {
                    try std.fs.File.stderr().deprecatedWriter().print(
                        "volt: dispatch binary not executable: {s}\n",
                        .{zolt_cmd},
                    );
                },
                else => {
                    try std.fs.File.stderr().deprecatedWriter().print(
                        "volt: dispatch validation failed: {s}\n",
                        .{@errorName(err)},
                    );
                },
            }
            return err;
        };

        break :dispatch_block try parseDispatchPlan(allocator, zolt_dispatch);
    } else try parseDispatchPlan(allocator, opts.dispatch);
    defer deinitDispatchPlan(allocator, dispatch);

    const bind = resolveGatewayBind(opts.bind);
    const address = try std.net.Address.parseIp(bind, opts.port);
    var listener = try address.listen(.{
        .reuse_address = true,
        .kernel_backlog = 128,
    });
    defer listener.deinit();

    try std.fs.File.stderr().deprecatedWriter().print(
        "volt: gateway listening on http://{s}:{d}\n",
        .{ bind, opts.port },
    );

    var ctx = GatewayRequestContext{
        .dispatch = dispatch,
        .default_account = default_account,
        .auth_token = auth_token,
        .bind = bind,
        .port = opts.port,
    };

    while (true) {
        const connection = try listener.accept();
        runGatewayConnection(allocator, connection, &ctx) catch |err| {
            std.log.err("gateway connection failed: {s}", .{@errorName(err)});
        };
    }
}

const GatewayRequestContext = struct {
    dispatch: DispatchPlan,
    default_account: []const u8,
    auth_token: []const u8,
    bind: []const u8,
    port: u16,
};

fn runGatewayConnection(
    allocator: Allocator,
    connection: std.net.Server.Connection,
    ctx: *const GatewayRequestContext,
) !void {
    defer connection.stream.close();

    var read_buffer: [4096]u8 = undefined;
    var write_buffer: [4096]u8 = undefined;
    var req_reader = connection.stream.reader(&read_buffer);
    var req_writer = connection.stream.writer(&write_buffer);
    var server = std.http.Server.init(req_reader.interface(), &req_writer.interface);

    while (true) {
        var request = server.receiveHead() catch |err| return switch (err) {
            error.HttpConnectionClosing => return,
            else => err,
        };

        try serveGatewayRequest(
            allocator,
            &request,
            ctx,
        );

        if (!request.head.keep_alive) return;
    }
}

fn serveGatewayRequest(
    allocator: Allocator,
    request: *std.http.Server.Request,
    ctx: *const GatewayRequestContext,
) !void {
    const route = parseGatewayRoute(request.head.target);

    switch (route) {
        .health => {
            if (request.head.method != .GET and request.head.method != .HEAD) {
                return respondGatewayJson(
                    allocator,
                    request,
                    .method_not_allowed,
                    .{ .status = "error", .message = "method not allowed", .path = request.head.target },
                );
            }

            return respondGatewayJson(
                allocator,
                request,
                .ok,
                .{
                    .status = "ok",
                    .service = "volt-gateway",
                    .bind = ctx.bind,
                    .port = ctx.port,
                },
            );
        },
        .status => {
            if (request.head.method != .GET and request.head.method != .HEAD) {
                return respondGatewayJson(
                    allocator,
                    request,
                    .method_not_allowed,
                    .{ .status = "error", .message = "method not allowed", .path = request.head.target },
                );
            }

            return respondGatewayJson(
                allocator,
                request,
                .ok,
                .{
                    .status = "ok",
                    .service = "volt-gateway",
                    .transport = "http",
                    .dispatch = switch (ctx.dispatch.mode) {
                        .shell => "shell",
                        .argv => "argv",
                    },
                    .defaultAccount = ctx.default_account,
                    .bind = ctx.bind,
                    .port = ctx.port,
                },
            );
        },
        .invoke => {
            if (!isGatewayAuthorized(request, ctx.auth_token)) {
                return respondGatewayJson(
                    allocator,
                    request,
                    .unauthorized,
                    .{ .status = "error", .message = "missing or invalid token" },
                );
            }
            if (request.head.method != .POST) {
                return respondGatewayJson(
                    allocator,
                    request,
                    .method_not_allowed,
                    .{ .status = "error", .message = "method not allowed", .path = request.head.target },
                );
            }

            const response = handleGatewayInvoke(allocator, request, ctx) catch |err| {
                switch (err) {
                    error.GatewayBadRequest => return respondGatewayJson(
                        allocator,
                        request,
                        .bad_request,
                        .{ .status = "error", .message = "invalid payload", .path = request.head.target },
                    ),
                    else => return respondGatewayJson(
                        allocator,
                        request,
                        .internal_server_error,
                        .{ .status = "error", .message = @errorName(err), .path = request.head.target },
                    ),
                }
            };
            defer allocator.free(response);

            return respondGatewayJson(
                allocator,
                request,
                .ok,
                .{
                    .status = "ok",
                    .response = response,
                },
            );
        },
        .unknown => {
            return respondGatewayJson(
                allocator,
                request,
                .not_found,
                .{ .status = "error", .message = "not found", .path = request.head.target },
            );
        },
    }
}

fn handleGatewayInvoke(
    allocator: Allocator,
    request: *std.http.Server.Request,
    ctx: *const GatewayRequestContext,
) ![]u8 {
    const body = try readGatewayBody(allocator, request);
    defer allocator.free(body);

    const payload = try parseGatewayInvokePayload(allocator, body);
    defer payload.deinit();

    const message = payload.value.message orelse payload.value.text orelse return error.GatewayBadRequest;
    const account = if (payload.value.account) |raw| blk: {
        break :blk try normalizeAccountId(allocator, raw);
    } else try allocator.dupe(u8, ctx.default_account);
    defer allocator.free(account);

    const session_key = if (payload.value.session) |raw_session| blk: {
        break :blk try allocator.dupe(u8, raw_session);
    } else if (payload.value.chat_id) |chat_id| blk: {
        break :blk try std.fmt.allocPrint(allocator, "gateway:{s}:{d}", .{ account, chat_id });
    } else blk: {
        break :blk try std.fmt.allocPrint(allocator, "gateway:{s}", .{account});
    };
    defer allocator.free(session_key);

    const dispatch_ctx = TelegramDispatchContext{
        .message = message,
        .account = account,
        .chat_id = payload.value.chat_id orelse 0,
        .session_key = session_key,
    };

    return executeDispatchForTelegram(allocator, ctx.dispatch, dispatch_ctx);
}

fn parseGatewayRoute(target: []const u8) GatewayRoute {
    const path = if (std.mem.indexOfScalar(u8, target, '?')) |idx|
        target[0..idx]
    else
        target;

    if (std.mem.eql(u8, path, "/health")) return .health;
    if (std.mem.eql(u8, path, "/gateway/health")) return .health;
    if (std.mem.eql(u8, path, "/gateway/status")) return .status;
    if (std.mem.eql(u8, path, "/invoke")) return .invoke;
    return .unknown;
}

fn respondGatewayJson(
    allocator: Allocator,
    request: *std.http.Server.Request,
    status: std.http.Status,
    payload: anytype,
) !void {
    var out = std.Io.Writer.Allocating.init(allocator);
    defer out.deinit();

    var stringify = std.json.Stringify{ .writer = &out.writer, .options = .{} };
    try stringify.write(payload);
    const body = try out.toOwnedSlice();
    defer allocator.free(body);

    const headers = [_]std.http.Header{.{ .name = "content-type", .value = "application/json" }};
    try request.respond(body, .{ .status = status, .extra_headers = &headers });
}

fn readGatewayBody(allocator: Allocator, request: *std.http.Server.Request) ![]u8 {
    if (request.head.content_length == null and request.head.transfer_encoding == .none) {
        return try allocator.dupe(u8, "");
    }

    const content_length = request.head.content_length orelse MaxGatewayRequestSize;
    if (content_length > MaxGatewayRequestSize) {
        return error.GatewayBadRequest;
    }

    if (content_length == 0) {
        return try allocator.dupe(u8, "");
    }

    var body_buffer: [4096]u8 = undefined;
    const body_reader = request.readerExpectNone(&body_buffer);
    var body = try allocator.alloc(u8, content_length);
    errdefer allocator.free(body);

    var body_len: usize = 0;
    while (body_len < content_length) {
        const chunk = body[body_len..];
        const read = body_reader.readSliceShort(chunk) catch return error.GatewayBadRequest;
        if (read == 0) break;
        body_len += read;
    }

    return body[0..body_len];
}

fn parseGatewayInvokePayload(allocator: Allocator, body: []const u8) !std.json.Parsed(GatewayInvokePayload) {
    if (body.len == 0) return error.GatewayBadRequest;
    return std.json.parseFromSlice(
        GatewayInvokePayload,
        allocator,
        body,
        .{ .ignore_unknown_fields = true },
    ) catch error.GatewayBadRequest;
}

fn isGatewayAuthorized(request: *std.http.Server.Request, token: []const u8) bool {
    if (token.len == 0) return true;

    var headers = request.iterateHeaders();
    while (headers.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "authorization")) {
            const value = std.mem.trim(u8, header.value, " \\t");
            const prefix = "Bearer ";
            if (std.mem.startsWith(u8, value, prefix) and std.mem.eql(u8, value[prefix.len..], token)) {
                return true;
            }
            if (std.mem.eql(u8, value, token)) {
                return true;
            }
        }

        if (std.ascii.eqlIgnoreCase(header.name, "x-volt-gateway-token") and
            std.mem.eql(u8, std.mem.trim(u8, header.value, " \\t"), token))
        {
            return true;
        }
    }
    return false;
}

fn resolveGatewayBind(raw: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return DefaultGatewayBind;
    if (std.mem.eql(u8, trimmed, "localhost")) return "127.0.0.1";
    return trimmed;
}

fn runInit(allocator: Allocator, opts: InitOptions) !void {
    const target_root = try resolveHomePath(allocator, opts.home_path);
    defer allocator.free(target_root);

    try ensureDirIfMissing(target_root);

    const required_dirs = [_][]const u8{
        "agents",
        "agents/main",
        "agents/main/sessions",
        "canvas",
        "credentials",
        "cron",
        "cron/runs",
        "devices",
        "identity",
        "memory",
        "telegram",
    };

    for (required_dirs) |dir| {
        const dir_path = try joinPath(allocator, target_root, dir);
        defer allocator.free(dir_path);
        try ensureDirIfMissing(dir_path);
    }

    const source_root = try resolveHomePath(allocator, opts.source_path);
    defer allocator.free(source_root);

    const template_text = loadTemplateText(allocator, source_root) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    defer if (template_text) |template| allocator.free(template);

    const workspace_path = try std.process.getCwdAlloc(allocator);
    defer allocator.free(workspace_path);

    const volt = try renderVoltConfig(allocator, "", workspace_path, template_text, null);
    defer allocator.free(volt);

    const volt_path = try joinPath(allocator, target_root, "volt.json");
    defer allocator.free(volt_path);
    try writeTextFile(volt_path, volt, opts.force);

    const allow_list_path = try joinPath(allocator, target_root, "credentials/telegram-allowFrom.json");
    defer allocator.free(allow_list_path);
    try writeTextFile(allow_list_path, DefaultAllowFromJson, opts.force);

    const pairing_path = try joinPath(allocator, target_root, "credentials/telegram-pairing.json");
    defer allocator.free(pairing_path);
    try writeTextFile(pairing_path, DefaultPairingJson, opts.force);

    const offset_path = try joinPath(allocator, target_root, "telegram/update-offset-default.json");
    defer allocator.free(offset_path);
    try writeTextFile(offset_path, DefaultOffsetJson, opts.force);

    const update_check_path = try joinPath(allocator, target_root, "update-check.json");
    defer allocator.free(update_check_path);
    try writeTextFile(update_check_path, DefaultUpdateCheckJson, opts.force);

    if (!opts.mirror_volt) return;

    const mirror_files = [_][]const u8{
        "clawdbot.json",
        "credentials/telegram-allowFrom.json",
        "credentials/telegram-pairing.json",
        "cron/jobs.json",
        "devices/paired.json",
        "devices/pending.json",
        "identity/device.json",
        "identity/device-auth.json",
        "telegram/update-offset-default.json",
        "update-check.json",
        "agents/main/sessions/sessions.json",
        "canvas/index.html",
    };

    var copied_any = false;
    for (mirror_files) |relative| {
        const source = try joinPath(allocator, source_root, relative);
        defer allocator.free(source);
        const dest = try joinPath(allocator, target_root, relative);
        defer allocator.free(dest);

        copyIfExists(allocator, source, dest, opts.force) catch |err| {
            if (err == error.FileNotFound) continue;
            return err;
        };
        copied_any = true;
    }

    if (!copied_any) return error.NoTemplateSourceFiles;
}

fn runTelegramSetup(allocator: Allocator, opts: TelegramSetupOptions) !void {
    const token = opts.token orelse return error.MissingBotToken;
    const account = try normalizeAccountId(allocator, opts.account);
    defer allocator.free(account);

    const root = try resolveHomePath(allocator, opts.home_path);
    defer allocator.free(root);

    try ensureDirIfMissing(root);

    const template_text = loadTemplateText(allocator, root) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    defer if (template_text) |template| allocator.free(template);

    const workspace = try std.process.getCwdAlloc(allocator);
    defer allocator.free(workspace);

    const volt = try renderVoltConfig(allocator, token, workspace, template_text, account);
    defer allocator.free(volt);

    const volt_path = try joinPath(allocator, root, "volt.json");
    defer allocator.free(volt_path);
    try writeTextFile(volt_path, volt, true);

    const credentials_path = try joinPath(allocator, root, "credentials");
    defer allocator.free(credentials_path);
    try ensureDirIfMissing(credentials_path);

    const allow_path = try joinPath(allocator, root, "credentials/telegram-allowFrom.json");
    defer allocator.free(allow_path);
    const allow_text = try renderAllowFromJson(allocator, opts.allow_from.items);
    defer allocator.free(allow_text);
    try writeTextFile(allow_path, allow_text, opts.force);

    const pairing_path = try joinPath(allocator, root, "credentials/telegram-pairing.json");
    defer allocator.free(pairing_path);
    try writeTextFile(pairing_path, DefaultPairingJson, opts.force);

    const offset_path = try resolveTelegramOffsetPath(allocator, root, account);
    defer allocator.free(offset_path);
    try writeTextFile(offset_path, DefaultOffsetJson, true);

    const update_check_path = try joinPath(allocator, root, "update-check.json");
    defer allocator.free(update_check_path);
    if (!pathExists(update_check_path)) {
        try writeTextFile(update_check_path, DefaultUpdateCheckJson, true);
    }
}

fn runTelegramGateway(allocator: Allocator, opts: TelegramRunOptions) !void {
    const root = try resolveHomePath(allocator, opts.home_path);
    defer allocator.free(root);

    const account = try normalizeAccountId(allocator, opts.account);
    defer allocator.free(account);

    const token = blk: {
        if (opts.token) |token_arg| {
            break :blk try allocator.dupe(u8, token_arg);
        }

        const path = try resolveConfigPath(allocator, root);
        defer allocator.free(path);

        const data = readFileAlloc(allocator, path) catch |err| {
            if (err == error.FileNotFound) return error.MissingBotToken;
            return err;
        };
        defer allocator.free(data);

        break :blk try resolveTelegramTokenFromConfig(allocator, data, account);
    };
    defer allocator.free(token);

    if (token.len == 0) return error.MissingBotToken;

    const allowed = try loadAllowFrom(allocator, root);
    defer allowed.deinit();
    const allow_list = allowed.value.allowFrom;

    const dispatch = if (opts.zolt) DispatchPlan{} else try parseDispatchPlan(allocator, opts.dispatch);
    defer deinitDispatchPlan(allocator, dispatch);

    const zolt_cmd = if (opts.zolt) blk: {
        const zolt_cmd = try resolveZoltCommand(allocator, opts.zolt_command);
        errdefer allocator.free(zolt_cmd);

        validateDispatchExecutable(allocator, zolt_cmd) catch |err| {
            switch (err) {
                error.DispatchBinaryNotFound => {
                    try std.fs.File.stderr().deprecatedWriter().print(
                        "volt: dispatch binary not found: {s}\n",
                        .{zolt_cmd},
                    );
                },
                error.DispatchBinaryNotExecutable => {
                    try std.fs.File.stderr().deprecatedWriter().print(
                        "volt: dispatch binary not executable: {s}\n",
                        .{zolt_cmd},
                    );
                },
                else => {
                    try std.fs.File.stderr().deprecatedWriter().print(
                        "volt: dispatch validation failed: {s}\n",
                        .{@errorName(err)},
                    );
                },
            }
            return err;
        };

        break :blk zolt_cmd;
    } else null;
    defer if (zolt_cmd) |command| allocator.free(command);

    if (dispatch.mode == .argv and dispatch.argv.len > 0) {
        validateDispatchExecutable(allocator, dispatch.argv[0]) catch |err| {
            switch (err) {
                error.DispatchBinaryNotFound => {
                    try std.fs.File.stderr().deprecatedWriter().print(
                        "volt: dispatch binary not found: {s}\n",
                        .{dispatch.argv[0]},
                    );
                },
                error.DispatchBinaryNotExecutable => {
                    try std.fs.File.stderr().deprecatedWriter().print(
                        "volt: dispatch binary not executable: {s}\n",
                        .{dispatch.argv[0]},
                    );
                },
                else => {
                    try std.fs.File.stderr().deprecatedWriter().print(
                        "volt: dispatch validation failed: {s}\n",
                        .{@errorName(err)},
                    );
                },
            }
            return err;
        };
    }

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    registerTelegramCommands(allocator, &client, token) catch |err| {
        std.log.warn("volt: failed to register telegram slash commands: {s}", .{@errorName(err)});
    };

    var current_offset = try loadOffset(allocator, root, account);

    while (true) {
        const updates = fetchUpdates(allocator, &client, token, current_offset, opts.poll_ms) catch |err| {
            _ = std.log.err("telegram getUpdates failed: {s}", .{@errorName(err)});
            std.Thread.sleep(clampPollInterval(opts.poll_ms) * std.time.ns_per_ms);
            continue;
        };
        defer updates.deinit(allocator);

        var next_offset = current_offset;
        for (updates.parsed.value.result) |update| {
            if (update.message) |message| {
                const chat = message.chat orelse continue;
                const text = message.text orelse continue;
                if (!chatAllowed(allow_list, chat.id)) continue;

                const session_key = try std.fmt.allocPrint(allocator, "telegram:{s}:{d}", .{ account, chat.id });
                defer allocator.free(session_key);

                const dispatch_ctx = TelegramDispatchContext{
                    .message = text,
                    .account = account,
                    .chat_id = chat.id,
                    .session_key = session_key,
                };

                if (extractTelegramSlashCommand(text)) |command| {
                    const output = executeTelegramSlashCommand(
                        allocator,
                        command,
                        root,
                        session_key,
                        account,
                        chat.id,
                        zolt_cmd,
                    ) catch |err| {
                        const error_msg = try std.fmt.allocPrint(allocator, "command failed: {s}", .{@errorName(err)});
                        defer allocator.free(error_msg);
                        try sendTelegramMessage(allocator, &client, token, chat.id, error_msg);
                        next_offset = @max(next_offset, update.update_id + 1);
                        continue;
                    };
                    defer allocator.free(output);

                    const response_text = if (output.len == 0) "(no output)" else output;
                    const clipped = if (response_text.len > 3800) response_text[0..3800] else response_text;
                    try sendTelegramMessage(allocator, &client, token, chat.id, clipped);
                    next_offset = @max(next_offset, update.update_id + 1);
                    continue;
                }

                const output = if (zolt_cmd) |command| blk: {
                    break :blk runTelegramThroughZolt(
                        allocator,
                        root,
                        command,
                        session_key,
                        text,
                    ) catch |err| {
                        const error_msg = try std.fmt.allocPrint(allocator, "command failed: {s}", .{@errorName(err)});
                        defer allocator.free(error_msg);
                        try sendTelegramMessage(allocator, &client, token, chat.id, error_msg);
                        continue;
                    };
                } else executeDispatchForTelegram(allocator, dispatch, dispatch_ctx) catch |err| {
                    const error_msg = try std.fmt.allocPrint(allocator, "command failed: {s}", .{@errorName(err)});
                    defer allocator.free(error_msg);
                    try sendTelegramMessage(allocator, &client, token, chat.id, error_msg);
                    continue;
                };
                defer allocator.free(output);

                const response_text = if (output.len == 0) "(no output)" else output;
                const clipped = if (response_text.len > 3800) response_text[0..3800] else response_text;
                try sendTelegramMessage(allocator, &client, token, chat.id, clipped);

                next_offset = @max(next_offset, update.update_id + 1);
            }
        }

        if (next_offset != current_offset) {
            current_offset = next_offset;
            try persistOffset(allocator, root, account, current_offset);
            continue;
        }

        std.Thread.sleep(clampPollInterval(opts.poll_ms) * std.time.ns_per_ms);
    }
}

fn extractTelegramSlashCommand(text: []const u8) ?TelegramSlashCommand {
    const trimmed = std.mem.trim(u8, text, " \t\r\n");
    if (trimmed.len == 0 or trimmed[0] != '/') return null;
    if (trimmed.len == 1) return null;

    var end: usize = 1;
    while (end < trimmed.len and !std.ascii.isWhitespace(trimmed[end])) {
        end += 1;
    }

    const raw_command_token = trimmed[1..end];
    if (raw_command_token.len == 0) return null;

    const command = if (std.mem.indexOfScalar(u8, raw_command_token, '@')) |at|
        raw_command_token[0..at]
    else
        raw_command_token;
    if (command.len == 0) return null;

    const command_args = if (end < trimmed.len)
        std.mem.trim(u8, trimmed[end..], " \t\r\n")
    else
        "";

    return TelegramSlashCommand{
        .command = command,
        .args = command_args,
    };
}

fn executeTelegramSlashCommand(
    allocator: Allocator,
    command: TelegramSlashCommand,
    root: []const u8,
    session_key: []const u8,
    account: []const u8,
    chat_id: i64,
    zolt_cmd: ?[]const u8,
) ![]u8 {
    if (isTelegramSlashCommand(command.command, "help") or isTelegramSlashCommand(command.command, "?")) {
        return renderTelegramSlashHelp(allocator);
    }

    if (isTelegramSlashCommand(command.command, "commands") or isTelegramSlashCommand(command.command, "menu")) {
        return renderTelegramSlashCommands(allocator);
    }

    if (isTelegramSlashCommand(command.command, "sessions") or isTelegramSlashCommand(command.command, "session")) {
        const mapped = loadTelegramZoltSessionId(allocator, root, session_key) catch null;
        defer if (mapped) |session| allocator.free(session);

        if (mapped) |session| {
            return try std.fmt.allocPrint(allocator, "chat {d} session: {s}", .{ chat_id, session });
        }
        return try std.fmt.allocPrint(allocator, "chat {d} has no active zolt session", .{chat_id});
    }

    if (isTelegramSlashCommand(command.command, "status")) {
        const mapped = loadTelegramZoltSessionId(allocator, root, session_key) catch null;
        defer if (mapped) |session| allocator.free(session);

        const mapped_value = if (mapped) |session| session else "none";
        const zolt_label = zolt_cmd orelse "(not configured)";

        return try std.fmt.allocPrint(
            allocator,
            "Volt status\naccount: {s}\nchat: {d}\nsession-key: {s}\nzolt-session: {s}\nzolt-command: {s}\n",
            .{ account, chat_id, session_key, mapped_value, zolt_label },
        );
    }

    if (isTelegramSlashCommand(command.command, "reset") or isTelegramSlashCommand(command.command, "new")) {
        const cleared = try clearTelegramZoltSessionId(allocator, root, session_key);
        if (cleared) {
            return try allocator.dupe(u8, "zolt session reset for this chat");
        }
        return try allocator.dupe(u8, "no active zolt session found for this chat");
    }

    if (isTelegramSlashCommand(command.command, "models")) {
        if (zolt_cmd) |command_bin| {
            return runZoltModelsCommand(allocator, command_bin);
        }
        return try allocator.dupe(u8, "models command requires --zolt mode");
    }

    return try std.fmt.allocPrint(allocator, "unknown command: /{s}. /help for available commands.", .{command.command});
}

fn isTelegramSlashCommand(value: []const u8, expected: []const u8) bool {
    return std.ascii.eqlIgnoreCase(value, expected);
}

fn renderTelegramSlashCommands(allocator: Allocator) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    defer out.deinit(allocator);

    try out.appendSlice(allocator, "Volt commands:\n");
    for (VoltTelegramSlashCommands) |entry| {
        try out.appendSlice(allocator, " /");
        try out.appendSlice(allocator, entry.command);
        if (entry.description.len > 0) {
            try out.appendSlice(allocator, " - ");
            try out.appendSlice(allocator, entry.description);
        }
        try out.append(allocator, '\n');
    }
    try out.appendSlice(allocator, "/help, /? - this message");
    return out.toOwnedSlice(allocator);
}

fn renderTelegramSlashHelp(allocator: Allocator) ![]u8 {
    return try allocator.dupe(
        u8,
        "Volt Telegram bot commands:\n" ++
            "/commands - show command list\n" ++
            "/sessions - show mapped zolt session\n" ++
            "/status - show runtime status\n" ++
            "/reset - clear mapped zolt session\n" ++
            "/models - show zolt model info\n",
    );
}

fn runZoltModelsCommand(allocator: Allocator, zolt_cmd: []const u8) ![]u8 {
    const argv = [_][]const u8{ zolt_cmd, "models" };
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &argv,
    });
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    return try composeChildOutput(
        allocator,
        result.stdout,
        result.stderr,
        result.term,
    );
}

fn registerTelegramCommands(allocator: Allocator, client: *std.http.Client, token: []const u8) !void {
    var payload = std.ArrayListUnmanaged(u8){};
    defer payload.deinit(allocator);

    try payload.appendSlice(allocator, "{\"commands\":[");
    for (VoltTelegramSlashCommands, 0..) |entry, index| {
        if (index > 0) {
            try payload.appendSlice(allocator, ",");
        }
        try payload.appendSlice(allocator, "{\"command\":\"");
        try appendTelegramJsonEscape(allocator, &payload, entry.command);
        try payload.appendSlice(allocator, "\",\"description\":\"");
        try appendTelegramJsonEscape(allocator, &payload, entry.description);
        try payload.appendSlice(allocator, "\"}");
    }
    try payload.appendSlice(allocator, "]}");

    const payload_text = try payload.toOwnedSlice(allocator);
    defer allocator.free(payload_text);

    var url_buf: [512]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://api.telegram.org/bot{s}/setMyCommands", .{token});

    var response = std.Io.Writer.Allocating.init(allocator);
    defer response.deinit();

    const result = try client.fetch(.{
        .location = .{ .url = url },
        .method = .POST,
        .payload = payload_text,
        .response_writer = &response.writer,
        .extra_headers = &[_]std.http.Header{
            .{ .name = "content-type", .value = "application/json" },
        },
    });

    if (result.status != .ok) {
        return error.TelegramRequestFailed;
    }

    const response_text = try response.toOwnedSlice();
    defer allocator.free(response_text);

    const parsed = std.json.parseFromSlice(
        TelegramCommandsResponse,
        allocator,
        response_text,
        .{ .ignore_unknown_fields = true },
    ) catch return error.TelegramRequestFailed;
    defer parsed.deinit();

    if (!parsed.value.ok) {
        return error.TelegramRequestFailed;
    }
}

fn appendTelegramJsonEscape(
    allocator: Allocator,
    out: *std.ArrayListUnmanaged(u8),
    value: []const u8,
) !void {
    for (value) |byte| {
        switch (byte) {
            '\"' => try out.appendSlice(allocator, "\\\""),
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            else => try out.append(allocator, byte),
        }
    }
}

fn parseInitOptions(args: []const []const u8) !InitOptions {
    var result = InitOptions{
        .mirror_volt = false,
        .force = false,
        .home_path = null,
        .source_path = null,
    };

    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];
        if (std.mem.eql(u8, arg, "--mirror-volt")) {
            result.mirror_volt = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--force")) {
            result.force = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--home")) {
            if (idx + 1 >= args.len) return error.UnexpectedArgument;
            result.home_path = args[idx + 1];
            idx += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--source")) {
            if (idx + 1 >= args.len) return error.UnexpectedArgument;
            result.source_path = args[idx + 1];
            idx += 1;
            continue;
        }
        return error.UnknownArgument;
    }

    return result;
}

fn resolveZoltCommand(allocator: Allocator, explicit: ?[]const u8) ![]u8 {
    if (explicit) |command| {
        return allocator.dupe(u8, command);
    }

    return std.process.getEnvVarOwned(allocator, "VOLT_ZOLT_PATH") catch |err| {
        if (err == error.EnvironmentVariableNotFound) {
            if (resolveBundledZoltCommand(allocator)) |command| {
                return command;
            }
            return allocator.dupe(u8, defaultZoltBinaryName());
        }
        return err;
    };
}

fn resolveBundledZoltCommand(allocator: Allocator) ?[]u8 {
    const exe_dir = std.fs.selfExeDirPathAlloc(allocator) catch return null;
    defer allocator.free(exe_dir);

    const candidate = joinPath(
        allocator,
        exe_dir,
        defaultZoltBinaryName(),
    ) catch return null;

    if (!pathExists(candidate)) {
        allocator.free(candidate);
        return null;
    }

    return candidate;
}

fn defaultZoltBinaryName() []const u8 {
    return if (builtin.os.tag == .windows) "zolt.exe" else "zolt";
}

fn parseTelegramSetupOptions(allocator: Allocator, args: []const []const u8) !TelegramSetupOptions {
    var result = TelegramSetupOptions{
        .home_path = null,
        .token = null,
        .force = false,
        .account = null,
        .allow_from = .empty,
    };

    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];
        if (std.mem.eql(u8, arg, "--home")) {
            if (idx + 1 >= args.len) return error.UnexpectedArgument;
            result.home_path = args[idx + 1];
            idx += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--token")) {
            if (idx + 1 >= args.len) return error.UnexpectedArgument;
            result.token = args[idx + 1];
            idx += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--force")) {
            result.force = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--account")) {
            if (idx + 1 >= args.len) return error.UnexpectedArgument;
            result.account = args[idx + 1];
            idx += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--allow-from")) {
            if (idx + 1 >= args.len) return error.UnexpectedArgument;
            const entry = std.mem.trim(u8, args[idx + 1], " \t\r\n");
            if (entry.len > 0) {
                if (!hasDuplicate(allocator, result.allow_from.items, entry)) {
                    try result.allow_from.append(allocator, entry);
                }
            }
            idx += 1;
            continue;
        }
        return error.UnknownArgument;
    }

    return result;
}

fn parseTelegramRunOptions(args: []const []const u8) !TelegramRunOptions {
    var result = TelegramRunOptions{
        .home_path = null,
        .token = null,
        .dispatch = null,
        .zolt = false,
        .zolt_command = null,
        .account = null,
        .poll_ms = 2500,
    };

    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];
        if (std.mem.eql(u8, arg, "--home")) {
            if (idx + 1 >= args.len) return error.UnexpectedArgument;
            result.home_path = args[idx + 1];
            idx += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--token")) {
            if (idx + 1 >= args.len) return error.UnexpectedArgument;
            result.token = args[idx + 1];
            idx += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--account")) {
            if (idx + 1 >= args.len) return error.UnexpectedArgument;
            result.account = args[idx + 1];
            idx += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--dispatch")) {
            if (idx + 1 >= args.len) return error.UnexpectedArgument;
            if (result.zolt) {
                return error.UnexpectedArgument;
            }
            result.dispatch = args[idx + 1];
            idx += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--zolt")) {
            if (result.dispatch != null) {
                return error.UnexpectedArgument;
            }
            result.zolt = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--zolt-path")) {
            if (idx + 1 >= args.len) return error.UnexpectedArgument;
            result.zolt_command = args[idx + 1];
            idx += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--poll-ms")) {
            if (idx + 1 >= args.len) return error.UnexpectedArgument;
            result.poll_ms = try std.fmt.parseInt(u64, args[idx + 1], 10);
            idx += 1;
            continue;
        }
        return error.UnknownArgument;
    }

    if (result.zolt_command != null and !result.zolt) {
        return error.UnexpectedArgument;
    }

    return result;
}

fn parseGatewayOptions(args: []const []const u8) !GatewayRunOptions {
    var result = GatewayRunOptions{
        .home_path = null,
        .bind = DefaultGatewayBind,
        .port = 18789,
        .account = null,
        .dispatch = null,
        .zolt = false,
        .zolt_command = null,
        .auth_token = null,
    };

    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];
        if (std.mem.eql(u8, arg, "--home")) {
            if (idx + 1 >= args.len) return error.UnexpectedArgument;
            result.home_path = args[idx + 1];
            idx += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--bind")) {
            if (idx + 1 >= args.len) return error.UnexpectedArgument;
            result.bind = args[idx + 1];
            idx += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--port")) {
            if (idx + 1 >= args.len) return error.UnexpectedArgument;
            result.port = try std.fmt.parseInt(u16, args[idx + 1], 10);
            idx += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--account")) {
            if (idx + 1 >= args.len) return error.UnexpectedArgument;
            result.account = args[idx + 1];
            idx += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--dispatch")) {
            if (idx + 1 >= args.len) return error.UnexpectedArgument;
            if (result.zolt) {
                return error.UnexpectedArgument;
            }
            result.dispatch = args[idx + 1];
            idx += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--zolt")) {
            if (result.dispatch != null) {
                return error.UnexpectedArgument;
            }
            result.zolt = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--zolt-path")) {
            if (idx + 1 >= args.len) return error.UnexpectedArgument;
            result.zolt_command = args[idx + 1];
            idx += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--auth-token")) {
            if (idx + 1 >= args.len) return error.UnexpectedArgument;
            result.auth_token = args[idx + 1];
            idx += 1;
            continue;
        }
        return error.UnknownArgument;
    }

    if (result.zolt_command != null and !result.zolt) {
        return error.UnexpectedArgument;
    }

    return result;
}

fn parseGatewayServiceAction(arg: []const u8) GatewayServiceAction {
    if (std.mem.eql(u8, arg, "install")) return .install;
    if (std.mem.eql(u8, arg, "uninstall")) return .uninstall;
    if (std.mem.eql(u8, arg, "start")) return .start;
    if (std.mem.eql(u8, arg, "stop")) return .stop;
    if (std.mem.eql(u8, arg, "restart")) return .restart;
    if (std.mem.eql(u8, arg, "status")) return .status;
    return .run;
}

fn runGatewayServiceAction(
    allocator: Allocator,
    action: GatewayServiceAction,
    opts: GatewayRunOptions,
) !void {
    switch (builtin.os.tag) {
        .linux => {
            try runGatewayServiceLinux(allocator, action, opts);
        },
        .macos => {
            try runGatewayServiceMacos(allocator, action, opts);
        },
        else => return GatewayServiceError.GatewayServiceUnsupportedPlatform,
    }
}

fn runGatewayServiceLinux(allocator: Allocator, action: GatewayServiceAction, opts: GatewayRunOptions) !void {
    const exe_path = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(exe_path);

    const unit_path = try resolveGatewaySystemdServicePath(allocator);
    defer allocator.free(unit_path);

    switch (action) {
        .install => {
            const unit = try buildGatewaySystemdUnit(allocator, exe_path, opts);
            defer allocator.free(unit);
            try writeTextFile(unit_path, unit, true);
            try runGatewayCommand(allocator, &.{ "systemctl", "--user", "daemon-reload" }, false);
            try runGatewayCommand(allocator, &.{ "systemctl", "--user", "enable", GatewaySystemdUnit }, false);
            try runGatewayCommand(allocator, &.{ "systemctl", "--user", "start", GatewaySystemdUnit }, false);
            try std.fs.File.stderr().deprecatedWriter().print("volt: installed gateway service: {s}\n", .{GatewaySystemdUnit});
        },
        .uninstall => {
            try runGatewayCommandOrWarn(allocator, &.{ "systemctl", "--user", "stop", GatewaySystemdUnit });
            try runGatewayCommandOrWarn(allocator, &.{ "systemctl", "--user", "disable", GatewaySystemdUnit });
            if (std.fs.cwd().deleteFile(unit_path)) |_| {} else |err| if (err != error.FileNotFound) return err;
            try runGatewayCommand(allocator, &.{ "systemctl", "--user", "daemon-reload" }, false);
            try std.fs.File.stderr().deprecatedWriter().print("volt: uninstalled gateway service: {s}\n", .{GatewaySystemdUnit});
        },
        .start => {
            try runGatewayCommand(allocator, &.{ "systemctl", "--user", "start", GatewaySystemdUnit }, false);
            try std.fs.File.stderr().deprecatedWriter().print("volt: started gateway service\n", .{});
        },
        .stop => {
            try runGatewayCommand(allocator, &.{ "systemctl", "--user", "stop", GatewaySystemdUnit }, true);
            try std.fs.File.stderr().deprecatedWriter().print("volt: stopped gateway service\n", .{});
        },
        .restart => {
            try runGatewayCommand(allocator, &.{ "systemctl", "--user", "restart", GatewaySystemdUnit }, true);
            try std.fs.File.stderr().deprecatedWriter().print("volt: restarted gateway service\n", .{});
        },
        .status => {
            var status = std.ArrayListUnmanaged(u8){};
            defer status.deinit(allocator);
            try status.appendSlice(allocator, "unknown");

            try runGatewayCommandWithOutput(
                allocator,
                &.{ "systemctl", "--user", "is-active", GatewaySystemdUnit },
                true,
                &status,
                true,
            );

            std.fs.File.stderr().deprecatedWriter().print("volt: gateway service status: {s}\n", .{status.items}) catch {};
        },
        .run => return,
    }
}

fn runGatewayServiceMacos(allocator: Allocator, action: GatewayServiceAction, opts: GatewayRunOptions) !void {
    const exe_path = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(exe_path);

    const plist_path = try resolveGatewayLaunchdPlistPath(allocator);
    defer allocator.free(plist_path);

    const service_label = GatewayLaunchdLabel;
    const gui_scope = try getLaunchdGuiScope(allocator);
    defer allocator.free(gui_scope);
    const launchd_service = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ gui_scope, service_label });
    defer allocator.free(launchd_service);

    switch (action) {
        .install => {
            const plist = try buildGatewayLaunchdPlist(allocator, exe_path, opts);
            defer allocator.free(plist);
            try writeTextFile(plist_path, plist, true);
            try runGatewayCommand(allocator, &.{ "launchctl", "bootstrap", gui_scope, plist_path }, false);
            try std.fs.File.stderr().deprecatedWriter().print("volt: installed gateway service: {s}\n", .{service_label});
        },
        .uninstall => {
            try runGatewayCommand(allocator, &.{ "launchctl", "bootout", gui_scope, plist_path }, true);
            if (std.fs.cwd().deleteFile(plist_path)) |_| {} else |err| if (err != error.FileNotFound) return err;
            try std.fs.File.stderr().deprecatedWriter().print("volt: uninstalled gateway service: {s}\n", .{service_label});
        },
        .start => {
            try runGatewayCommand(allocator, &.{ "launchctl", "bootstrap", gui_scope, plist_path }, false);
            try std.fs.File.stderr().deprecatedWriter().print("volt: started gateway service\n", .{});
        },
        .stop => {
            try runGatewayCommandOrWarn(allocator, &.{ "launchctl", "bootout", gui_scope, launchd_service });
            try std.fs.File.stderr().deprecatedWriter().print("volt: stopped gateway service\n", .{});
        },
        .restart => {
            try runGatewayCommandOrWarn(allocator, &.{ "launchctl", "bootout", gui_scope, launchd_service });
            try runGatewayCommand(allocator, &.{ "launchctl", "bootstrap", gui_scope, plist_path }, false);
            try std.fs.File.stderr().deprecatedWriter().print("volt: restarted gateway service\n", .{});
        },
        .status => {
            var status = std.ArrayListUnmanaged(u8){};
            defer status.deinit(allocator);
            try runGatewayCommandWithOutput(
                allocator,
                &.{ "launchctl", "print", launchd_service },
                false,
                &status,
                true,
            );
            try std.fs.File.stderr().deprecatedWriter().print("volt: gateway service status:\n{s}\n", .{status.items});
        },
        .run => return,
    }
}

fn runGatewayCommand(allocator: Allocator, argv: []const []const u8, tolerate_failure: bool) !void {
    return runGatewayCommandWithOutput(allocator, argv, false, null, tolerate_failure);
}

fn runGatewayCommandWithOutput(
    allocator: Allocator,
    argv: []const []const u8,
    capture_output: bool,
    output_sink: ?*std.ArrayListUnmanaged(u8),
    tolerate_failure: bool,
) !void {
    const cmd = try std.process.Child.run(.{ .allocator = allocator, .argv = argv });
    defer {
        allocator.free(cmd.stdout);
        allocator.free(cmd.stderr);
    }

    if (capture_output) {
        if (output_sink) |sink| {
            try sink.appendSlice(allocator, std.mem.trim(u8, cmd.stdout, " \r\n"));
        }
    }

    switch (cmd.term) {
        .Exited => |code| {
            if (!tolerate_failure and code != 0) {
                if (cmd.stderr.len > 0) {
                    try std.fs.File.stderr().deprecatedWriter().print(
                        "volt: command failed: {s}\n",
                        .{cmd.stderr},
                    );
                } else if (cmd.stdout.len > 0) {
                    try std.fs.File.stderr().deprecatedWriter().print(
                        "volt: command failed: {s}\n",
                        .{cmd.stdout},
                    );
                }
                return GatewayServiceError.GatewayServiceCommandFailed;
            }
        },
        else => if (!tolerate_failure) return GatewayServiceError.GatewayServiceCommandFailed,
    }

    if (cmd.term == .Exited) {
        return;
    }

    return;
}

fn runGatewayCommandOrWarn(allocator: Allocator, argv: []const []const u8) !void {
    runGatewayCommandWithOutput(allocator, argv, false, null, true) catch |err| switch (err) {
        error.GatewayServiceCommandFailed => return,
        else => return err,
    };
}

fn getLaunchdGuiScope(allocator: Allocator) ![]u8 {
    const uid = std.posix.getuid();
    return try std.fmt.allocPrint(allocator, "gui/{d}", .{uid});
}

fn resolveGatewaySystemdServicePath(allocator: Allocator) ![]u8 {
    const config_root = resolveGatewayXdgConfigRoot(allocator) catch return error.GatewayServiceUnsupportedPlatform;
    const systemd_path = try joinPath(allocator, config_root, "systemd");
    defer allocator.free(systemd_path);
    const user_path = try joinPath(allocator, systemd_path, "user");
    defer allocator.free(user_path);
    try ensureDirIfMissing(user_path);
    return try joinPath(allocator, user_path, GatewaySystemdUnit);
}

fn resolveGatewayXdgConfigRoot(allocator: Allocator) ![]u8 {
    const xdg = std.process.getEnvVarOwned(allocator, "XDG_CONFIG_HOME") catch |err| {
        if (err != error.EnvironmentVariableNotFound) return err;
        const home = try resolveVoltHome(allocator);
        defer allocator.free(home);
        return try joinPath(allocator, home, ".config");
    };
    return xdg;
}

fn resolveGatewayLaunchdPlistPath(allocator: Allocator) ![]u8 {
    const home = try resolveVoltHome(allocator);
    defer allocator.free(home);
    const support = try joinPath(allocator, home, "Library/LaunchAgents");
    defer allocator.free(support);
    try ensureDirIfMissing(support);
    return try std.fmt.allocPrint(allocator, "{s}/{s}.plist", .{ support, GatewayLaunchdLabel });
}

fn buildGatewaySystemdUnit(allocator: Allocator, exe_path: []const u8, opts: GatewayRunOptions) ![]u8 {
    var exec_start = std.ArrayListUnmanaged(u8){};
    defer exec_start.deinit(allocator);

    const escaped_exe = try systemdShellQuote(allocator, exe_path);
    defer allocator.free(escaped_exe);
    try exec_start.appendSlice(allocator, escaped_exe);
    try exec_start.appendSlice(allocator, " gateway");
    try appendGatewayServiceArg(allocator, &exec_start, "--home", opts.home_path);
    try appendGatewayServiceArg(allocator, &exec_start, "--bind", opts.bind);
    const port = try std.fmt.allocPrint(allocator, "{d}", .{opts.port});
    defer allocator.free(port);
    try appendGatewayServiceArg(allocator, &exec_start, "--port", port);
    try appendGatewayServiceArg(allocator, &exec_start, "--account", opts.account);
    if (opts.zolt) {
        try exec_start.appendSlice(allocator, " --zolt");
        if (opts.zolt_command) |zolt_command| {
            try appendGatewayServiceArg(allocator, &exec_start, "--zolt-path", zolt_command);
        }
    } else if (opts.dispatch) |dispatch| {
        try appendGatewayServiceArg(allocator, &exec_start, "--dispatch", dispatch);
    }

    if (opts.auth_token) |auth_token| {
        try appendGatewayServiceArg(allocator, &exec_start, "--auth-token", auth_token);
    }

    return std.fmt.allocPrint(
        allocator,
        "[Unit]\n" ++
            "Description=volt gateway service\n" ++
            "After=network.target\n" ++
            "\n" ++
            "[Service]\n" ++
            "Type=simple\n" ++
            "ExecStart={s}\n" ++
            "Restart=always\n" ++
            "RestartSec=2\n" ++
            "\n" ++
            "[Install]\n" ++
            "WantedBy=default.target\n",
        .{exec_start.items},
    );
}

fn buildGatewayLaunchdPlist(allocator: Allocator, exe_path: []const u8, opts: GatewayRunOptions) ![]u8 {
    var args = std.ArrayListUnmanaged([]const u8){};
    defer {
        for (args.items) |entry| allocator.free(entry);
        args.deinit(allocator);
    }

    try args.append(allocator, try allocator.dupe(u8, exe_path));
    try args.append(allocator, try allocator.dupe(u8, "gateway"));
    if (opts.home_path) |home_path| {
        try args.append(allocator, try allocator.dupe(u8, "--home"));
        try args.append(allocator, try allocator.dupe(u8, home_path));
    }
    if (opts.bind.len > 0) {
        const bind = resolveGatewayBind(opts.bind);
        try args.append(allocator, try allocator.dupe(u8, "--bind"));
        try args.append(allocator, try allocator.dupe(u8, bind));
    }
    const port = try std.fmt.allocPrint(allocator, "{d}", .{opts.port});
    defer allocator.free(port);
    try args.append(allocator, try allocator.dupe(u8, "--port"));
    try args.append(allocator, try allocator.dupe(u8, port));
    if (opts.account) |account| {
        try args.append(allocator, try allocator.dupe(u8, "--account"));
        try args.append(allocator, try allocator.dupe(u8, account));
    }
    if (opts.zolt) {
        try args.append(allocator, try allocator.dupe(u8, "--zolt"));
        if (opts.zolt_command) |zolt_command| {
            try args.append(allocator, try allocator.dupe(u8, "--zolt-path"));
            try args.append(allocator, try allocator.dupe(u8, zolt_command));
        }
    } else if (opts.dispatch) |dispatch| {
        try args.append(allocator, try allocator.dupe(u8, "--dispatch"));
        try args.append(allocator, try allocator.dupe(u8, dispatch));
    }
    if (opts.auth_token) |auth_token| {
        try args.append(allocator, try allocator.dupe(u8, "--auth-token"));
        try args.append(allocator, try allocator.dupe(u8, auth_token));
    }

    var xml = std.ArrayListUnmanaged(u8){};
    defer xml.deinit(allocator);
    try xml.appendSlice(allocator, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    try xml.appendSlice(allocator, "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n");
    try xml.appendSlice(allocator, "<plist version=\"1.0\">\n");
    try xml.appendSlice(allocator, "  <dict>\n");
    try xml.appendSlice(allocator, "    <key>Label</key>\n");
    try xml.appendSlice(allocator, "    <string>");
    try xml.appendSlice(allocator, GatewayLaunchdLabel);
    try xml.appendSlice(allocator, "</string>\n");
    try xml.appendSlice(allocator, "    <key>RunAtLoad</key>\n");
    try xml.appendSlice(allocator, "    <true/>\n");
    try xml.appendSlice(allocator, "    <key>ProgramArguments</key>\n");
    try xml.appendSlice(allocator, "    <array>\n");
    for (args.items) |arg| {
        try xml.appendSlice(allocator, "      <string>");
        const escaped = try escapeXmlString(allocator, arg);
        defer allocator.free(escaped);
        try xml.appendSlice(allocator, escaped);
        try xml.appendSlice(allocator, "</string>\n");
    }
    try xml.appendSlice(allocator, "    </array>\n");
    try xml.appendSlice(allocator, "  </dict>\n");
    try xml.appendSlice(allocator, "</plist>\n");

    return xml.toOwnedSlice(allocator);
}

fn appendGatewayServiceArg(
    allocator: Allocator,
    out: *std.ArrayListUnmanaged(u8),
    name: []const u8,
    value: ?[]const u8,
) !void {
    if (value) |raw| {
        if (raw.len == 0) return;
        try out.appendSlice(allocator, " ");
        const escaped_name = try systemdShellQuote(allocator, name);
        defer allocator.free(escaped_name);
        try out.appendSlice(allocator, escaped_name);
        const escaped_value = try systemdShellQuote(allocator, raw);
        defer allocator.free(escaped_value);
        try out.appendSlice(allocator, " ");
        try out.appendSlice(allocator, escaped_value);
    }
}

fn systemdShellQuote(allocator: Allocator, value: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    defer out.deinit(allocator);
    try out.append(allocator, '\'');
    if (value.len == 0) {
        try out.append(allocator, '\'');
        return try out.toOwnedSlice(allocator);
    }
    for (value) |byte| {
        if (byte == '\'') {
            try out.appendSlice(allocator, "'\"'\"'");
        } else {
            try out.append(allocator, byte);
        }
    }
    try out.append(allocator, '\'');
    return out.toOwnedSlice(allocator);
}

fn escapeXmlString(allocator: Allocator, value: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    defer out.deinit(allocator);
    for (value) |byte| {
        switch (byte) {
            '&' => try out.appendSlice(allocator, "&amp;"),
            '<' => try out.appendSlice(allocator, "&lt;"),
            '>' => try out.appendSlice(allocator, "&gt;"),
            '"' => try out.appendSlice(allocator, "&quot;"),
            '\'' => try out.appendSlice(allocator, "&apos;"),
            else => try out.append(allocator, byte),
        }
    }
    return out.toOwnedSlice(allocator);
}

fn resolveHomePath(allocator: Allocator, override: ?[]const u8) ![]u8 {
    return resolveConfigRoot(allocator, override);
}

fn resolveConfigRoot(allocator: Allocator, override: ?[]const u8) ![]u8 {
    if (override) |value| {
        const base = try resolveVoltHome(allocator);
        defer allocator.free(base);
        return try resolveExpandedPath(allocator, value, base);
    }

    const volt_state_dir = std.process.getEnvVarOwned(allocator, "VOLT_STATE_DIR") catch |err| {
        return switch (err) {
            error.EnvironmentVariableNotFound => {
                const home = try resolveVoltHome(allocator);
                defer allocator.free(home);
                return try joinPath(allocator, home, ".volt");
            },
            else => return err,
        };
    };
    defer allocator.free(volt_state_dir);

    const home = try resolveVoltHome(allocator);
    defer allocator.free(home);
    return try resolveExpandedPath(allocator, volt_state_dir, home);
}

fn resolveVoltHome(allocator: Allocator) ![]u8 {
    const volt_home = std.process.getEnvVarOwned(allocator, "VOLT_HOME") catch |err| {
        return switch (err) {
            error.EnvironmentVariableNotFound => {
                const home = std.process.getEnvVarOwned(allocator, "HOME") catch |home_err| {
                    return switch (home_err) {
                        error.EnvironmentVariableNotFound => {
                            const cwd = try std.process.getCwdAlloc(allocator);
                            defer allocator.free(cwd);
                            return try allocator.dupe(u8, cwd);
                        },
                        else => return home_err,
                    };
                };
                defer allocator.free(home);
                const trimmed = std.mem.trim(u8, home, " \t\r\n");
                if (trimmed.len == 0) {
                    const cwd = try std.process.getCwdAlloc(allocator);
                    defer allocator.free(cwd);
                    return try allocator.dupe(u8, cwd);
                }
                return try allocator.dupe(u8, trimmed);
            },
            else => return err,
        };
    };
    defer allocator.free(volt_home);
    const trimmed = std.mem.trim(u8, volt_home, " \t\r\n");
    if (trimmed.len == 0) {
        const cwd = try std.process.getCwdAlloc(allocator);
        defer allocator.free(cwd);
        return try allocator.dupe(u8, cwd);
    }
    const host_home = try resolveHostHome(allocator);
    defer allocator.free(host_home);
    return try resolveExpandedPath(allocator, volt_home, host_home);
}

fn resolveHostHome(allocator: Allocator) ![]u8 {
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch |home_err| {
        return switch (home_err) {
            error.EnvironmentVariableNotFound => {
                const cwd = try std.process.getCwdAlloc(allocator);
                defer allocator.free(cwd);
                return try allocator.dupe(u8, cwd);
            },
            else => return home_err,
        };
    };
    defer allocator.free(home);

    const trimmed = std.mem.trim(u8, home, " \t\r\n");
    if (trimmed.len == 0) {
        const cwd = try std.process.getCwdAlloc(allocator);
        defer allocator.free(cwd);
        return try allocator.dupe(u8, cwd);
    }

    return try allocator.dupe(u8, trimmed);
}

fn resolveExpandedPath(allocator: Allocator, value: []const u8, fallback_home: []const u8) ![]u8 {
    const trimmed = std.mem.trim(u8, value, " \t\r\n");
    if (trimmed.len == 0) {
        return allocator.dupe(u8, ".");
    }

    if (trimmed[0] != '~') {
        return allocator.dupe(u8, trimmed);
    }

    if (trimmed.len == 1) {
        return try allocator.dupe(u8, fallback_home);
    }

    if (trimmed[1] != '/' and trimmed[1] != '\\') {
        return allocator.dupe(u8, trimmed);
    }

    const suffix = std.mem.trimLeft(u8, trimmed[1..], "/\\");
    if (suffix.len == 0) {
        return try allocator.dupe(u8, fallback_home);
    }

    return try joinPath(allocator, fallback_home, suffix);
}

fn resolveConfigPath(allocator: Allocator, home_root: []const u8) ![]u8 {
    const config_path = std.process.getEnvVarOwned(allocator, "VOLT_CONFIG_PATH") catch |err| {
        switch (err) {
            error.EnvironmentVariableNotFound => {
                const home = try resolveVoltHome(allocator);
                defer allocator.free(home);
                return try joinPath(allocator, home_root, "volt.json");
            },
            else => return err,
        }
    };
    defer allocator.free(config_path);

    const home = try resolveVoltHome(allocator);
    defer allocator.free(home);
    return try resolveExpandedPath(allocator, config_path, home);
}

fn joinPath(allocator: Allocator, base: []const u8, rel: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ base, rel });
}

fn ensureDirIfMissing(path: []const u8) !void {
    std.fs.makeDirAbsolute(path) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };
}

fn ensureParentDir(path: []const u8) !void {
    const parent = std.fs.path.dirname(path) orelse return;
    try ensureDirIfMissing(parent);
}

fn pathExists(path: []const u8) bool {
    std.fs.accessAbsolute(path, .{}) catch return false;
    return true;
}

fn writeTextFile(path: []const u8, content: []const u8, overwrite: bool) !void {
    if (!overwrite and pathExists(path)) return;

    try ensureParentDir(path);
    var file = try std.fs.createFileAbsolute(path, .{ .truncate = true });
    defer file.close();
    var out = file.deprecatedWriter();
    try out.writeAll(content);
}

fn copyIfExists(allocator: Allocator, source: []const u8, dest: []const u8, overwrite: bool) !void {
    _ = allocator;
    if (!overwrite and pathExists(dest)) return;
    if (!pathExists(source)) return;

    try ensureParentDir(dest);
    try std.fs.copyFileAbsolute(source, dest, .{});
}

fn readFileAlloc(allocator: Allocator, path: []const u8) ![]u8 {
    var file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();

    const size = try file.getEndPos();
    return try file.readToEndAlloc(allocator, size);
}

fn loadTemplateText(allocator: Allocator, source_root: []const u8) !?[]u8 {
    const template_path = try joinPath(allocator, source_root, "volt.json");
    defer allocator.free(template_path);

    return try readFileAlloc(allocator, template_path);
}

fn renderVoltConfig(
    allocator: Allocator,
    token: []const u8,
    workspace: []const u8,
    template_text: ?[]const u8,
    account_id: ?[]const u8,
) ![]u8 {
    if (template_text) |template| {
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, template, .{}) catch {
            return try renderVoltSeedConfig(allocator, token, workspace, account_id);
        };
        defer parsed.deinit();

        var root = parsed.value;
        try patchVoltValue(allocator, &root, token, workspace, account_id);

        var out = std.Io.Writer.Allocating.init(allocator);
        defer out.deinit();

        var stringify = std.json.Stringify{ .writer = &out.writer, .options = .{} };
        try stringify.write(root);
        return out.toOwnedSlice();
    }

    return try renderVoltSeedConfig(allocator, token, workspace, account_id);
}

fn renderVoltSeedConfig(
    allocator: Allocator,
    token: []const u8,
    workspace: []const u8,
    account_id: ?[]const u8,
) ![]u8 {
    const account = account_id orelse DefaultAccountId;
    var seed = DEFAULT_VOLT_SEED;
    if (std.mem.eql(u8, account, DefaultAccountId)) {
        seed.channels.telegram.botToken = token;
    }
    seed.gateway.auth.token = DefaultGatewayToken;

    var out = std.Io.Writer.Allocating.init(allocator);
    defer out.deinit();

    var stringify = std.json.Stringify{ .writer = &out.writer, .options = .{} };
    try stringify.write(seed);

    const rendered = try out.toOwnedSlice();
    defer allocator.free(rendered);
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        allocator,
        rendered,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    var root = parsed.value;
    try patchVoltValue(allocator, &root, token, workspace, account_id);

    var rewritten = std.Io.Writer.Allocating.init(allocator);
    defer rewritten.deinit();

    stringify = std.json.Stringify{ .writer = &rewritten.writer, .options = .{} };
    try stringify.write(root);
    return rewritten.toOwnedSlice();
}

fn patchVoltValue(
    allocator: Allocator,
    root: *std.json.Value,
    token: []const u8,
    workspace: []const u8,
    account_id: ?[]const u8,
) !void {
    const account = account_id orelse DefaultAccountId;
    if (std.mem.eql(u8, account, DefaultAccountId)) {
        try setJsonStringField(allocator, root, &.{ "channels", "telegram", "botToken" }, token);
    } else {
        const account_path = [_][]const u8{
            "channels",
            "telegram",
            "accounts",
            account,
            "botToken",
        };
        try setJsonStringField(allocator, root, account_path[0..], token);
    }
    try setJsonStringField(allocator, root, &.{ "gateway", "auth", "token" }, DefaultGatewayToken);
    try setJsonStringField(allocator, root, &.{ "skills", "entries", "openai-image-gen", "apiKey" }, "");

    if (workspace.len > 0) {
        try setJsonStringField(allocator, root, &.{ "agents", "defaults", "workspace" }, workspace);
    }
}

fn setJsonStringField(
    allocator: Allocator,
    root: *std.json.Value,
    path: []const []const u8,
    value: []const u8,
) !void {
    if (path.len == 0) return;

    var current = root;
    for (path[0 .. path.len - 1]) |key| {
        if (current.* != .object) return;

        const gop = try current.object.getOrPut(key);
        if (!gop.found_existing or gop.value_ptr.* != .object) {
            gop.value_ptr.* = .{ .object = std.json.ObjectMap.init(allocator) };
        }
        current = gop.value_ptr;
    }

    if (current.* != .object) return;
    const leaf = path[path.len - 1];
    const leaf_gop = try current.object.getOrPut(leaf);
    leaf_gop.value_ptr.* = .{ .string = value };
}

fn renderAllowFromJson(allocator: Allocator, allow: []const []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    defer out.deinit(allocator);

    try out.appendSlice(allocator, "{\"version\":1,\"allowFrom\":[");
    for (allow, 0..) |entry, i| {
        if (i > 0) try out.appendSlice(allocator, ",");
        try out.appendSlice(allocator, "\"");
        try out.appendSlice(allocator, entry);
        try out.appendSlice(allocator, "\"");
    }
    try out.appendSlice(allocator, "]}");

    return out.toOwnedSlice(allocator);
}

fn parseDispatchPlan(allocator: Allocator, dispatch: ?[]const u8) !DispatchPlan {
    const raw = std.mem.trim(u8, dispatch orelse "", " \t\r\n");
    if (raw.len == 0) {
        return DispatchPlan{};
    }

    const argv = try parseCommandLineTokens(allocator, raw);
    if (argv.len == 0) {
        return DispatchPlan{};
    }

    return DispatchPlan{
        .mode = .argv,
        .argv = argv,
    };
}

fn deinitDispatchPlan(allocator: Allocator, plan: DispatchPlan) void {
    if (plan.mode != .argv) return;
    for (plan.argv) |entry| {
        allocator.free(entry);
    }
    allocator.free(plan.argv);
}

fn parseCommandLineTokens(allocator: Allocator, input: []const u8) ![]const []const u8 {
    const trimmed = std.mem.trim(u8, input, " \t\r\n");
    if (trimmed.len == 0) {
        return try allocator.alloc([]const u8, 0);
    }

    var tokens = std.mem.tokenizeAny(u8, trimmed, " \t\r\n");
    var out = std.ArrayListUnmanaged([]const u8){};
    defer out.deinit(allocator);

    while (tokens.next()) |raw_token| {
        const token = try stripTokenQuotes(allocator, raw_token);
        try out.append(allocator, token);
    }

    return out.toOwnedSlice(allocator);
}

fn stripTokenQuotes(allocator: Allocator, token: []const u8) ![]u8 {
    const len = token.len;
    if (len >= 2 and
        ((token[0] == '"' and token[len - 1] == '"') or
            (token[0] == '\'' and token[len - 1] == '\'')))
    {
        return try allocator.dupe(u8, token[1 .. len - 1]);
    }

    return try allocator.dupe(u8, token);
}

fn executeDispatchForTelegram(allocator: Allocator, plan: DispatchPlan, ctx: TelegramDispatchContext) ![]u8 {
    return switch (plan.mode) {
        .shell => executeShellCommand(allocator, ctx.message),
        .argv => executeDispatchCommand(allocator, plan.argv, ctx),
    };
}

fn runTelegramThroughZolt(
    allocator: Allocator,
    root: []const u8,
    zolt_command: []const u8,
    session_key: []const u8,
    message: []const u8,
) ![]u8 {
    const existing_session_id = blk: {
        break :blk loadTelegramZoltSessionId(allocator, root, session_key) catch |err| {
            std.log.warn("volt: failed to load zolt session mapping ({s}): {s}", .{ session_key, @errorName(err) });
            break :blk null;
        };
    };
    defer if (existing_session_id) |mapped_session| allocator.free(mapped_session);

    if (existing_session_id) |mapped_session| {
        const mapped_output = try runZoltCommandForMessage(
            allocator,
            zolt_command,
            mapped_session,
            message,
            false,
        );
        if (!isZoltSessionNotFound(mapped_output)) {
            const mapped_parsed = parseZoltRunJson(allocator, mapped_output) catch null;
            if (mapped_parsed) |parsed| {
                defer deinitZoltRunOutput(allocator, parsed);
                if (parsed.response.len > 0) {
                    allocator.free(mapped_output);
                    if (parsed.session_id.len > 0 and
                        !std.mem.eql(u8, parsed.session_id, mapped_session))
                    {
                        try persistTelegramZoltSessionId(allocator, root, session_key, parsed.session_id);
                    }
                    return try allocator.dupe(u8, parsed.response);
                }
            }
            return mapped_output;
        }
        allocator.free(mapped_output);
        std.log.warn("volt: zolt session not found, recreating {s}", .{session_key});
    }

    const session_output = try runZoltCommandForMessage(allocator, zolt_command, null, message, true);
    defer allocator.free(session_output);
    const parsed = parseZoltRunJson(allocator, session_output) catch |err| {
        std.log.warn("volt: failed to parse zolt json output ({s}): {s}", .{ session_key, @errorName(err) });
        return try allocator.dupe(u8, session_output);
    };
    defer deinitZoltRunOutput(allocator, parsed);

    if (parsed.session_id.len == 0) {
        return error.ZoltSessionIdMissing;
    }

    try persistTelegramZoltSessionId(allocator, root, session_key, parsed.session_id);
    return try allocator.dupe(u8, parsed.response);
}

fn deinitZoltRunOutput(allocator: Allocator, output: ZoltRunOutput) void {
    allocator.free(output.session_id);
    allocator.free(output.response);
}

fn parseZoltRunJson(allocator: Allocator, text: []const u8) !ZoltRunOutput {
    const json_slice = extractJsonObject(text) orelse return error.InvalidArgument;
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        allocator,
        json_slice,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    const root = &parsed.value;
    const session_id = if (resolveJsonStringField(root, &.{"session_id"})) |raw| blk: {
        break :blk try allocator.dupe(u8, raw);
    } else try allocator.dupe(u8, "");

    const response = if (resolveJsonStringField(root, &.{"response"})) |raw| blk: {
        break :blk try allocator.dupe(u8, raw);
    } else try allocator.dupe(u8, "");

    return ZoltRunOutput{
        .session_id = session_id,
        .response = response,
    };
}

fn extractJsonObject(text: []const u8) ?[]const u8 {
    const first = std.mem.indexOfScalar(u8, text, '{') orelse return null;
    var depth: isize = 0;
    var in_string = false;
    var escaped = false;

    for (text[first..], 0..) |byte, i| {
        if (escaped) {
            escaped = false;
            continue;
        }

        if (byte == '\\' and in_string) {
            escaped = true;
            continue;
        }

        if (byte == '"') {
            in_string = !in_string;
        } else if (!in_string) {
            if (byte == '{') {
                depth += 1;
            } else if (byte == '}') {
                if (depth == 0) return null;
                depth -= 1;
                if (depth == 0) {
                    return text[first .. first + i + 1];
                }
            }
        }
    }

    return null;
}

fn isZoltSessionNotFound(output: []const u8) bool {
    return std.mem.indexOf(u8, output, "session not found:") != null or
        std.mem.indexOf(u8, output, "Session not found:") != null or
        std.mem.indexOf(u8, output, "SESSION NOT FOUND:") != null;
}

fn runZoltCommandForMessage(
    allocator: Allocator,
    zolt_command: []const u8,
    session_id: ?[]const u8,
    message: []const u8,
    include_json_output: bool,
) ![]u8 {
    var argv = std.ArrayListUnmanaged([]const u8){};
    defer argv.deinit(allocator);

    try argv.append(allocator, zolt_command);
    try argv.append(allocator, "run");
    if (session_id) |session| {
        try argv.append(allocator, "--session");
        try argv.append(allocator, session);
    }
    if (include_json_output) {
        try argv.append(allocator, "--output");
        try argv.append(allocator, "json");
    }
    try argv.append(allocator, message);

    debugArgv(allocator, "zolt argv", argv.items);
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv.items,
    });
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }
    debugPrint(allocator, "zolt exit: {any}", .{result.term});
    debugPrint(allocator, "zolt stdout({d} bytes): {s}", .{
        result.stdout.len,
        debugSnippet(allocator, result.stdout),
    });
    if (result.stderr.len > 0) {
        debugPrint(allocator, "zolt stderr({d} bytes): {s}", .{
            result.stderr.len,
            debugSnippet(allocator, result.stderr),
        });
    }

    if (include_json_output) {
        switch (result.term) {
            .Exited => |code| {
                if (code != 0 and result.stderr.len > 0) {
                    return try composeChildOutput(
                        allocator,
                        result.stdout,
                        result.stderr,
                        result.term,
                    );
                }
            },
            else => {
                if (result.stderr.len > 0) {
                    return try composeChildOutput(
                        allocator,
                        result.stdout,
                        result.stderr,
                        result.term,
                    );
                }
            },
        }

        return try allocator.dupe(u8, result.stdout);
    }

    switch (result.term) {
        .Exited => |code| {
            if (code != 0) {
                return try composeChildOutput(
                    allocator,
                    result.stdout,
                    result.stderr,
                    result.term,
                );
            }
        },
        else => {
            return try composeChildOutput(
                allocator,
                result.stdout,
                result.stderr,
                result.term,
            );
        },
    }

    return try allocator.dupe(u8, result.stdout);
}

fn executeDispatchCommand(allocator: Allocator, argv: []const []const u8, ctx: TelegramDispatchContext) ![]u8 {
    if (argv.len == 0) {
        return error.InvalidArgument;
    }

    const context_argv = try renderDispatchArgv(allocator, argv, ctx);
    defer {
        for (context_argv) |arg| {
            allocator.free(arg);
        }
        allocator.free(context_argv);
    }

    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = context_argv,
    });
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    return try composeChildOutput(
        allocator,
        result.stdout,
        result.stderr,
        result.term,
    );
}

const DispatchValidationError = error{
    DispatchBinaryNotFound,
    DispatchBinaryNotExecutable,
    DispatchBinaryCheckFailed,
};

fn validateDispatchExecutable(allocator: Allocator, command: []const u8) DispatchValidationError!void {
    var last_error: ?DispatchValidationError = null;

    for (DefaultCommandCheckArgv) |help_arg| {
        const probe_argv = [_][]const u8{ command, help_arg };
        const result = std.process.Child.run(.{
            .allocator = allocator,
            .argv = &probe_argv,
        }) catch |err| {
            last_error = mapDispatchValidationError(err);
            continue;
        };

        defer {
            allocator.free(result.stdout);
            allocator.free(result.stderr);
        }
        return;
    }

    return last_error orelse DispatchValidationError.DispatchBinaryCheckFailed;
}

fn mapDispatchValidationError(err: anyerror) DispatchValidationError {
    return switch (err) {
        error.FileNotFound => DispatchValidationError.DispatchBinaryNotFound,
        error.AccessDenied, error.PermissionDenied, error.InvalidExe => DispatchValidationError.DispatchBinaryNotExecutable,
        else => DispatchValidationError.DispatchBinaryCheckFailed,
    };
}

fn renderDispatchArgv(allocator: Allocator, argv: []const []const u8, ctx: TelegramDispatchContext) ![]const []const u8 {
    var rendered = std.ArrayListUnmanaged([]const u8){};
    defer rendered.deinit(allocator);

    var message_included = false;
    for (argv) |arg| {
        const rendered_arg = try renderDispatchArg(allocator, arg, ctx, &message_included);
        try rendered.append(allocator, rendered_arg);
    }

    if (!message_included) {
        try rendered.append(allocator, try allocator.dupe(u8, ctx.message));
    }

    return rendered.toOwnedSlice(allocator);
}

fn renderDispatchArg(
    allocator: Allocator,
    template: []const u8,
    ctx: TelegramDispatchContext,
    message_included: *bool,
) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    defer out.deinit(allocator);

    var start: usize = 0;
    while (start < template.len) {
        if (template[start] != '{') {
            try out.append(allocator, template[start]);
            start += 1;
            continue;
        }

        const close = std.mem.indexOfScalarPos(u8, template, start + 1, '}') orelse {
            try out.appendSlice(allocator, template[start..]);
            break;
        };
        const token = template[start + 1 .. close];

        if (std.mem.eql(u8, token, "message") or std.mem.eql(u8, token, "text")) {
            try out.appendSlice(allocator, ctx.message);
            message_included.* = true;
        } else if (std.mem.eql(u8, token, "chat_id")) appendChatId: {
            const chat_id_text = try std.fmt.allocPrint(allocator, "{d}", .{ctx.chat_id});
            defer allocator.free(chat_id_text);
            try out.appendSlice(allocator, chat_id_text);
            break :appendChatId;
        } else if (std.mem.eql(u8, token, "account")) {
            try out.appendSlice(allocator, ctx.account);
        } else if (std.mem.eql(u8, token, "session")) {
            try out.appendSlice(allocator, ctx.session_key);
        } else {
            try out.appendSlice(allocator, template[start .. close + 1]);
        }

        start = close + 1;
    }

    if (out.items.len == 0) {
        return try allocator.dupe(u8, template);
    }
    return out.toOwnedSlice(allocator);
}

fn executeShellCommand(allocator: Allocator, command: []const u8) ![]u8 {
    const argv = [_][]const u8{ "sh", "-lc", command };
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &argv,
    });
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    return try composeChildOutput(
        allocator,
        result.stdout,
        result.stderr,
        result.term,
    );
}

fn composeChildOutput(
    allocator: Allocator,
    stdout: []const u8,
    stderr: []const u8,
    term: std.process.Child.Term,
) ![]u8 {
    var footer_text: ?[]const u8 = null;
    var exit_buf: [16]u8 = undefined;
    switch (term) {
        .Exited => |code| {
            if (code != 0) {
                footer_text = std.fmt.bufPrint(&exit_buf, "[exit={d}]", .{code}) catch unreachable;
            }
        },
        .Signal => footer_text = "[signal]\n",
        .Stopped => footer_text = "[stopped]\n",
        .Unknown => footer_text = "[unknown]\n",
    }

    const has_body = stdout.len > 0 or stderr.len > 0;
    var total_len = stdout.len;
    if (stderr.len > 0) {
        if (stdout.len > 0) total_len += 1;
        total_len += "[stderr]\n".len;
        total_len += stderr.len;
    }
    if (footer_text != null) {
        total_len += if (has_body) 1 else 0;
    }
    if (footer_text) |text| {
        total_len += text.len;
    }

    var out = try allocator.alloc(u8, total_len);
    var stream = std.io.fixedBufferStream(out);
    var writer = stream.writer();

    if (stdout.len > 0) {
        try writer.writeAll(stdout);
    }

    if (stderr.len > 0) {
        if (stdout.len > 0) {
            try writer.writeByte('\n');
        }
        try writer.writeAll("[stderr]\n");
        try writer.writeAll(stderr);
    }

    if (footer_text) |text| {
        if (has_body) {
            try writer.writeByte('\n');
        }
        try writer.writeAll(text);
    }

    return out[0..stream.pos];
}

fn fetchUpdates(
    allocator: Allocator,
    client: *std.http.Client,
    token: []const u8,
    offset: i64,
    poll_ms: u64,
) !TelegramUpdatesEnvelope {
    var url_buf: [1536]u8 = undefined;
    const url = try std.fmt.bufPrint(
        &url_buf,
        "https://api.telegram.org/bot{s}/getUpdates?timeout={d}&offset={d}",
        .{ token, @divFloor(clampPollInterval(poll_ms), 1000) + 1, offset },
    );

    var response = std.Io.Writer.Allocating.init(allocator);
    defer response.deinit();

    const request_result = try client.fetch(.{
        .location = .{ .url = url },
        .response_writer = &response.writer,
    });
    if (request_result.status != .ok) {
        return error.TelegramRequestFailed;
    }

    const payload = try response.toOwnedSlice();
    const parsed = try std.json.parseFromSlice(
        TelegramUpdates,
        allocator,
        payload,
        .{ .ignore_unknown_fields = true },
    );

    return TelegramUpdatesEnvelope{
        .payload = payload,
        .parsed = parsed,
    };
}

fn sendTelegramMessage(allocator: Allocator, client: *std.http.Client, token: []const u8, chat_id: i64, text: []const u8) !void {
    var url_buf: [768]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://api.telegram.org/bot{s}/sendMessage", .{token});

    var payload_buf = std.Io.Writer.Allocating.init(allocator);
    defer payload_buf.deinit();
    {
        var stringify = std.json.Stringify{ .writer = &payload_buf.writer, .options = .{} };
        try stringify.write(.{ .chat_id = chat_id, .text = text });
    }
    const payload = try payload_buf.toOwnedSlice();
    defer allocator.free(payload);

    const result = try client.fetch(.{
        .location = .{ .url = url },
        .method = .POST,
        .payload = payload,
        .extra_headers = &[_]std.http.Header{
            .{ .name = "content-type", .value = "application/json" },
        },
    });
    if (result.status != .ok) {
        return error.TelegramRequestFailed;
    }
}

fn hasDuplicate(allocator: Allocator, entries: []const []const u8, candidate: []const u8) bool {
    _ = allocator;
    for (entries) |entry| {
        if (std.mem.eql(u8, entry, candidate)) {
            return true;
        }
    }
    return false;
}

fn normalizeAccountId(allocator: Allocator, raw: ?[]const u8) ![]u8 {
    const trimmed = std.mem.trim(u8, raw orelse "", " \t\r\n");
    if (trimmed.len == 0) {
        return allocator.dupe(u8, DefaultAccountId);
    }

    if (trimmed.len <= 64) {
        var valid = true;
        for (trimmed, 0..) |raw_ch, index| {
            const ch = if (raw_ch >= 'A' and raw_ch <= 'Z') raw_ch + 32 else raw_ch;
            const is_start = index == 0;
            if (is_start and
                !(ch >= 'a' and ch <= 'z') and
                !(ch >= '0' and ch <= '9'))
            {
                valid = false;
                break;
            }
            if (!(ch >= 'a' and ch <= 'z') and !(ch >= '0' and ch <= '9') and ch != '-' and ch != '_') {
                valid = false;
                break;
            }
        }
        if (valid) {
            const direct = try allocator.alloc(u8, trimmed.len);
            for (trimmed, 0..) |raw_ch, index| {
                direct[index] = if (raw_ch >= 'A' and raw_ch <= 'Z') raw_ch + 32 else raw_ch;
            }
            return direct;
        }
    }

    var out = std.ArrayListUnmanaged(u8){};
    defer out.deinit(allocator);
    for (trimmed) |raw_ch| {
        const lower = if (raw_ch >= 'A' and raw_ch <= 'Z') raw_ch + 32 else raw_ch;
        const normalized = if ((lower >= 'a' and lower <= 'z') or
            (lower >= '0' and lower <= '9') or
            lower == '-' or
            lower == '_') lower else '-';
        try out.append(allocator, normalized);
    }
    var start: usize = 0;
    var end: usize = out.items.len;

    while (start < end and out.items[start] == '-') {
        start += 1;
    }
    while (end > start and out.items[end - 1] == '-') {
        end -= 1;
    }

    const sliced = out.items[start..end];
    if (sliced.len == 0) {
        return allocator.dupe(u8, DefaultAccountId);
    }

    const limit = @min(sliced.len, 64);
    return try allocator.dupe(u8, sliced[0..limit]);
}

fn resolveJsonValue(
    root: *const std.json.Value,
    path: []const []const u8,
) ?*const std.json.Value {
    var current = root;
    for (path) |key| {
        if (current.* != .object) {
            return null;
        }
        current = current.object.getPtr(key) orelse return null;
    }
    return current;
}

fn resolveJsonStringField(
    root: *const std.json.Value,
    path: []const []const u8,
) ?[]const u8 {
    const value = resolveJsonValue(root, path) orelse return null;
    if (value.* != .string) {
        return null;
    }
    return value.string;
}

fn readTokenFromPath(allocator: Allocator, raw_path: []const u8) !?[]u8 {
    const token_path = std.mem.trim(u8, raw_path, " \t\r\n");
    if (token_path.len == 0) {
        return null;
    }

    const data = readFileAlloc(allocator, token_path) catch |err| {
        return switch (err) {
            error.FileNotFound => null,
            else => return null,
        };
    };
    defer allocator.free(data);

    const trimmed = std.mem.trim(u8, data, " \t\r\n");
    if (trimmed.len == 0) {
        return null;
    }

    return try allocator.dupe(u8, trimmed);
}

fn resolveTelegramAccountConfig(
    allocator: Allocator,
    root: *const std.json.Value,
    account: []const u8,
) ?*const std.json.Value {
    const accounts_path = [_][]const u8{ "channels", "telegram", "accounts" };
    const accounts_value = resolveJsonValue(root, accounts_path[0..]) orelse return null;
    if (accounts_value.* != .object) {
        return null;
    }

    if (accounts_value.object.getPtr(account)) |direct| {
        return direct;
    }

    var it = accounts_value.object.iterator();
    while (it.next()) |entry| {
        const normalized_key = normalizeAccountId(allocator, entry.key_ptr.*) catch continue;
        defer allocator.free(normalized_key);
        if (std.mem.eql(u8, normalized_key, account)) {
            return entry.value_ptr;
        }
    }

    return null;
}

fn resolveTelegramTokenFromConfig(
    allocator: Allocator,
    data: []const u8,
    account: []const u8,
) ![]u8 {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, data, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    const root = &parsed.value;
    const allow_env = std.mem.eql(u8, account, DefaultAccountId);

    if (resolveTelegramAccountConfig(allocator, root, account)) |account_cfg| {
        if (resolveJsonStringField(account_cfg, &.{"tokenFile"})) |token_file| {
            if (try readTokenFromPath(allocator, token_file)) |token| {
                return token;
            }
            return allocator.dupe(u8, "");
        }

        if (resolveJsonStringField(account_cfg, &.{"botToken"})) |token| {
            const trimmed = std.mem.trim(u8, token, " \t\r\n");
            if (trimmed.len > 0) {
                return try allocator.dupe(u8, trimmed);
            }
        }
    }

    if (allow_env) {
        if (resolveJsonStringField(root, &.{ "channels", "telegram", "tokenFile" })) |token_file| {
            if (try readTokenFromPath(allocator, token_file)) |token| {
                return token;
            }
            return allocator.dupe(u8, "");
        }

        if (resolveJsonStringField(root, &.{ "channels", "telegram", "botToken" })) |token| {
            const trimmed = std.mem.trim(u8, token, " \t\r\n");
            if (trimmed.len > 0) {
                return try allocator.dupe(u8, trimmed);
            }
        }

        const env_token = std.process.getEnvVarOwned(allocator, "TELEGRAM_BOT_TOKEN") catch |err| {
            return switch (err) {
                error.EnvironmentVariableNotFound => allocator.dupe(u8, ""),
                else => return err,
            };
        };
        defer allocator.free(env_token);

        const env_trimmed = std.mem.trim(u8, env_token, " \t\r\n");
        if (env_trimmed.len > 0) {
            return try allocator.dupe(u8, env_trimmed);
        }
    }

    return allocator.dupe(u8, "");
}

fn resolveGatewayAuthToken(
    allocator: Allocator,
    root: []const u8,
    explicit: ?[]const u8,
) ![]u8 {
    if (explicit) |token| {
        return allocator.dupe(u8, token);
    }

    if (std.process.getEnvVarOwned(allocator, "VOLT_GATEWAY_TOKEN")) |env_token| {
        defer allocator.free(env_token);
        const trimmed = std.mem.trim(u8, env_token, " \t\r\n");
        if (trimmed.len > 0) {
            return allocator.dupe(u8, trimmed);
        }
    } else |err| {
        if (err != error.EnvironmentVariableNotFound) return err;
    }

    const path = resolveConfigPath(allocator, root) catch return allocator.dupe(u8, DefaultGatewayToken);
    defer allocator.free(path);

    const data = readFileAlloc(allocator, path) catch |err| {
        if (err == error.FileNotFound) return allocator.dupe(u8, DefaultGatewayToken);
        return err;
    };
    defer allocator.free(data);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, data, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    const token = resolveJsonStringField(&parsed.value, &.{ "gateway", "auth", "token" }) orelse DefaultGatewayToken;
    const trimmed = std.mem.trim(u8, token, " \t\r\n");
    if (trimmed.len == 0) {
        return allocator.dupe(u8, "");
    }

    return allocator.dupe(u8, trimmed);
}

fn resolveTelegramOffsetPath(
    allocator: Allocator,
    root: []const u8,
    account: []const u8,
) ![]u8 {
    if (std.mem.eql(u8, account, DefaultAccountId)) {
        return try joinPath(allocator, root, "telegram/update-offset-default.json");
    }
    return try std.fmt.allocPrint(allocator, "{s}/telegram/update-offset-{s}.json", .{ root, account });
}

fn loadAllowFrom(allocator: Allocator, root: []const u8) !std.json.Parsed(TelegramAllowFrom) {
    const path = try joinPath(allocator, root, "credentials/telegram-allowFrom.json");
    defer allocator.free(path);

    const data = readFileAlloc(allocator, path) catch |err| {
        if (err == error.FileNotFound) {
            return std.json.parseFromSlice(
                TelegramAllowFrom,
                allocator,
                DefaultAllowFromJson,
                .{ .ignore_unknown_fields = true },
            );
        }
        return err;
    };
    defer allocator.free(data);

    return std.json.parseFromSlice(TelegramAllowFrom, allocator, data, .{ .ignore_unknown_fields = true });
}

fn loadOffset(allocator: Allocator, root: []const u8, account: []const u8) !i64 {
    const path = try resolveTelegramOffsetPath(allocator, root, account);
    defer allocator.free(path);

    const data = readFileAlloc(allocator, path) catch |err| {
        if (err == error.FileNotFound) {
            return 0;
        }
        return err;
    };
    defer allocator.free(data);

    const parsed = try std.json.parseFromSlice(TelegramOffset, allocator, data, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    return parsed.value.lastUpdateId;
}

fn resolveTelegramZoltSessionPath(allocator: Allocator, root: []const u8) ![]u8 {
    return joinPath(allocator, root, "credentials/telegram-zolt-sessions.json");
}

fn loadTelegramZoltSessionId(
    allocator: Allocator,
    root: []const u8,
    key: []const u8,
) !?[]u8 {
    const path = try resolveTelegramZoltSessionPath(allocator, root);
    defer allocator.free(path);

    const data = readFileAlloc(allocator, path) catch |err| {
        if (err == error.FileNotFound) return null;
        return err;
    };
    defer allocator.free(data);

    const parsed = try std.json.parseFromSlice(
        TelegramZoltSessionMap,
        allocator,
        data,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    for (parsed.value.sessions) |entry| {
        if (std.mem.eql(u8, entry.key, key)) {
            return try allocator.dupe(u8, entry.session);
        }
    }
    return null;
}

fn clearTelegramZoltSessionId(
    allocator: Allocator,
    root: []const u8,
    key: []const u8,
) !bool {
    const path = try resolveTelegramZoltSessionPath(allocator, root);
    defer allocator.free(path);

    const data = readFileAlloc(allocator, path) catch |err| {
        if (err == error.FileNotFound) return false;
        return err;
    };
    defer allocator.free(data);

    const parsed = try std.json.parseFromSlice(
        TelegramZoltSessionMap,
        allocator,
        data,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    var sessions = std.ArrayListUnmanaged(TelegramZoltSessionMapEntry){};
    defer sessions.deinit(allocator);

    var removed = false;
    for (parsed.value.sessions) |entry| {
        if (std.mem.eql(u8, entry.key, key)) {
            removed = true;
            continue;
        }
        try sessions.append(allocator, entry);
    }

    if (!removed) return false;

    const merged = TelegramZoltSessionMap{
        .version = 1,
        .sessions = sessions.items,
    };

    var out = std.Io.Writer.Allocating.init(allocator);
    defer out.deinit();

    var writer = std.json.Stringify{
        .writer = &out.writer,
        .options = .{},
    };
    try writer.write(merged);

    const payload = try out.toOwnedSlice();
    defer allocator.free(payload);
    try writeTextFile(path, payload, true);
    return true;
}

fn persistTelegramZoltSessionId(
    allocator: Allocator,
    root: []const u8,
    key: []const u8,
    session_id: []const u8,
) !void {
    const path = try resolveTelegramZoltSessionPath(allocator, root);
    defer allocator.free(path);

    const path_exists = pathExists(path);
    const data = blk: {
        if (!path_exists) break :blk DefaultTelegramZoltSessionsJson;
        break :blk readFileAlloc(allocator, path) catch |err| switch (err) {
            error.FileNotFound => DefaultTelegramZoltSessionsJson,
            else => return err,
        };
    };
    defer if (path_exists) allocator.free(data);

    const parsed = try std.json.parseFromSlice(
        TelegramZoltSessionMap,
        allocator,
        data,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    var sessions = std.ArrayListUnmanaged(TelegramZoltSessionMapEntry){};
    defer sessions.deinit(allocator);

    var found = false;
    for (parsed.value.sessions) |entry| {
        if (std.mem.eql(u8, entry.key, key)) {
            if (!std.mem.eql(u8, entry.session, session_id)) {
                try sessions.append(allocator, .{
                    .key = key,
                    .session = session_id,
                });
            } else {
                try sessions.append(allocator, entry);
            }
            found = true;
            continue;
        }
        try sessions.append(allocator, entry);
    }

    if (!found) {
        try sessions.append(allocator, .{ .key = key, .session = session_id });
    }

    const merged = TelegramZoltSessionMap{
        .version = 1,
        .sessions = sessions.items,
    };

    var out = std.Io.Writer.Allocating.init(allocator);
    defer out.deinit();

    var writer = std.json.Stringify{
        .writer = &out.writer,
        .options = .{},
    };
    try writer.write(merged);

    const payload = try out.toOwnedSlice();
    defer allocator.free(payload);
    try writeTextFile(path, payload, true);
}

fn persistOffset(allocator: Allocator, root: []const u8, account: []const u8, offset: i64) !void {
    const path = try resolveTelegramOffsetPath(allocator, root, account);
    defer allocator.free(path);

    const text = try std.fmt.allocPrint(allocator, "{{\"version\":1,\"lastUpdateId\":{d}}}", .{offset});
    defer allocator.free(text);

    try writeTextFile(path, text, true);
}

fn chatAllowed(allow: []const []const u8, chat_id: i64) bool {
    if (allow.len == 0) return true;

    var buffer: [32]u8 = undefined;
    const chat_text = std.fmt.bufPrint(&buffer, "{d}", .{chat_id}) catch return false;

    for (allow) |candidate| {
        if (std.mem.eql(u8, candidate, chat_text)) return true;
    }
    return false;
}

fn clampPollInterval(ms: u64) u64 {
    if (ms < 250) return 250;
    return ms;
}

fn trimLine(value: []const u8) []const u8 {
    return std.mem.trim(u8, value, "\r\n");
}

test "normalizeAccountId matches volt constraints" {
    const allocator = testing.allocator;

    const normalized = try normalizeAccountId(allocator, " Work Account ");
    defer allocator.free(normalized);
    try testing.expect(std.mem.eql(u8, normalized, "work-account"));

    const unchanged = try normalizeAccountId(allocator, "work_account");
    defer allocator.free(unchanged);
    try testing.expect(std.mem.eql(u8, unchanged, "work_account"));
}

test "resolveTelegramTokenFromConfig supports tokenFile, botToken, and normalized account keys" {
    const allocator = testing.allocator;

    const token_file = "/tmp/volt-token-test.txt";
    const token_file_handle = try std.fs.createFileAbsolute(token_file, .{ .truncate = true });
    defer {
        token_file_handle.close();
        std.fs.deleteFileAbsolute(token_file) catch {};
    }
    try token_file_handle.writeAll("from-file\n");

    const account_token_file = "/tmp/volt-account-token-test.txt";
    const account_token_file_handle = try std.fs.createFileAbsolute(account_token_file, .{ .truncate = true });
    defer {
        account_token_file_handle.close();
        std.fs.deleteFileAbsolute(account_token_file) catch {};
    }
    try account_token_file_handle.writeAll("account-file-token\n");

    var config_out = std.ArrayListUnmanaged(u8){};
    defer config_out.deinit(allocator);
    try config_out.appendSlice(allocator, "{\"channels\":{\"telegram\":{\"tokenFile\":\"");
    try config_out.appendSlice(allocator, token_file);
    try config_out.appendSlice(allocator, "\",\"accounts\":{\"Work Account\":{\"tokenFile\":\"");
    try config_out.appendSlice(allocator, account_token_file);
    try config_out.appendSlice(allocator, "\"}}}}}");
    const config = try config_out.toOwnedSlice(allocator);
    defer allocator.free(config);

    const account = try normalizeAccountId(allocator, " work.account ");
    defer allocator.free(account);

    const account_token = try resolveTelegramTokenFromConfig(allocator, config, account);
    defer allocator.free(account_token);
    try testing.expect(std.mem.eql(u8, account_token, "account-file-token"));

    const default_token = try resolveTelegramTokenFromConfig(
        allocator,
        config,
        DefaultAccountId,
    );
    defer allocator.free(default_token);
    try testing.expect(std.mem.eql(u8, default_token, "from-file"));
}

test "parseGatewayOptions parses all supported args" {
    const opts = try parseGatewayOptions(&.{
        "--home",
        "/tmp/volt",
        "--bind",
        "127.0.0.2",
        "--port",
        "19999",
        "--account",
        "Work Team",
        "--dispatch",
        "zolt --message {message}",
        "--auth-token",
        "token123",
    });

    try testing.expect(opts.home_path != null);
    try testing.expectEqualStrings("/tmp/volt", opts.home_path.?);
    try testing.expectEqualStrings("127.0.0.2", opts.bind);
    try testing.expectEqual(@as(u16, 19999), opts.port);
    try testing.expectEqualStrings("Work Team", opts.account.?);
    try testing.expectEqualStrings("zolt --message {message}", opts.dispatch.?);
    try testing.expect(!opts.zolt);
    try testing.expect(opts.zolt_command == null);
    try testing.expectEqualStrings("token123", opts.auth_token.?);
}

test "parseGatewayOptions supports --zolt and enforces exclusivity" {
    const opts = try parseGatewayOptions(&.{ "--zolt", "--zolt-path", "/usr/local/bin/zolt" });
    try testing.expect(opts.zolt);
    try testing.expect(opts.dispatch == null);
    try testing.expectEqualStrings("/usr/local/bin/zolt", opts.zolt_command.?);

    try testing.expectError(
        error.UnexpectedArgument,
        parseGatewayOptions(&.{ "--zolt", "--dispatch", "zolt --message {message}" }),
    );
    try testing.expectError(
        error.UnexpectedArgument,
        parseGatewayOptions(&.{ "--zolt-path", "/usr/local/bin/zolt" }),
    );
}

test "parseGatewayServiceAction maps command strings" {
    try testing.expectEqual(GatewayServiceAction.run, parseGatewayServiceAction("gateway"));
    try testing.expectEqual(GatewayServiceAction.install, parseGatewayServiceAction("install"));
    try testing.expectEqual(GatewayServiceAction.uninstall, parseGatewayServiceAction("uninstall"));
    try testing.expectEqual(GatewayServiceAction.start, parseGatewayServiceAction("start"));
    try testing.expectEqual(GatewayServiceAction.stop, parseGatewayServiceAction("stop"));
    try testing.expectEqual(GatewayServiceAction.restart, parseGatewayServiceAction("restart"));
    try testing.expectEqual(GatewayServiceAction.status, parseGatewayServiceAction("status"));
}

test "buildGatewaySystemdUnit builds launch command and service header" {
    const allocator = testing.allocator;
    const opts = try parseGatewayOptions(&.{
        "--home",
        "/tmp/volt",
        "--bind",
        "127.0.0.1",
        "--port",
        "18889",
        "--account",
        "team",
        "--auth-token",
        "token-123",
    });

    const unit = try buildGatewaySystemdUnit(allocator, "/usr/local/bin/volt", opts);
    defer allocator.free(unit);

    try testing.expect(std.mem.indexOf(u8, unit, "[Unit]") != null);
    try testing.expect(std.mem.indexOf(u8, unit, "[Service]") != null);
    try testing.expect(std.mem.indexOf(u8, unit, "Type=simple") != null);
    try testing.expect(std.mem.indexOf(u8, unit, "Restart=always") != null);
    try testing.expect(std.mem.indexOf(u8, unit, "WantedBy=default.target") != null);
    try testing.expect(std.mem.indexOf(u8, unit, "ExecStart=") != null);
    try testing.expect(std.mem.indexOf(u8, unit, "'--home'") != null);
    try testing.expect(std.mem.indexOf(u8, unit, "'/usr/local/bin/volt' gateway") != null);
    try testing.expect(std.mem.indexOf(u8, unit, "'--bind' '127.0.0.1'") != null);
    try testing.expect(std.mem.indexOf(u8, unit, "'--port' '18889'") != null);
    try testing.expect(std.mem.indexOf(u8, unit, "WorkingDirectory=") == null);
}

test "buildGatewayLaunchdPlist includes configured arguments" {
    const allocator = testing.allocator;
    const opts = try parseGatewayOptions(&.{
        "--home",
        "/tmp/volt",
        "--bind",
        "localhost",
        "--port",
        "18889",
        "--zolt",
    });

    const plist = try buildGatewayLaunchdPlist(allocator, "/usr/local/bin/volt", opts);
    defer allocator.free(plist);

    try testing.expect(std.mem.indexOf(u8, plist, "<key>Label</key>") != null);
    try testing.expect(std.mem.indexOf(u8, plist, "<string>com.volt.gateway</string>") != null);
    try testing.expect(std.mem.indexOf(u8, plist, "<key>ProgramArguments</key>") != null);
    try testing.expect(std.mem.indexOf(u8, plist, "<string>gateway</string>") != null);
    try testing.expect(std.mem.indexOf(u8, plist, "<string>--home</string>") != null);
    try testing.expect(std.mem.indexOf(u8, plist, "<string>/tmp/volt</string>") != null);
    try testing.expect(std.mem.indexOf(u8, plist, "<string>--zolt</string>") != null);
}

test "parseGatewayRoute recognizes supported paths" {
    try testing.expect(parseGatewayRoute("/health") == .health);
    try testing.expect(parseGatewayRoute("/gateway/health") == .health);
    try testing.expect(parseGatewayRoute("/gateway/status") == .status);
    try testing.expect(parseGatewayRoute("/invoke") == .invoke);
    try testing.expect(parseGatewayRoute("/unknown") == .unknown);
}

test "parseGatewayInvokePayload parses message/chat_id fields" {
    const allocator = testing.allocator;
    const payload = try parseGatewayInvokePayload(
        allocator,
        "{\"message\":\"hello\",\"chat_id\":123,\"account\":\"work\",\"session\":\"abc\"}",
    );
    defer payload.deinit();

    try testing.expect(payload.value.message != null);
    try testing.expectEqualStrings("hello", payload.value.message.?);
    try testing.expectEqual(@as(i64, 123), payload.value.chat_id.?);
    try testing.expectEqualStrings("work", payload.value.account.?);
    try testing.expectEqualStrings("abc", payload.value.session.?);
    try testing.expect(payload.value.text == null);
}

test "parseGatewayInvokePayload rejects invalid json" {
    const allocator = testing.allocator;
    try testing.expectError(
        error.GatewayBadRequest,
        parseGatewayInvokePayload(allocator, "{not json}"),
    );
}

test "parseDispatchPlan keeps shell behavior for missing dispatch" {
    const allocator = testing.allocator;

    const plan = try parseDispatchPlan(allocator, null);
    defer deinitDispatchPlan(allocator, plan);

    try testing.expect(plan.mode == .shell);
    try testing.expect(plan.argv.len == 0);
}

test "parseTelegramRunOptions supports --zolt flag" {
    const opts = try parseTelegramRunOptions(&.{"--zolt"});
    try testing.expect(opts.zolt);
    try testing.expect(opts.dispatch == null);
    try testing.expect(opts.zolt_command == null);
    try testing.expect(opts.poll_ms == 2500);
    try testing.expect(opts.account == null);
}

test "parseTelegramRunOptions supports --zolt-path" {
    const opts = try parseTelegramRunOptions(&.{ "--zolt", "--zolt-path", "/usr/local/bin/zolt" });
    try testing.expect(opts.zolt);
    try testing.expect(opts.zolt_command != null);
    try testing.expectEqualStrings("/usr/local/bin/zolt", opts.zolt_command.?);
}

test "parseTelegramRunOptions rejects --zolt combined with --dispatch" {
    try testing.expectError(
        error.UnexpectedArgument,
        parseTelegramRunOptions(&.{ "--zolt", "--dispatch", "zolt --message {message}" }),
    );
}

test "parseTelegramRunOptions sets default dispatch command when --zolt enabled" {
    const allocator = testing.allocator;
    const opts = try parseTelegramRunOptions(&.{"--zolt"});

    const dispatch = try parseDispatchPlan(allocator, if (opts.zolt) DefaultZoltDispatch else opts.dispatch);
    defer deinitDispatchPlan(allocator, dispatch);

    try testing.expect(dispatch.mode == .argv);
    try testing.expect(dispatch.argv.len == 5);
    try testing.expectEqualStrings("zolt", dispatch.argv[0]);
    try testing.expectEqualStrings("run", dispatch.argv[1]);
    try testing.expectEqualStrings("--session", dispatch.argv[2]);
    try testing.expectEqualStrings("{session}", dispatch.argv[3]);
    try testing.expectEqualStrings("{message}", dispatch.argv[4]);
}

test "dispatch rendering replaces session placeholders" {
    const allocator = testing.allocator;

    const plan = try parseDispatchPlan(allocator, "zolt --session {session} --reply-to {chat_id} --account {account} {message}");
    defer deinitDispatchPlan(allocator, plan);

    const ctx = TelegramDispatchContext{
        .message = "status update",
        .account = "work",
        .chat_id = 123456,
        .session_key = "telegram:work:123456",
    };

    const rendered = try renderDispatchArgv(allocator, plan.argv, ctx);
    defer {
        for (rendered) |entry| allocator.free(entry);
        allocator.free(rendered);
    }

    try testing.expectEqualStrings("zolt", rendered[0]);
    try testing.expectEqualStrings("--session", rendered[1]);
    try testing.expectEqualStrings("telegram:work:123456", rendered[2]);
    try testing.expectEqualStrings("--reply-to", rendered[3]);
    try testing.expectEqualStrings("123456", rendered[4]);
    try testing.expectEqualStrings("--account", rendered[5]);
    try testing.expectEqualStrings("work", rendered[6]);
    try testing.expectEqualStrings("status update", rendered[7]);
}

test "composeChildOutput combines stdout and stderr with suffix markers" {
    const allocator = testing.allocator;

    const plain = try composeChildOutput(allocator, "answer", "", .{ .Exited = 0 });
    defer allocator.free(plain);
    try testing.expectEqualStrings("answer", plain);

    const stderr_only = try composeChildOutput(allocator, "", "warn\n", .{ .Exited = 0 });
    defer allocator.free(stderr_only);
    try testing.expectEqualStrings("[stderr]\nwarn\n", stderr_only);

    const both = try composeChildOutput(allocator, "answer", "warn\n", .{ .Exited = 0 });
    defer allocator.free(both);
    try testing.expectEqualStrings("answer\n[stderr]\nwarn\n", both);

    const with_exit = try composeChildOutput(allocator, "answer", "warn\n", .{ .Exited = 2 });
    defer allocator.free(with_exit);
    try testing.expectEqualStrings("answer\n[stderr]\nwarn\n\n[exit=2]", with_exit);
}

test "parseInitOptions parses mirror-volt and source/home paths" {
    const opts = try parseInitOptions(&.{ "--mirror-volt", "--force", "--home", "/tmp/volt-home", "--source", "/tmp/volt-source" });
    try testing.expect(opts.mirror_volt);
    try testing.expect(opts.force);
    try testing.expectEqualStrings("/tmp/volt-home", opts.home_path.?);
    try testing.expectEqualStrings("/tmp/volt-source", opts.source_path.?);
}

test "parseInitOptions rejects unknown argument" {
    try testing.expectError(error.UnknownArgument, parseInitOptions(&.{"--foo"}));
}

test "parseTelegramSetupOptions deduplicates allow-from entries" {
    const allocator = testing.allocator;
    var opts = try parseTelegramSetupOptions(allocator, &.{ "--allow-from", "111", "--allow-from", "222", "--allow-from", "111", "--allow-from", " 333 " });
    defer opts.allow_from.deinit(allocator);

    try testing.expectEqual(@as(usize, 3), opts.allow_from.items.len);
    try testing.expectEqualStrings("111", opts.allow_from.items[0]);
    try testing.expectEqualStrings("222", opts.allow_from.items[1]);
    try testing.expectEqualStrings("333", opts.allow_from.items[2]);
}

test "parseTelegramRunOptions rejects --zolt-path without --zolt" {
    try testing.expectError(
        error.UnexpectedArgument,
        parseTelegramRunOptions(&.{ "--zolt-path", "/usr/local/bin/zolt" }),
    );
}

test "resolveExpandedPath handles home expansion and whitespace" {
    const allocator = testing.allocator;

    const trimmed = try resolveExpandedPath(allocator, "   ./relative/path   ", "/fallback");
    defer allocator.free(trimmed);
    try testing.expectEqualStrings("./relative/path", trimmed);

    const tilde = try resolveExpandedPath(allocator, "   ~/foo/bar", "/fallback");
    defer allocator.free(tilde);
    try testing.expectEqualStrings("/fallback/foo/bar", tilde);

    const bare_tilde = try resolveExpandedPath(allocator, "   ~ ", "/fallback");
    defer allocator.free(bare_tilde);
    try testing.expectEqualStrings("/fallback", bare_tilde);

    const empty = try resolveExpandedPath(allocator, "   ", "/fallback");
    defer allocator.free(empty);
    try testing.expectEqualStrings(".", empty);
}

test "parseCommandLineTokens strips single and double quoted tokens" {
    const allocator = testing.allocator;
    const tokens = try parseCommandLineTokens(allocator, "echo 'hello' \"world\"");
    defer {
        for (tokens) |token| allocator.free(token);
        allocator.free(tokens);
    }

    try testing.expectEqual(@as(usize, 3), tokens.len);
    try testing.expectEqualStrings("echo", tokens[0]);
    try testing.expectEqualStrings("hello", tokens[1]);
    try testing.expectEqualStrings("world", tokens[2]);
}

test "extractTelegramSlashCommand parses slash commands" {
    const command = extractTelegramSlashCommand("/help");
    try testing.expect(command != null);
    try testing.expectEqualStrings("help", command.?.command);
    try testing.expectEqualStrings("", command.?.args);

    const with_args = extractTelegramSlashCommand("/sessions@VoltBot 11111");
    try testing.expect(with_args != null);
    try testing.expectEqualStrings("sessions", with_args.?.command);
    try testing.expectEqualStrings("11111", with_args.?.args);

    try testing.expect(extractTelegramSlashCommand("not slash") == null);
}

test "executeTelegramSlashCommand can render status and clear sessions" {
    const allocator = testing.allocator;
    const root = try std.fmt.allocPrint(allocator, "/tmp/volt-slash-command-test-{d}", .{std.time.milliTimestamp()});
    defer allocator.free(root);

    try std.fs.makeDirAbsolute(root);
    defer std.fs.deleteTreeAbsolute(root) catch {};

    const session_key = "telegram:default:111";
    const response_sessions = try executeTelegramSlashCommand(
        allocator,
        .{ .command = "sessions", .args = "" },
        root,
        session_key,
        "default",
        111,
        null,
    );
    defer allocator.free(response_sessions);
    try testing.expect(std.mem.eql(u8, response_sessions, "chat 111 has no active zolt session"));

    try persistTelegramZoltSessionId(allocator, root, session_key, "z123");
    const response_after_set = try executeTelegramSlashCommand(
        allocator,
        .{ .command = "sessions", .args = "" },
        root,
        session_key,
        "default",
        111,
        null,
    );
    defer allocator.free(response_after_set);
    try testing.expect(std.mem.eql(u8, response_after_set, "chat 111 session: z123"));

    const reset_result = try executeTelegramSlashCommand(
        allocator,
        .{ .command = "reset", .args = "" },
        root,
        session_key,
        "default",
        111,
        null,
    );
    defer allocator.free(reset_result);
    try testing.expect(std.mem.eql(u8, reset_result, "zolt session reset for this chat"));

    const response_sessions_after_reset = try executeTelegramSlashCommand(
        allocator,
        .{ .command = "sessions", .args = "" },
        root,
        session_key,
        "default",
        111,
        null,
    );
    defer allocator.free(response_sessions_after_reset);
    try testing.expect(std.mem.eql(u8, response_sessions_after_reset, "chat 111 has no active zolt session"));
}

test "clearTelegramZoltSessionId updates persisted sessions" {
    const allocator = testing.allocator;
    const root = try std.fmt.allocPrint(allocator, "/tmp/volt-clear-session-test-{d}", .{std.time.milliTimestamp()});
    defer allocator.free(root);

    try std.fs.makeDirAbsolute(root);
    defer std.fs.deleteTreeAbsolute(root) catch {};

    try persistTelegramZoltSessionId(allocator, root, "telegram:default:1", "s1");
    try persistTelegramZoltSessionId(allocator, root, "telegram:default:2", "s2");

    const first = try clearTelegramZoltSessionId(allocator, root, "telegram:default:1");
    try testing.expect(first);

    const remaining = try loadTelegramZoltSessionId(allocator, root, "telegram:default:1");
    defer if (remaining) |session| allocator.free(session);
    try testing.expect(remaining == null);

    const second = try clearTelegramZoltSessionId(allocator, root, "missing");
    try testing.expect(!second);
}

test "chatAllowed supports default open and allowlist matching" {
    const allow_empty = [_][]const u8{};
    try testing.expect(chatAllowed(allow_empty[0..], 123));

    const allow = [_][]const u8{ "123", "456" };
    try testing.expect(chatAllowed(allow[0..], 123));
    try testing.expect(!chatAllowed(allow[0..], 789));
}

test "clampPollInterval enforces minimum" {
    try testing.expectEqual(@as(u64, 250), clampPollInterval(1));
    try testing.expectEqual(@as(u64, 250), clampPollInterval(250));
    try testing.expectEqual(@as(u64, 1000), clampPollInterval(1000));
}

test "resolveTelegramOffsetPath uses account-specific naming" {
    const allocator = testing.allocator;

    const default_path = try resolveTelegramOffsetPath(allocator, "/workspace", DefaultAccountId);
    defer allocator.free(default_path);
    try testing.expectEqualStrings("/workspace/telegram/update-offset-default.json", default_path);

    const account_path = try resolveTelegramOffsetPath(allocator, "/workspace", "work");
    defer allocator.free(account_path);
    try testing.expectEqualStrings("/workspace/telegram/update-offset-work.json", account_path);
}

test "parseZoltRunJson reads session_id and response" {
    const allocator = testing.allocator;
    const payload = "{\"session_id\":\"sess_123\",\"response\":\"hello\"}";

    const parsed = try parseZoltRunJson(allocator, payload);
    defer deinitZoltRunOutput(allocator, parsed);

    try testing.expectEqualStrings("sess_123", parsed.session_id);
    try testing.expectEqualStrings("hello", parsed.response);
}

test "parseZoltRunJson handles missing fields" {
    const allocator = testing.allocator;

    const parsed = try parseZoltRunJson(allocator, "{}");
    defer deinitZoltRunOutput(allocator, parsed);

    try testing.expectEqualStrings("", parsed.session_id);
    try testing.expectEqualStrings("", parsed.response);
}

test "parseZoltRunJson ignores stderr noise around json payload" {
    const allocator = testing.allocator;
    const payload =
        "{" ++
        "\"provider\":\"openai\"," ++
        "\"session_id\":\"abc\"," ++
        "\"response\":\"ok\"}" ++
        "\n[stderr]\ninfo: loaded 91 providers from models cache (cached)";
    const parsed = try parseZoltRunJson(allocator, payload);
    defer deinitZoltRunOutput(allocator, parsed);

    try testing.expectEqualStrings("abc", parsed.session_id);
    try testing.expectEqualStrings("ok", parsed.response);
}

test "isZoltSessionNotFound detects session error output" {
    try testing.expect(isZoltSessionNotFound("session not found: telegram:default:1"));
    try testing.expect(!isZoltSessionNotFound("all good"));
}

test "telegram zolt session map persists across loads" {
    const allocator = testing.allocator;
    const root = try std.fmt.allocPrint(allocator, "/tmp/volt-zolt-map-test-{d}", .{std.time.milliTimestamp()});
    defer allocator.free(root);

    try std.fs.makeDirAbsolute(root);
    defer std.fs.deleteTreeAbsolute(root) catch {};

    const key = "telegram:default:777";
    try persistTelegramZoltSessionId(allocator, root, key, "session_1");

    const loaded_first = try loadTelegramZoltSessionId(allocator, root, key);
    defer if (loaded_first) |value| allocator.free(value);
    try testing.expectEqualStrings("session_1", loaded_first.?);

    try persistTelegramZoltSessionId(allocator, root, key, "session_2");
    const loaded_second = try loadTelegramZoltSessionId(allocator, root, key);
    defer if (loaded_second) |value| allocator.free(value);
    try testing.expectEqualStrings("session_2", loaded_second.?);

    const unknown = try loadTelegramZoltSessionId(allocator, root, "missing");
    try testing.expect(unknown == null);
}

test "runTelegramThroughZolt bootstraps and reuses zolt sessions" {
    const allocator = testing.allocator;
    const root = try std.fmt.allocPrint(allocator, "/tmp/volt-zolt-run-test-{d}", .{std.time.milliTimestamp()});
    defer allocator.free(root);

    try std.fs.makeDirAbsolute(root);
    defer std.fs.deleteTreeAbsolute(root) catch {};

    const zolt_command = try joinPath(allocator, root, "zolt");
    defer allocator.free(zolt_command);

    var script = try std.fs.createFileAbsolute(zolt_command, .{
        .truncate = true,
        .mode = 0o755,
    });
    const script_body =
        \\#!/bin/sh
        \\
        \\if [ "$1" != "run" ]; then
        \\  echo "invalid" >&2
        \\  exit 2
        \\fi
        \\shift
        \\
        \\session=""
        \\if [ "$1" = "--session" ]; then
        \\  session="$2"
        \\  shift 2
        \\fi
        \\
        \\output_json=0
        \\if [ "$1" = "--output" ] && [ "$2" = "json" ]; then
        \\  output_json=1
        \\  shift 2
        \\fi
        \\
        \\message="$1"
        \\
        \\if [ "$output_json" -eq 1 ]; then
        \\  if [ -z "$session" ]; then
        \\    session="session_$message"
        \\  fi
        \\  printf '{"session_id":"%s","response":"reply:%s"}' "$session" "$message"
        \\  exit 0
        \\fi
        \\
        \\if [ "$session" = "stale" ]; then
        \\  echo "session not found: $session" >&2
        \\  exit 2
        \\fi
        \\printf "ok:$session:$message"
    ;
    try script.writeAll(script_body);
    script.close();

    const session_key = "telegram:default:1111";
    const response_one = try runTelegramThroughZolt(allocator, root, zolt_command, session_key, "hello");
    defer allocator.free(response_one);
    try testing.expectEqualStrings("reply:hello", response_one);

    const session_one = try loadTelegramZoltSessionId(allocator, root, session_key);
    defer if (session_one) |session| allocator.free(session);
    try testing.expectEqualStrings("session_hello", session_one.?);

    const response_two = try runTelegramThroughZolt(allocator, root, zolt_command, session_key, "again");
    defer allocator.free(response_two);
    try testing.expectEqualStrings("ok:session_hello:again", response_two);

    try persistTelegramZoltSessionId(allocator, root, session_key, "stale");
    const response_three = try runTelegramThroughZolt(allocator, root, zolt_command, session_key, "fixed");
    defer allocator.free(response_three);
    try testing.expectEqualStrings("reply:fixed", response_three);

    const session_three = try loadTelegramZoltSessionId(allocator, root, session_key);
    defer if (session_three) |session| allocator.free(session);
    try testing.expectEqualStrings("session_fixed", session_three.?);
}
