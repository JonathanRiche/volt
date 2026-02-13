const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "volt",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    b.installArtifact(exe);
    maybeAddBundledZolt(b, target, optimize);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the application");
    run_step.dependOn(&run_cmd.step);

    const test_step = b.step("test", "Run unit tests");
    const exe_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    test_step.dependOn(&b.addRunArtifact(exe_tests).step);

    const fmt_check = b.addFmt(.{ .paths = &.{ "src", "build.zig", "build.zig.zon" } });
    test_step.dependOn(&fmt_check.step);
}

fn maybeAddBundledZolt(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    const with_zolt = b.option(bool, "with-zolt", "Bundle a local zolt binary with volt installs") orelse true;
    if (!with_zolt) return;

    const explicit_source = b.option(
        []const u8,
        "zolt-source",
        "Local zolt source path (defaults to ../zig-ai if it exists)",
    );
    const source_path = resolveZoltSourcePath(explicit_source);
    if (source_path == null) return;

    const source_main = std.fmt.allocPrint(
        b.allocator,
        "{s}/src/main.zig",
        .{source_path.?},
    ) catch {
        return;
    };
    const source_exists = pathExists(source_main);
    if (!source_exists) {
        return;
    }

    const zolt_module = b.createModule(.{
        .root_source_file = b.path(source_main),
        .target = target,
        .optimize = optimize,
    });
    const zolt = b.addExecutable(.{
        .name = "zolt",
        .root_module = zolt_module,
    });
    b.installArtifact(zolt);
}

fn resolveZoltSourcePath(explicit_source: ?[]const u8) ?[]const u8 {
    if (explicit_source) |path| {
        if (std.fs.path.isAbsolute(path)) {
            std.debug.print(
                "volt: ignoring absolute zolt source path '{s}'; expected a path relative to the build root.\n",
                .{path},
            );
            return null;
        }
        if (path.len > 0) {
            return path;
        }
        return null;
    }
    if (pathExists("../zig-ai/src/main.zig")) {
        return "../zig-ai";
    }
    return null;
}

fn pathExists(path: []const u8) bool {
    std.fs.cwd().access(path, .{}) catch return false;
    return true;
}
