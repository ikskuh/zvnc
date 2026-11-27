const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });

    const vnc_mod = b.addModule("vnc", .{
        .root_source_file = b.path("src/vnc.zig"),
    });

    const client_mod = b.createModule(.{
        .root_source_file = b.path("src/client-main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "vnc", .module = vnc_mod },
        },
    });

    const client_exe = b.addExecutable(.{
        .name = "zvnc-client",
        .root_module = client_mod,
    });
    b.installArtifact(client_exe);

    const server_mod = b.createModule(.{
        .root_source_file = b.path("src/server-main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "vnc", .module = vnc_mod },
        },
    });

    const server_exe = b.addExecutable(.{
        .name = "zvnc-server",
        .root_module = server_mod,
    });
    b.installArtifact(server_exe);

    const run_client_cmd = b.addRunArtifact(client_exe);
    run_client_cmd.addPassthruArgs();

    const run_server_cmd = b.addRunArtifact(server_exe);

    const run_server_step = b.step("run-server", "Run the app");
    run_server_step.dependOn(&run_server_cmd.step);

    const run_client_step = b.step("run-client", "Run the app");
    run_client_step.dependOn(&run_client_cmd.step);

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/vnc.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe_tests = b.addTest(.{
        .root_module = exe_mod,
    });

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(exe_tests).step);
}
