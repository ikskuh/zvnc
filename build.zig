const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });

    const network_dep = b.dependency("network", .{});
    const network_mod = network_dep.module("network");

    const client_exe = b.addExecutable(.{
        .name = "zvnc-client",
        .root_source_file = .{ .path = "src/client-main.zig" },
        .target = target,
        .optimize = optimize,
    });
    client_exe.addModule("network", network_mod);
    b.installArtifact(client_exe);

    const server_exe = b.addExecutable(.{
        .name = "zvnc-server",
        .root_source_file = .{ .path = "src/server-main.zig" },
        .target = target,
        .optimize = optimize,
    });
    server_exe.addModule("network", network_mod);
    b.installArtifact(server_exe);

    const run_client_cmd = b.addRunArtifact(client_exe);
    if (b.args) |args| {
        run_client_cmd.addArgs(args);
    }

    const run_server_cmd = b.addRunArtifact(server_exe);

    const run_server_step = b.step("run-server", "Run the app");
    run_server_step.dependOn(&run_server_cmd.step);

    const run_client_step = b.step("run-client", "Run the app");
    run_client_step.dependOn(&run_client_cmd.step);

    const exe_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/vnc.zig" },
        .target = target,
        .optimize = optimize,
    });

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(exe_tests).step);
}
