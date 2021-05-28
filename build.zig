const std = @import("std");

pub fn build(b: *std.build.Builder) !void {
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});

    var lib_tests = b.addTest("src/main.zig");
    lib_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&lib_tests.step);

    const znk_version = "0.2.1";

    var znk_tests = b.addTest("tool/znk.zig");
    znk_tests.setBuildMode(mode);
    znk_tests.addPackagePath("nkeys", "src/main.zig");
    znk_tests.addBuildOption([]const u8, "version", znk_version);

    const znk_test_step = b.step("test-znk", "Run znk tests");
    znk_test_step.dependOn(&znk_tests.step);

    const znk = b.addExecutable("znk", "tool/znk.zig");
    znk.setBuildMode(mode);
    znk.setTarget(target);
    znk.addPackagePath("nkeys", "src/main.zig");
    znk.addBuildOption([]const u8, "version", znk_version);

    const znk_install = b.addInstallArtifact(znk);

    const znk_step = b.step("znk", "Build znk");
    znk_step.dependOn(&znk_install.step);

    const znk_run_cmd = znk.run();
    znk_run_cmd.step.dependOn(&znk_install.step);
    if (b.args) |args| {
        znk_run_cmd.addArgs(args);
    }

    const znk_run_step = b.step("run-znk", "Run znk");
    znk_run_step.dependOn(&znk_run_cmd.step);
}
