const std = @import("std");

pub fn build(b: *std.build.Builder) !void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const version = "0.1.0-dev";

    const lib = b.addStaticLibrary("nkeys", "src/nkeys.zig");
    lib.setBuildMode(mode);
    lib.addBuildOption([:0]const u8, "version", try b.allocator.dupeZ(u8, version));
    lib.install();

    var lib_tests = b.addTest("src/nkeys.zig");
    lib_tests.setBuildMode(mode);
    lib_tests.addBuildOption([:0]const u8, "version", try b.allocator.dupeZ(u8, version));

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&lib_tests.step);

    var znk_tests = b.addTest("tool/znk.zig");
    znk_tests.setBuildMode(mode);
    znk_tests.addPackagePath("nkeys", "src/nkeys.zig");
    znk_tests.addBuildOption([:0]const u8, "version", try b.allocator.dupeZ(u8, version));

    const znk_test_step = b.step("test-znk", "Run znk tests");
    znk_test_step.dependOn(&znk_tests.step);

    const znk = b.addExecutable("znk", "tool/znk.zig");
    znk.setTarget(target);
    znk.setBuildMode(mode);
    znk.addPackagePath("nkeys", "src/nkeys.zig");
    znk.addBuildOption([:0]const u8, "version", try b.allocator.dupeZ(u8, version));

    const znk_install = b.addInstallArtifact(znk);

    const znk_step = b.step("znk", "Build only znk");
    znk_step.dependOn(&znk_install.step);

    const znk_run_cmd = znk.run();
    znk_run_cmd.step.dependOn(&znk_install.step);
    if (b.args) |args| {
        znk_run_cmd.addArgs(args);
    }

    const znk_run_step = b.step("run-znk", "Run znk");
    znk_run_step.dependOn(&znk_run_cmd.step);
}
