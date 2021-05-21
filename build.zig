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

    const lib = b.addStaticLibrary("zats", "src/nkeys.zig");
    lib.setBuildMode(mode);
    lib.addBuildOption([:0]const u8, "version", try b.allocator.dupeZ(u8, version));
    lib.install();

    var lib_tests = b.addTest("src/nkeys.zig");
    lib_tests.setBuildMode(mode);
    lib_tests.addBuildOption([:0]const u8, "version", try b.allocator.dupeZ(u8, version));

    var znk_tests = b.addTest("src/znk.zig");
    znk_tests.setBuildMode(mode);
    znk_tests.addBuildOption([:0]const u8, "version", try b.allocator.dupeZ(u8, version));

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&lib_tests.step);

    const znk_test_step = b.step("znk-test", "Run znk tests");
    znk_test_step.dependOn(&znk_tests.step);

    const exe = b.addExecutable("znk", "src/znk.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.addBuildOption([:0]const u8, "version", try b.allocator.dupeZ(u8, version));
    exe.install();

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run znk");
    run_step.dependOn(&run_cmd.step);
}
