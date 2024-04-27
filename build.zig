const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    const run_lib_tests = b.addRunArtifact(lib_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_lib_tests.step);

    const znk_version = "0.2.2";

    const znk_options = b.addOptions();
    znk_options.addOption([]const u8, "version", znk_version);

    const lib = b.addStaticLibrary(.{
        .name = "nkeys",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    b.installArtifact(lib);

    const znk_tests = b.addTest(.{
        .root_source_file = .{ .path = "tool/znk.zig" },
        .target = target,
        .optimize = optimize,
    });
    znk_tests.root_module.addImport("nkeys", &lib.root_module);
    znk_tests.root_module.addOptions("build_options", znk_options);
    const run_znk_tests = b.addRunArtifact(znk_tests);

    const znk_test_step = b.step("test-znk", "Run znk tests");
    znk_test_step.dependOn(&run_znk_tests.step);

    const znk = b.addExecutable(.{
        .name = "znk",
        .root_source_file = .{ .path = "tool/znk.zig" },
        .target = target,
        .optimize = optimize,
    });
    znk.root_module.addImport("nkeys", &lib.root_module);
    znk.root_module.addOptions("build_options", znk_options);

    b.installArtifact(znk);

    const znk_run_cmd = b.addRunArtifact(znk);
    znk_run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        znk_run_cmd.addArgs(args);
    }

    const znk_run_step = b.step("run-znk", "Run znk");
    znk_run_step.dependOn(&znk_run_cmd.step);
}
