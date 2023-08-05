const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseFast });

    const lib = b.addStaticLibrary(.{
        .name = "libaegis",
        .target = target,
        .optimize = optimize,
    });

    lib.linkLibC();
    lib.strip = true;

    lib.addIncludePath(.{ .path = "src/include" });

    lib.addCSourceFiles(&.{
        "src/aegis128l/aegis128l_aesni.c",
        "src/aegis128l/aegis128l_armcrypto.c",
        "src/aegis128l/aegis128l_soft.c",
        "src/aegis128l/aegis128l.c",

        "src/aegis256/aegis256_aesni.c",
        "src/aegis256/aegis256_armcrypto.c",
        "src/aegis256/aegis256_soft.c",
        "src/aegis256/aegis256.c",

        "src/common/common.c",
        "src/common/cpu.c",
        "src/common/softaes.c",
    }, &.{});

    // This declares intent for the executable to be installed into the
    // standard location when the user invokes the "install" step (the default
    // step when running `zig build`).
    b.installArtifact(lib);

    b.installDirectory(.{
        .install_dir = .header,
        .install_subdir = "",
        .source_dir = .{ .path = "src/include" },
    });

    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    const main_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/test/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    main_tests.addIncludePath(.{ .path = "src/include" });
    main_tests.linkLibrary(lib);

    const run_main_tests = b.addRunArtifact(main_tests);

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build test`
    // This will evaluate the `test` step rather than the default, which is "install".
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);
}
