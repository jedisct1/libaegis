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

    const lib_options = b.addOptions();

    const favor_performance: bool = b.option(bool, "favor-performance", "Favor performance over side channel mitigations") orelse false;
    lib_options.addOption(bool, "favor_performance", favor_performance);
    if (favor_performance) {
        lib.defineCMacro("FAVOR_PERFORMANCE", "1");
    }

    const non_temporal_stores: bool = b.option(bool, "non-temporal-stores", "Use non-temporal stores") orelse false;
    lib_options.addOption(bool, "non_temporal_stores", non_temporal_stores);
    if (non_temporal_stores) {
        lib.defineCMacro("NON_TEMPORAL_STORES", "1");
    }

    lib.addIncludePath(.{ .path = "src/include" });

    lib.addCSourceFiles(&.{
        "src/aegis128l/aegis128l_aesni.c",
        "src/aegis128l/aegis128l_armcrypto.c",
        "src/aegis128l/aegis128l_soft.c",
        "src/aegis128l/aegis128l.c",

        "src/aegis128x2/aegis128x2_aesni.c",
        "src/aegis128x2/aegis128x2_avx2.c",
        "src/aegis128x2/aegis128x2_armcrypto.c",
        "src/aegis128x2/aegis128x2_soft.c",
        "src/aegis128x2/aegis128x2.c",

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
