cc_test(
    name = "kale_test",
    srcs = glob(["*_test.cc"]) + ["run_all_tests.cc"],
    copts = [
        "-std=c++14",
        "-Wall",
        "-Werror",
        "-g",
    ],
    linkopts = ["-lpthread", "-lpcap", "-ldbus-1"],
    deps = ["//:kale"],
)
