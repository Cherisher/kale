cc_library(
    licenses = ["notice"],
    visibility = ["//visibility:public"],
    name = "kale",
    srcs = glob(["*.cc"]),
    hdrs = glob(["include/**/*.h"]),
    includes = ["include", "kl/include"],
    copts = [
        "-std=c++14",
        "-Wall",
        "-Werror",
    ],
    deps = ["//kl:kl"],
    linkopts = ["-lpthread"],
)
