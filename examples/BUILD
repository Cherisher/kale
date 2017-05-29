filegroup(
    name = "examples",
    srcs = [
        "dns_query",
        "raw_tun_proxy",
        "tun_proxy_remote",
    ],
)

cc_binary(
    name = "dns_query",
    srcs = ["dns_query.cc"],
    deps = ["//:kale"],
    copts = [
        "-std=c++14",
    ],
    linkopts = [
        "-lpthread",
    ],
)

cc_binary(
    name = "raw_tun_proxy",
    srcs = ["raw_tun_proxy.cc"],
    deps = ["//:kale"],
    copts = [
        "-std=c++14",
    ],
    linkopts = [
        "-lpthread",
        "-lpcap",
    ],
)

cc_binary(
    name = "tun_proxy_remote",
    srcs = ["tun_proxy_remote.cc"],
    deps = ["//:kale"],
    copts = [
        "-std=c++14",
    ],
    linkopts = [
        "-lpthread",
        "-lpcap",
    ],
)
