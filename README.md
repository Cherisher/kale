kale 卡了
--------------------------------
A lag proxy library.

# Build
In order to build this library, some packages are prerequisites. On ubuntu, users can install them by
`sudo apt install flex bison libpcap-dev libdbus-1-dev`. Then just compile it with command `bazel build examples`.

# Examples
`examples/raw_tun_proxy.cc` and `examples/tun_proxy_remote.cc` demonstrate how to use this library to build a scalable L3 proxy.
