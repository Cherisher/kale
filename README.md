kale 卡了
--------------------------------
A lag proxy library.

# Build
In order to build this library, `flex` and `bison` are prerequisites. On ubuntu, users can install them by
`sudo apt install flex bison`. Then just compile it with command `make`.

# Examples
`examples/raw_tun_proxy.cc` and `tun_proxy_remote.cc` demonstrate how to use this library to build a scalable L3 proxy.
