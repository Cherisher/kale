examples
--------
Use `make` command to build examples.

# L3 proxy
This proxy currently supports Linux only and takes over almost all the traffic that goes into internet.
I might add white/black list in the future.

`examples/raw_tun_proxy.cc` implements client of the proxy, while `tun_proxy_remote.cc` contains server's code.
In order to launch an instance of the proxy, user must have root privilege in both client and server side.
One might run `sudo ./tun_proxy_remote -l <inet_adrees:inet_port> -i eth0 -d` in server side first, and then
`sudo ./raw_tun_proxy -n eth0 -g <gateway> -r <server_address:server_port>` for the client side.
