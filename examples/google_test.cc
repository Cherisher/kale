// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#include <iostream>

#include "kl/env.h"
#include "kl/inet.h"
#include "kl/netdev.h"
#include "kl/tcp.h"

int main() {
  const char *ifname = "tun0";
  const char *dst_addr = "216.58.193.99";
  uint16_t dst_port = 80;
  auto tcp_sock = kl::tcp::Socket();
  assert(tcp_sock);
  int fd = *tcp_sock;
  kl::env::Defer defer([fd] { ::close(fd); });
  auto bind_if = kl::netdev::BindInterface(fd, ifname);
  assert(bind_if);
  // Or reverse path route filter might drop packets
  kl::netdev::AddRoute(dst_addr, nullptr, ifname);
  auto connect = kl::inet::BlockingConnect(fd, dst_addr, dst_port);
  assert(connect);
  const std::string get("GET / HTTP/1.1\r\n\r\n");
  int nwrite = ::write(fd, get.data(), get.size());
  assert(nwrite == static_cast<int>(get.size()));
  char buf[65536];
  int nread = ::read(fd, buf, sizeof(buf));
  buf[nread] = 0;
  std::cout << buf << std::endl;
  return 0;
}
