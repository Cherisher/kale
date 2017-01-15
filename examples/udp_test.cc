// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#include <iostream>

#include "kl/env.h"
#include "kl/inet.h"
#include "kl/netdev.h"
#include "kl/udp.h"

int main() {
  const char *ifname = "tun0";
  const char *dst_addr = "216.58.193.99";
  const std::string message("c", 1472);
  uint16_t dst_port = 80;
  auto udp_sock = kl::udp::Socket();
  assert(udp_sock);
  int fd = *udp_sock;
  kl::env::Defer defer([fd] { ::close(fd); });
  auto bind_if = kl::netdev::BindInterface(fd, ifname);
  assert(bind_if);
  // Or reverse path route filter might drop packets
  kl::netdev::AddRoute(dst_addr, nullptr, ifname);
  auto send = kl::inet::Sendto(fd, message.data(), message.size(), 0, dst_addr,
                               dst_port);
  assert(send);
  return 0;
}
