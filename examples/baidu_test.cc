// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#include <iostream>

#include "kl/env.h"
#include "kl/inet.h"
#include "kl/netdev.h"
#include "kl/tcp.h"

static const char *GET = "GET / HTTP/1.1\r\n\r\n";

int main() {
  auto tcp_sock = kl::tcp::Socket();
  assert(tcp_sock);
  int fd = *tcp_sock;
  kl::env::Defer defer([fd] { ::close(fd); });
  auto bind_if = kl::netdev::BindInterface(fd, "tun0");
  if (!bind_if) {
    std::cerr << bind_if.Err().ToCString() << std::endl;
  }
  assert(bind_if);
  auto bind = kl::inet::Bind(fd, "10.0.0.1", 4000);
  assert(bind);
  auto connect = kl::inet::BlockingConnect(fd, "123.125.114.144", 80);
  assert(connect);
  return 0;
}
