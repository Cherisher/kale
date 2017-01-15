// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
// Use of this source code is governed by the BSD license that can be found in
// the LICENSE file.

#include <iostream>

#include "kl/env.h"
#include "kl/inet.h"
#include "kl/netdev.h"
#include "kl/tcp.h"

int main() {
  const char *dst_addr = "123.125.114.144";
  uint16_t dst_port = 80;
  auto tcp_sock = kl::tcp::Socket();
  assert(tcp_sock);
  int fd = *tcp_sock;
  kl::env::Defer defer([fd] { ::close(fd); });
  auto connect = kl::inet::BlockingConnect(fd, dst_addr, dst_port);
  assert(connect);
  return 0;
}
