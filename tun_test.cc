// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <iostream>
#include <sstream>
#include <thread>

#include "ip_packet.h"
#include "kl/env.h"
#include "kl/epoll.h"
#include "kl/inet.h"
#include "kl/logger.h"
#include "kl/netdev.h"
#include "kl/tcp.h"
#include "kl/testkit.h"
#include "kl/udp.h"
#include "kl/wait_group.h"
#include "tun.h"

class T {};

TEST(T, Allocation) {
  std::string tun_name(kale::RandomTunName());
  auto alloc = kale::AllocateTun(tun_name.c_str());
  ASSERT(alloc);
  auto ifindex = kl::netdev::RetrieveIFIndex(tun_name.c_str());
  ASSERT(ifindex);
  ::close(*alloc);
}

TEST(T, UDPTun) {
  const std::string message("imfao|wtf|rofl");
  const char *addr = "10.0.0.1";
  const char *dstaddr = "10.0.0.2";
  const char *mask = "255.255.255.255";
  uint16_t port = 4000;
  auto tun_if = kale::AllocateTunInterface("tun23", addr, dstaddr, mask);
  ASSERT(tun_if);
  int tun_fd = *tun_if;
  kl::env::Defer defer([fd = tun_fd] { ::close(fd); });
  ASSERT(kl::netdev::InterfaceUp("tun23"));
  auto add_route = kl::netdev::AddRoute("tun23", addr, mask);
  if (!add_route) {
    KL_DEBUG(add_route.Err().ToCString());
  }
  ASSERT(add_route);
  auto send_thread = std::thread([addr, port, message, dstaddr] {
    auto sock = kl::udp::Socket();
    ASSERT(sock);
    kl::env::Defer defer([fd = *sock] { ::close(fd); });
    auto bind = kl::inet::Bind(*sock, addr, port);
    if (!bind) {
      KL_DEBUG(bind.Err().ToCString());
    }
    ASSERT(bind);
    auto send = kl::inet::Sendto(*sock, message.c_str(), message.size(), 0,
                                 dstaddr, 80);
    ASSERT(send);
    KL_DEBUG("send %d bytes", *send);
  });
  char buf[65536];
  KL_DEBUG("waiting for traffic...");
  int nread = ::read(tun_fd, buf, sizeof(buf));
  // minimum ip header size + minimum udp header size = 20 + 8 = 28
  ASSERT(nread >= 28);
  KL_DEBUG("read %d bytes", nread);
  KL_DEBUG("header origin check sum: %u",
           *reinterpret_cast<uint16_t *>(buf + 10));
  KL_DEBUG("header check sum: %u",
           kale::ip_packet::IPHeaderCheckSum(
               reinterpret_cast<const uint8_t *>(buf), nread));
  buf[nread] = '\0';
  ASSERT(std::string(buf + 28) == message);
  send_thread.join();
}

TEST(T, RawIPv4Socket) {
  auto raw = kale::RawIPv4Socket();
  if (!raw) {
    KL_DEBUG(raw.Err().ToCString());
  }
  ASSERT(raw);
  ::close(*raw);
}

int main() { return KL_TEST(); }
