// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
// Use of this source code is governed by the BSD license that can be found in
// the LICENSE file.

#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <iostream>
#include <sstream>
#include <thread>

#include "kale/ip_packet.h"
#include "kale/tun.h"
#include "kl/env.h"
#include "kl/epoll.h"
#include "kl/inet.h"
#include "kl/logger.h"
#include "kl/netdev.h"
#include "kl/tcp.h"
#include "kl/testkit.h"
#include "kl/udp.h"
#include "kl/wait_group.h"

namespace {

class T {};

TEST(T, Allocation) {
  std::string tun_name(kale::RandomTunName());
  auto alloc = kale::AllocateTun(tun_name.c_str());
  ASSERT(alloc);
  auto ifindex = kl::netdev::RetrieveIFIndex(tun_name.c_str());
  ASSERT(ifindex);
  ::close(*alloc);
}

TEST(T, ReadWriteTun) {
  const int kNumOfPackets = 1 << 10;
  const std::string message("imfao|wtf|rofl~~|rekt");
  const char *ifname = "tun0";
  const char *addr = "10.0.0.10";
  const char *mask = "255.255.255.0";
  const char *dst_addr = "123.125.114.144";
  uint16_t dst_port = 3000;
  auto tun_if = kale::AllocateTun(ifname);
  ASSERT(tun_if);
  int tun_fd = *tun_if;
  kl::env::Defer defer([fd = tun_fd] { ::close(fd); });
  // ASSERT(kl::env::SetNonBlocking(tun_fd));
  ASSERT(kl::netdev::InterfaceUp(ifname));
  ASSERT(kl::netdev::SetAddr(ifname, addr));
  ASSERT(kl::netdev::SetNetMask(ifname, mask));
  ASSERT(kl::netdev::AddRoute(dst_addr, nullptr, ifname));
  auto send_thread = std::thread([addr, message, ifname, dst_addr, dst_port] {
    auto sock = kl::udp::Socket();
    ASSERT(sock);
    kl::env::Defer defer([fd = *sock] { ::close(fd); });
    auto bind_if = kl::netdev::BindInterface(*sock, ifname);
    if (!bind_if) {
      KL_ERROR(bind_if.Err().ToCString());
    }
    for (int i = 0; i < kNumOfPackets; ++i) {
      auto send = kl::inet::Sendto(*sock, message.c_str(), message.size(), 0,
                                   dst_addr, dst_port);
      ASSERT(send);
      // KL_DEBUG("delivered %d bytes via socket", *send);
      char buf[65536];
      int nread = ::read(*sock, buf, sizeof(buf));
      ASSERT(nread >= 0);
      // KL_DEBUG("read %d bytes from socket", nread);
      buf[nread] = 0;
      ASSERT(std::string(buf) == message);
    }
  });
  char buf[65536];
  // KL_DEBUG("waiting for traffic...");
  for (int i = 0; i < kNumOfPackets; ++i) {
    int nread = ::read(tun_fd, buf, sizeof(buf));
    // minimum ip header size + minimum udp header size = 20 + 8 = 28
    ASSERT(nread >= 28);
    // KL_DEBUG("read %d bytes from tun", nread);
    uint8_t *packet = reinterpret_cast<uint8_t *>(buf);
    size_t len = nread;
    // protocol type
    ASSERT(kale::ip_packet::IsUDP(packet, len));
    // header check sum
    // KL_DEBUG("ip header actual checksum: %u",
    //          *reinterpret_cast<uint16_t *>(packet + 10));
    // KL_DEBUG("ip header checksum calculated: %u",
    //          kale::ip_packet::IPHeaderChecksum(packet, len));
    ASSERT(*reinterpret_cast<uint16_t *>(buf + 10) ==
           kale::ip_packet::IPHeaderChecksum(packet, len));
    // udp check sum
    uint8_t *segment = kale::ip_packet::SegmentBase(packet, len);
    // KL_DEBUG("src port %u", kale::ip_packet::UDPSrcPort(packet, len));
    // KL_DEBUG("dst port %u", kale::ip_packet::UDPDstPort(packet, len));
    uint16_t checksum = *reinterpret_cast<const uint16_t *>(segment + 6);
    // KL_DEBUG("udp actual checksum: %u", checksum);
    // KL_DEBUG("udp checksum calculated: %u",
    //             kale::ip_packet::UDPChecksum(packet, len));
    ASSERT(checksum == kale::ip_packet::UDPChecksum(packet, len));
    buf[nread] = '\0';
    ASSERT(std::string(buf + 28) == message);
    // swap src/dst
    kale::ip_packet::UDPEcho(packet, nread);
    kale::ip_packet::UDPFillChecksum(packet, nread);
    kale::ip_packet::IPFillChecksum(packet, nread);
    // KL_DEBUG("writing to tun");
    int nwrite = ::write(tun_fd, buf, nread);
    // KL_DEBUG("write %d bytes back to tun", nwrite);
    ASSERT(nwrite == nread);
  }
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

TEST(T, BindPort) {
  auto udp = kl::udp::Socket();
  int fd0 = *udp;
  kl::env::Defer defer([fd = fd0] { ::close(fd); });
  udp = kl::udp::Socket();
  int fd1 = *udp;
  defer([fd = fd1] { ::close(fd); });
  uint16_t port = 40000;
  ASSERT(kl::inet::Bind(fd0, "0.0.0.0", port));
  ASSERT(!kl::inet::Bind(fd1, "127.0.0.1", port));
}

}  // namespace
