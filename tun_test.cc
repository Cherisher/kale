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

TEST(T, ReadWriteTun) {
  const std::string message("imfao|wtf|rofl~~|rekt");
  const char *ifname = "tun23";
  const char *addr = "10.0.0.1";
  const char *dst_addr = "10.0.0.2";
  const char *mask = "255.255.255.0";
  uint16_t port = 4000;
  uint16_t dst_port = 3000;
  auto tun_if = kale::AllocateTun(ifname);
  ASSERT(tun_if);
  int tun_fd = *tun_if;
  kl::env::Defer defer([fd = tun_fd] { ::close(fd); });
  // ASSERT(kl::env::SetNonBlocking(tun_fd));
  ASSERT(kl::netdev::InterfaceUp(ifname));
  ASSERT(kl::netdev::SetAddr(ifname, addr));
  ASSERT(kl::netdev::SetNetMask(ifname, mask));
  auto send_thread =
      std::thread([addr, port, message, ifname, dst_addr, dst_port] {
        auto sock = kl::udp::Socket();
        ASSERT(sock);
        kl::env::Defer defer([fd = *sock] { ::close(fd); });
        auto bind_if = kl::netdev::BindInterface(*sock, ifname);
        if (!bind_if) {
          KL_DEBUG(bind_if.Err().ToCString());
        }
        auto bind = kl::inet::Bind(*sock, addr, port);
        ASSERT(bind);
        auto send = kl::inet::Sendto(*sock, message.c_str(), message.size(), 0,
                                     dst_addr, dst_port);
        ASSERT(send);
        KL_DEBUG("delivered %d bytes", *send);
        char buf[65536];
        int nread = ::read(*sock, buf, sizeof(buf));
        ASSERT(nread >= 0);
        KL_DEBUG("read %d bytes", nread);
      });
  char buf[65536];
  KL_DEBUG("waiting for traffic...");
  int nread = ::read(tun_fd, buf, sizeof(buf));
  // minimum ip header size + minimum udp header size = 20 + 8 = 28
  ASSERT(nread >= 28);
  KL_DEBUG("read %d bytes", nread);
  // protocol type
  ASSERT(kale::ip_packet::IsUDP(reinterpret_cast<const uint8_t *>(buf), nread));
  // header check sum
  KL_DEBUG("ip header actual checksum: %u",
           *reinterpret_cast<uint16_t *>(buf + 10));
  KL_DEBUG("ip header checksum calculated: %u",
           kale::ip_packet::IPHeaderChecksum(
               reinterpret_cast<const uint8_t *>(buf), nread));
  ASSERT(*reinterpret_cast<uint16_t *>(buf + 10) ==
         kale::ip_packet::IPHeaderChecksum(
             reinterpret_cast<const uint8_t *>(buf), nread));
  // udp check sum
  uint8_t *segment = reinterpret_cast<uint8_t *>(
      buf + kale::ip_packet::IPHeaderLength(
                reinterpret_cast<const uint8_t *>(buf), nread));
  KL_DEBUG("src port %u", ntohs(*reinterpret_cast<const uint16_t *>(segment)));
  KL_DEBUG("dst port %u",
           ntohs(*reinterpret_cast<const uint16_t *>(segment + 2)));
  uint16_t checksum = *reinterpret_cast<const uint16_t *>(segment + 6);
  KL_DEBUG("udp actual checksum: %u", checksum);
  KL_DEBUG("udp checksum calculated: %u",
           kale::ip_packet::UDPChecksum(reinterpret_cast<const uint8_t *>(buf),
                                        nread));
  ASSERT(checksum == kale::ip_packet::UDPChecksum(
                         reinterpret_cast<const uint8_t *>(buf), nread));
  buf[nread] = '\0';
  ASSERT(std::string(buf + 28) == message);
  // swap src/dst
  uint8_t *packet = reinterpret_cast<uint8_t *>(buf);
  uint32_t tmp_addr = *reinterpret_cast<uint32_t *>(packet + 12);
  *reinterpret_cast<uint32_t *>(packet + 12) =
      *reinterpret_cast<uint32_t *>(packet + 16);
  *reinterpret_cast<uint32_t *>(packet + 16) = tmp_addr;
  uint16_t tmp_port = *reinterpret_cast<uint16_t *>(segment);
  *reinterpret_cast<uint16_t *>(segment) =
      *reinterpret_cast<uint16_t *>(segment + 2);
  *reinterpret_cast<uint16_t *>(segment + 2) = tmp_port;
  kale::ip_packet::UDPFillChecksum(packet, nread);
  kale::ip_packet::IPFillChecksum(packet, nread);
  KL_DEBUG("writing to tun");
  int nwrite = ::write(tun_fd, buf, nread);
  KL_DEBUG("write %d bytes", nwrite);
  ASSERT(nwrite == nread);
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
