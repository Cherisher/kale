// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
// Use of this source code is governed by the BSD license that can be found in
// the LICENSE file.

#include <unistd.h>

#include <atomic>
#include <cstdlib>
#include <iostream>
#include <string>

#include "kale/arcfour.h"
#include "kale/coding.h"
#include "kale/demo_coding.h"
#include "kale/ip.h"
#include "kale/tun.h"
#include "kl/env.h"
#include "kl/epoll.h"
#include "kl/hexdump.h"
#include "kl/inet.h"
#include "kl/logger.h"
#include "kl/netdev.h"
#include "kl/scheduler.h"
#include "kl/slice.h"
#include "kl/string.h"
#include "kl/udp.h"

namespace {

void DumpErrorPacket(const char *packet_type, const uint8_t *packet,
                     size_t len) {
  std::string packet_dump;
  kl::Slice s(reinterpret_cast<const char *>(packet), len);
  kl::HexDump(s, &packet_dump);
  KL_ERROR("%s packet dump: %s", packet_type, packet_dump.c_str());
}

void StatTCP(const uint8_t *packet, size_t len) {
  const uint8_t *segment = kale::ip::SegmentBase(packet, len);
  uint16_t actual_checksum = *reinterpret_cast<const uint16_t *>(segment + 16);
  uint16_t calc_checksum = kale::ip::TCPChecksum(packet, len);
  if (actual_checksum != calc_checksum) {
    KL_ERROR("tcp actual_checksum: %u, calc_checksum: %u", actual_checksum,
             calc_checksum);
    DumpErrorPacket("tcp", packet, len);
  }
  KL_DEBUG("tcp segment, src addr %s, dst addr %s, data length: %u",
           kale::ip::TCPSrcAddr(packet, len).c_str(),
           kale::ip::TCPDstAddr(packet, len).c_str(),
           kale::ip::TCPDataLength(packet, len));
}

void StatUDP(const uint8_t *packet, size_t len) {
  const uint8_t *segment = kale::ip::SegmentBase(packet, len);
  uint16_t actual_checksum = *reinterpret_cast<const uint16_t *>(segment + 6);
  uint16_t calc_checksum = kale::ip::UDPChecksum(packet, len);
  if (actual_checksum != calc_checksum) {
    KL_ERROR("udp actual_checksum: %u, calc_checksum: %u", actual_checksum,
             calc_checksum);
    DumpErrorPacket("udp", packet, len);
  }
  KL_DEBUG("udp segment, src addr %s, dst addr %s, data length: %u",
           kale::ip::UDPSrcAddr(packet, len).c_str(),
           kale::ip::UDPDstAddr(packet, len).c_str(),
           kale::ip::UDPDataLength(packet, len));
}

void StatIPPacket(const uint8_t *packet, size_t len) {
  uint16_t actual_checksum = *reinterpret_cast<const uint16_t *>(packet + 10);
  uint16_t calculated_checksum = kale::ip::IPHeaderChecksum(packet, len);
  if (actual_checksum != calculated_checksum) {
    KL_ERROR("actual checksum: %u, calculated checksum: %u", actual_checksum,
             calculated_checksum);
    DumpErrorPacket("ip", packet, len);
    return;
  }
  if (kale::ip::IsTCP(packet, len)) {
    StatTCP(packet, len);
  }
  if (kale::ip::IsUDP(packet, len)) {
    StatUDP(packet, len);
  }
}

class RawTunProxy {
 public:
  RawTunProxy(const char *inet_ifname, const char *inet_gateway,
              const char *ifname, const char *addr, const char *mask,
              uint16_t mtu, const char *remote_host, uint16_t remote_port,
              const char *key, size_t key_len);

  int Run();
  ~RawTunProxy() {
    if (tun_fd_ >= 0) {
      ::close(tun_fd_);
    }
    if (udp_fd_ >= 0) {
      ::close(udp_fd_);
    }
  }

 private:
  int EpollLoop();
  kl::Result<void> HandleTUN();
  kl::Result<void> HandleUDP();
  std::string ifname_, addr_, mask_;
  uint16_t mtu_;
  std::string remote_host_;
  uint16_t remote_port_;
  int tun_fd_, udp_fd_;
  kl::Epoll epoll_;
  kale::Coding coding_;
  uint64_t write_tun_dropped_;
  uint64_t write_udp_dropped_;
};

RawTunProxy::RawTunProxy(const char *inet_ifname, const char *inet_gateway,
                         const char *ifname, const char *addr, const char *mask,
                         uint16_t mtu, const char *remote_host,
                         uint16_t remote_port, const char *key, size_t key_len)
    : ifname_(ifname),
      addr_(addr),
      mask_(mask),
      mtu_(mtu),
      remote_host_(remote_host),
      remote_port_(remote_port),
      tun_fd_(-1),
      udp_fd_(-1),
      coding_(
          kale::DemoCoding(reinterpret_cast<const uint8_t *>(key), key_len)),
      write_tun_dropped_(0),
      write_udp_dropped_(0) {
  auto alloc_tun = kale::AllocateTun(ifname);
  if (!alloc_tun) {
    throw std::runtime_error(alloc_tun.Err().ToCString());
  }
  tun_fd_ = *alloc_tun;
  assert(tun_fd_ >= 0);
  auto set_addr = kl::netdev::SetAddr(ifname, addr);
  if (!set_addr) {
    throw std::runtime_error(set_addr.Err().ToCString());
  }
  auto set_mask = kl::netdev::SetNetMask(ifname, mask);
  if (!set_mask) {
    throw std::runtime_error(set_mask.Err().ToCString());
  }
  auto set_mtu = kl::netdev::SetMTU(ifname, mtu);
  if (!set_mtu) {
    throw std::runtime_error(set_mtu.Err().ToCString());
  }
  auto if_up = kl::netdev::InterfaceUp(ifname);
  if (!if_up) {
    throw std::runtime_error(if_up.Err().ToCString());
  }
  auto add_route = kl::netdev::AddRoute(remote_host, inet_gateway, inet_ifname);
  if (!add_route && add_route.Err().Code() != EEXIST) {
    throw std::runtime_error(kl::string::FormatString(
        "%s:%d: failed to add route entry, %s\n", __FILE__, __LINE__,
        add_route.Err().ToCString()));
  }
  add_route = kl::netdev::AddDefaultGateway(addr);
  if (!add_route && add_route.Err().Code() != EEXIST) {
    throw std::runtime_error(kl::string::FormatString(
        "%s:%d: failed to add route entry, %s\n", __FILE__, __LINE__,
        add_route.Err().ToCString()));
  }
  auto udp = kl::udp::Socket();
  if (!udp) {
    throw std::runtime_error(udp.Err().ToCString());
  }
  udp_fd_ = *udp;
  assert(udp_fd_ >= 0);
}

int RawTunProxy::Run() {
  auto set_nb = kl::env::SetNonBlocking(udp_fd_);
  if (!set_nb) {
    KL_ERROR("set udp_fd_ failed, %s", set_nb.Err().ToCString());
    return 1;
  }
  set_nb = kl::env::SetNonBlocking(tun_fd_);
  if (!set_nb) {
    KL_ERROR("set tun_fd_ failed, %s", set_nb.Err().ToCString());
    return 1;
  }
  auto add_udp = epoll_.AddFd(udp_fd_, EPOLLET | EPOLLIN);
  if (!add_udp) {
    KL_ERROR(add_udp.Err().ToCString());
    return 1;
  }
  auto add_tun = epoll_.AddFd(tun_fd_, EPOLLET | EPOLLIN);
  if (!add_tun) {
    KL_ERROR(add_tun.Err().ToCString());
    return 1;
  }
  int err = EpollLoop();
  return err;
}

kl::Result<void> RawTunProxy::HandleTUN() {
  char buf[65536];
  while (true) {
    int nread = ::read(tun_fd_, buf, sizeof(buf));
    if (nread < 0) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        return kl::Err(errno, std::strerror(errno));
      }
      break;
    }
    const uint8_t *packet = reinterpret_cast<const uint8_t *>(buf);
    size_t len = nread;
    StatIPPacket(packet, len);
    std::vector<uint8_t> data;
    coding_.Encode(packet, len, &data);
    auto send = kl::inet::Sendto(udp_fd_, data.data(), data.size(), 0,
                                 remote_host_.c_str(), remote_port_);
    // record number of packets dropped
    if (!send &&
        (send.Err().Code() == EAGAIN || send.Err().Code() == EWOULDBLOCK)) {
      uint64_t tmp = ++write_udp_dropped_;
      KL_ERROR("current write_udp_dropped_: %u", tmp);
    }
    if (!send && send.Err().Code() != EAGAIN &&
        send.Err().Code() != EWOULDBLOCK) {
      return kl::Err(send.MoveErr());
    }
  }
  return kl::Ok();
}

kl::Result<void> RawTunProxy::HandleUDP() {
  char buf[65536];
  while (true) {
    int nread = ::read(udp_fd_, buf, sizeof(buf));
    if (nread < 0) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        return kl::Err(errno, std::strerror(errno));
      }
      break;
    }
    std::vector<uint8_t> data;
    auto ok =
        coding_.Decode(reinterpret_cast<const uint8_t *>(buf), nread, &data);
    if (!ok) {
      KL_ERROR(ok.Err().ToCString());
      // just ignore it
      continue;
    }
    const uint8_t *packet = data.data();
    size_t len = data.size();
    StatIPPacket(packet, len);
    int nwrite = ::write(tun_fd_, packet, len);
    // record number of packets dropped
    if (nwrite < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      uint64_t tmp = ++write_tun_dropped_;
      KL_ERROR("current write_tun_dropped_: %u", tmp);
    }
    if (nwrite < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
      return kl::Err(errno, std::strerror(errno));
    }
  }
  return kl::Ok();
}

int RawTunProxy::EpollLoop() {
  while (true) {
    auto wait = epoll_.Wait(2, -1);
    if (!wait) {
      KL_ERROR(wait.Err().ToCString());
      return 1;
    }
    for (const auto &event : *wait) {
      int fd = event.data.fd;
      uint32_t events = event.events;
      if (events & EPOLLERR) {
        int error = 0;
        socklen_t len = sizeof(error);
        if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) == 0) {
          KL_ERROR(std::strerror(error));
        } else {
          KL_ERROR("EPOLLERR");
        }
        return 1;
      }
      assert(events & EPOLLIN);
      if (fd == udp_fd_) {
        auto ok = HandleUDP();
        if (!ok) {
          KL_ERROR(ok.Err().ToCString());
        }
      }
      if (fd == tun_fd_) {
        auto ok = HandleTUN();
        if (!ok) {
          KL_ERROR(ok.Err().ToCString());
        }
      }
    }
  }
}

}  // namespace (anonymous)

static void PrintUsage(int argc, char *argv[]) {
  std::fprintf(stderr,
               "%s:\n"
               "    -n <inet_interface>\n"
               "    -g <inet_gateway>\n"
               "    -r <remote_host:remote_port>\n"
               "    -i <tun_name>\n"
               "    -a <tun_addr>\n"
               "    -m <tun_mask>\n"
               "    -d daemonize\n"
               "    -u <mtu> mtu\n"
               "    -o <logfile> logfile\n"
               "    -p <passwd> password\n",
               argv[0]);
}

int main(int argc, char *argv[]) {
  std::string remote_host;
  uint16_t remote_port = 0;                // -r
  std::string inet_ifname;                 // -n
  std::string inet_gateway;                // -g
  std::string tun_name("tun0");            // -i
  std::string tun_addr("10.0.0.1");        // -a
  std::string tun_mask("255.255.255.0");   // -m
  uint16_t tun_mtu = 1380;                 // -u
  std::string log_file;                    // -o
  bool daemonize = false;                  // -d
  std::string passwd("\xc0\xde\xba\xbe");  // -p
  kl::env::Defer defer;                    // for some clean work
  int opt = 0;
  while ((opt = ::getopt(argc, argv, "n:g:r:t:a:i:m:hdo:u:p:")) != -1) {
    switch (opt) {
      case 'o':
        log_file = optarg;
        break;
      case 'u': {
        tun_mtu = atoi(optarg);
        break;
      }
      case 'd': {
        daemonize = true;
        break;
      }
      case 'n': {
        inet_ifname = optarg;
        break;
      }
      case 'g': {
        inet_gateway = optarg;
        break;
      }
      case 'r': {
        auto split = kl::inet::SplitAddr(optarg, &remote_host, &remote_port);
        if (!split) {
          std::cerr << split.Err().ToCString() << "\n";
          ::exit(1);
        }
        break;
      }
      case 'i': {
        tun_name = optarg;
        break;
      }
      case 'a': {
        tun_addr = optarg;
        break;
      }
      case 'm': {
        tun_mask = optarg;
        break;
      }
      case 'p': {
        passwd = optarg;
        break;
      }
      case 'h':
      default:
        PrintUsage(argc, argv);
        ::exit(1);
    }
  }
  if (daemonize) {
    int err = ::daemon(1, 1);
    if (err < 0) {
      KL_ERROR(std::strerror(errno));
      ::exit(1);
    }
  }
  kl::env::WritePidToFile("/tmp/raw_tun_proxy.pid");
  if (remote_host.empty() || remote_port == 0 ||
      !kl::inet::InetSockAddr(remote_host.c_str(), remote_port)) {
    std::fprintf(stderr, "%s: invalid remote host %s:%u\n", argv[0],
                 remote_host.c_str(), remote_port);
    PrintUsage(argc, argv);
    ::exit(1);
  }
  if (inet_ifname.empty()) {
    std::fprintf(stderr, "%s: inet interface must be specified.", argv[0]);
    PrintUsage(argc, argv);
    ::exit(1);
  }
  if (inet_gateway.empty() ||
      !kl::inet::InetSockAddr(inet_gateway.c_str(), 0)) {
    std::fprintf(stderr, "%s: invalid inet gateway address %s", argv[0],
                 inet_gateway.c_str());
    PrintUsage(argc, argv);
    ::exit(1);
  }
  if (!log_file.empty()) {
    int fd = ::open(log_file.c_str(), O_CREAT | O_WRONLY, 0644);
    if (fd < 0) {
      KL_ERROR(std::strerror(errno));
      ::exit(1);
    }
    defer([fd] { ::close(fd); });
    kl::logging::Logger::SetDefaultLogger(kl::logging::Logger(
        kl::logging::kError, [fd](const std::string &message) {
          int nwrite = ::write(fd, message.data(), message.size());
          (void)nwrite;
        }));
  }
  RawTunProxy proxy(inet_ifname.c_str(), inet_gateway.c_str(), tun_name.c_str(),
                    tun_addr.c_str(), tun_mask.c_str(), tun_mtu,
                    remote_host.c_str(), remote_port, passwd.c_str(),
                    passwd.size());
  return proxy.Run();
}
