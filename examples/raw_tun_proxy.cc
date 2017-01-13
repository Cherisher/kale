// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#include <unistd.h>

#include <cstdlib>
#include <iostream>
#include <string>

#include "ip_packet.h"
#include "kl/env.h"
#include "kl/epoll.h"
#include "kl/inet.h"
#include "kl/logger.h"
#include "kl/netdev.h"
#include "kl/string.h"
#include "kl/udp.h"
#include "snappy/snappy.h"
#include "tun.h"

namespace {
class RawTunProxy {
public:
  RawTunProxy(const char *ifname, const char *addr, const char *mask,
              uint16_t mtu, const char *remote_host, uint16_t remote_port);

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
};

RawTunProxy::RawTunProxy(const char *ifname, const char *addr, const char *mask,
                         uint16_t mtu, const char *remote_host,
                         uint16_t remote_port)
    : ifname_(ifname), addr_(addr), mask_(mask), mtu_(mtu),
      remote_host_(remote_host), remote_port_(remote_port), tun_fd_(-1),
      udp_fd_(-1) {
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
  return EpollLoop();
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
    std::string compress;
    snappy::Compress(buf, nread, &compress);
    auto send = kl::inet::Sendto(udp_fd_, compress.data(), compress.size(), 0,
                                 remote_host_.c_str(), remote_port_);
    if (!send) {
      return kl::Err(send.MoveErr());
    }
    KL_DEBUG("send %d bytes to %s:%u", *send, remote_host_.c_str(),
             remote_port_);
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
    std::string uncompress;
    bool ok = snappy::Uncompress(buf, nread, &uncompress);
    if (!ok) {
      KL_ERROR("failed to uncompress from buf");
      // just ignore it
      continue;
    }
    int nwrite = ::write(tun_fd_, uncompress.data(), uncompress.size());
    if (nwrite < 0) {
      return kl::Err(errno, std::strerror(errno));
    }
    KL_DEBUG("write %d bytes back to tun", nwrite);
    const uint8_t *packet =
        reinterpret_cast<const uint8_t *>(uncompress.data());
    size_t len = uncompress.size();
    if (kale::ip_packet::IsUDP(packet, len)) {
      KL_DEBUG("udp dst port: %u",
               ntohs(kale::ip_packet::UDPDstPort(packet, len)));
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
          return ok.Err().Code();
        }
      }
      if (fd == tun_fd_) {
        auto ok = HandleTUN();
        if (!ok) {
          KL_ERROR(ok.Err().ToCString());
          return ok.Err().Code();
        }
      }
    }
  }
}

}  // namespace (anonymous)

static void PrintUsage(int argc, char *argv[]) {
  std::fprintf(stderr, "%s:\n"
                       "    -r <remote_host:remote_port>\n"
                       "    -i <tun_name>\n"
                       "    -a <tun_addr>\n"
                       "    -m <tun_mask>\n",
               argv[0]);
}

int main(int argc, char *argv[]) {
  std::string remote_host;
  uint16_t remote_port = 0;               // -r
  std::string tun_name("tun0");           // -i
  std::string tun_addr("10.0.0.1");       // -a
  std::string tun_mask("255.255.255.0");  // -m
  uint16_t tun_mtu = 1380;
  int opt = 0;
  while ((opt = ::getopt(argc, argv, "r:t:a:d:m:h")) != -1) {
    switch (opt) {
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
      case 'h':
      default:
        PrintUsage(argc, argv);
        ::exit(1);
    }
  }
  if (remote_host.empty() || remote_port == 0) {
    std::fprintf(stderr, "%s: invalid remote host %s:%u\n", argv[0],
                 remote_host.c_str(), remote_port);
    PrintUsage(argc, argv);
    ::exit(1);
  }
  RawTunProxy proxy(tun_name.c_str(), tun_addr.c_str(), tun_mask.c_str(),
                    tun_mtu, remote_host.c_str(), remote_port);
  return proxy.Run();
}
