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

void PrintUsage(int argc, char *argv[]) {
  std::fprintf(stderr, "%s: \n"
                       "    -r <remote_host:remote_port>\n"
                       "    -t <tun_name>\n"
                       "    -a <tun_addr>\n"
                       "    -d <tun_dstaddr>\n"
                       "    -m <tun_mask>\n",
               argv[0]);
}

static kl::Result<ssize_t> WriteTun(int tun_fd, const char *buf, int len) {
  ssize_t nwrite = ::write(tun_fd, buf, len);
  if (nwrite < 0) {
    return kl::Err(errno, std::strerror(errno));
  }
  return kl::Ok(nwrite);
}

static kl::Result<ssize_t> WriteInet(int udp_fd, const char *buf, int len,
                                     const char *host, uint16_t port) {
  std::string compress;
  size_t n = snappy::Compress(buf, len, &compress);
  KL_DEBUG("origin len %d, compressed len %d", len, n);
  return kl::inet::Sendto(udp_fd, compress.data(), compress.size(), 0, host,
                          port);
}

static int RunIt(const std::string &remote_host, uint16_t remote_port,
                 int tun_fd) {
  auto udp_sock = kl::udp::Socket();
  if (!udp_sock) {
    KL_ERROR(udp_sock.Err().ToCString());
    return 1;
  }
  int udp_fd = *udp_sock;
  kl::env::Defer defer([fd = udp_fd] { ::close(fd); });
  auto set_nb = kl::env::SetNonBlocking(udp_fd);
  if (!set_nb) {
    KL_ERROR(set_nb.Err().ToCString());
    return 1;
  }
  char buf[65536];
  kl::Epoll epoll;
  epoll.AddFd(tun_fd, EPOLLET | EPOLLIN);
  epoll.AddFd(udp_fd, EPOLLET | EPOLLIN);
  while (true) {
    auto wait = epoll.Wait(4, -1);
    if (!wait) {
      KL_ERROR(wait.Err().ToCString());
      return 1;
    }
    for (const auto &event : *wait) {
      int fd = event.data.fd;
      if (event.events & EPOLLIN) {
        // read until EAGAIN or EWOULDBLOCK
        while (true) {
          int nread = ::read(fd, buf, sizeof(buf));
          if (nread < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
              break;
            }
            KL_ERROR(std::strerror(errno));
            return 1;
          }
          KL_DEBUG("read %d bytes", nread);
          if (kale::ip_packet::IsUDP(reinterpret_cast<const uint8_t *>(buf),
                                     nread)) {
            KL_DEBUG("udp protocol");
          } else if (kale::ip_packet::IsTCP(reinterpret_cast<uint8_t *>(buf),
                                            nread)) {
            KL_DEBUG("tcp protocol");
          }
          if (fd == tun_fd) {
            auto write =
                WriteInet(udp_fd, buf, nread, remote_host.c_str(), remote_port);
            if (!write) {
              KL_ERROR(write.Err().ToCString());
              return 1;
            }
          } else if (fd == udp_fd) {
            auto write = WriteTun(tun_fd, buf, nread);
            if (!write) {
              KL_ERROR(write.Err().ToCString());
              return 1;
            }
          }
        }  // end while
      }    // end EPOLLIN handle
      if (event.events & EPOLLERR) {
        int error = 0;
        socklen_t len = sizeof(error);
        if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) == 0) {
          KL_ERROR(std::strerror(error));
        } else {
          KL_ERROR("EPOLLERR");
        }
        return 1;
      }
    }
  }
  return 0;
}

int main(int argc, char *argv[]) {
  std::string remote_host;
  uint16_t remote_port = 0;                 // -r
  std::string tun_name("tun0");             // -t
  std::string tun_addr("10.0.0.1");         // -a
  std::string tun_dstaddr("10.0.0.2");      // -d
  std::string tun_mask("255.255.255.255");  // -m
  int opt = 0;
  while ((opt = ::getopt(argc, argv, "r:t:a:d:m:h")) != -1) {
    switch (opt) {
      case 'r': {
        auto split = kl::inet::SplitAddr(optarg, &remote_host, &remote_port);
        if (!split) {
          std::cerr << split.Err().ToCString() << "\n";
          ::exit(1);
        }
        // KL_DEBUG("remote host %s:%u", remote_host.c_str(), remote_port);
        break;
      }
      case 't': {
        tun_name = optarg;
        break;
      }
      case 'a': {
        tun_addr = optarg;
        break;
      }
      case 'd': {
        tun_dstaddr = optarg;
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
  auto tun_if =
      kale::AllocateTunInterface(tun_name.c_str(), tun_addr.c_str(),
                                 tun_dstaddr.c_str(), tun_mask.c_str());
  if (!tun_if) {
    std::fprintf(stderr, "%s\n", tun_if.Err().ToCString());
    ::exit(1);
  }
  kl::env::Defer defer([fd = *tun_if] { ::close(fd); });
  auto set_nb = kl::env::SetNonBlocking(*tun_if);
  if (!set_nb) {
    std::fprintf(stderr, "%s\n", set_nb.Err().ToCString());
    ::exit(1);
  }
  auto if_up = kl::netdev::InterfaceUp(tun_name.c_str());
  if (!if_up) {
    std::fprintf(stderr, "%s\n", if_up.Err().ToCString());
    ::exit(1);
  }
  auto add_route = kl::netdev::AddRoute(tun_name.c_str(), tun_addr.c_str(),
                                        tun_mask.c_str());
  if (!add_route) {
    std::fprintf(stderr, "%s\n", add_route.Err().ToCString());
    ::exit(1);
  }
  return RunIt(remote_host, remote_port, *tun_if);
}
