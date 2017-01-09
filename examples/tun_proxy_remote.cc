// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#include <unistd.h>

#include <atomic>
#include <cstdlib>
#include <map>
#include <set>
#include <string>
#include <thread>

#include "ip_packet.h"
#include "kl/env.h"
#include "kl/epoll.h"
#include "kl/inet.h"
#include "kl/logger.h"
#include "kl/tcp.h"
#include "kl/udp.h"
#include "kl/wait_group.h"
#include "sniffer.h"
#include "tun.h"

// For NAT
static std::map<uint16_t, std::tuple<std::string, uint16_t>> udp_port_to_host;
static std::map<uint16_t, std::tuple<std::string, uint16_t>> tcp_port_to_host;

class FdManager {
public:
  void AddFd(int fd) {
    assert(fd >= 0);
    set_.insert(fd);
  }

  ~FdManager() {
    for (auto fd : set_) {
      ::close(fd);
    }
  }

private:
  std::set<int> set_;
};

static int RunIt(const char *ifname, const char *host, uint16_t port,
                 uint16_t port_min, uint16_t port_max) {
  char filter_expr[256];
  std::snprintf(filter_expr, sizeof(filter_expr),
                "(udp or tcp)"
                " and host %s and dst portrange %u-%u",
                host, port_min, port_max);
  // sniffer to monitor traffic to port_min-port_max
  kale::Sniffer sniffer(ifname);
  auto compile = sniffer.CompileAndInstall(filter_expr);
  if (!compile) {
    KL_ERROR(compile.Err().ToCString());
    return 1;
  }
  // epoll to recv packets from client
  auto udp_sock = kl::udp::Socket();
  if (!udp_sock) {
    KL_ERROR(udp_sock.Err().ToCString());
    return 1;
  }
  int udp_fd = *udp_sock;
  auto udp_bind = kl::inet::Bind(udp_fd, host, port);
  if (!udp_bind) {
    KL_ERROR(udp_bind.Err().ToCString());
    return 1;
  }
  kl::Epoll epoll;
  auto add_udp_fd = epoll.AddFd(udp_fd, EPOLLET | EPOLLIN);
  if (!add_udp_fd) {
    KL_ERROR(add_udp_fd.Err().ToCString());
    return 1;
  }
  // threads to run epoll and sniffer
  std::atomic<bool> stop(false);
  kl::WaitGroup wg;
  // sniffer thread
  wg.Add();
  std::thread([&sniffer, &wg, &stop, udp_fd] {
    kl::env::Defer defer([&wg, &stop] {
      stop.store(true);
      wg.Done();
    });
    struct pcap_pkthdr header;
    while (!stop) {
      const uint8_t *packet = sniffer.NextPacket(&header);
      if (packet == nullptr) {
        KL_ERROR("recv null packet");
        break;
      }
      // TODO(Kai Luo): Get ip packet and forward using udp_fd
    }
  }).detach();
  // epoll thread
  wg.Add();
  std::thread([&wg, &stop, &epoll, udp_fd] {
    kl::env::Defer defer([&wg, &stop] {
      stop.store(true);
      wg.Done();
    });
    // create raw socket to send packets
    auto raw_sock = kale::RawIPv4Socket();
    if (!raw_sock) {
      KL_ERROR(raw_sock.Err().ToCString());
      return;
    }
    int raw_fd = *raw_sock;
    defer([fd = raw_fd] { ::close(fd); });
    char buf[65536];
    while (!stop) {
      auto wait = epoll.Wait(1, -1);
      if (!wait) {
        KL_ERROR(wait.Err().ToCString());
        break;
      }
      for (const auto &event : *wait) {
        int fd = event.data.fd;
        uint32_t events = event.events;
        if (events & EPOLLIN) {
          while (true) {
            int nread = ::read(fd, buf, sizeof(buf));
            if (nread < 0) {
              if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
              }
              KL_ERROR(std::strerror(errno));
              return;
            }
            // TODO(Kai Luo): NAT and forward using raw_fd
          }
        }
        if (events & EPOLLERR) {
          int error = 0;
          socklen_t len = sizeof(error);
          if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) == 0) {
            KL_ERROR(std::strerror(error));
          } else {
            KL_ERROR("EPOLLERR");
          }
          return;
        }
      }
    }
  }).detach();
  wg.Wait();
  return 0;
}

static kl::Result<void> BindPorts(FdManager *fd_manager, const char *host,
                                  uint16_t port_min, uint16_t port_max) {
  for (uint16_t port = port_min; port <= port_max; ++port) {
    // tcp port
    auto tcp_sock = kl::tcp::Socket();
    if (!tcp_sock) {
      return kl::Err(tcp_sock.MoveErr());
    }
    auto tcp_bind = kl::inet::Bind(*tcp_sock, host, port);
    if (!tcp_bind) {
      return kl::Err(tcp_bind.MoveErr());
    }
    fd_manager->AddFd(*tcp_sock);
    // udp port
    auto udp_sock = kl::udp::Socket();
    if (!udp_sock) {
      return kl::Err(udp_sock.MoveErr());
    }
    auto udp_bind = kl::inet::Bind(*udp_sock, host, port);
    if (!udp_bind) {
      return kl::Err(udp_bind.MoveErr());
    }
    fd_manager->AddFd(*udp_sock);
  }
  return kl::Ok();
}

int main(int argc, char *argv[]) {
  std::string ifname("eth0");  // -i
  std::string host("0.0.0.0");
  uint16_t port = 4000;  // -l
  (void)port;
  uint16_t port_min = 60000, port_max = 60255;  // -r
  int opt = 0;
  while ((opt = ::getopt(argc, argv, "i:l:r:h")) != -1) {
    // TODO(Kai Luo): Commandline parse
    switch (opt) {
      case 'i': {
        ifname = optarg;
        break;
      }
      case 'h':
      default:
        ::exit(1);
    }
  }
  // Bind ports so that OS won't use these ports
  FdManager fd_manager;
  auto bind_range = BindPorts(&fd_manager, host.c_str(), port_min, port_max);
  if (!bind_range) {
    KL_ERROR(bind_range.Err().ToCString());
  }
  // TODO(Kai Luo): use iptables to drop packets towards these ports
  return RunIt(ifname.c_str(), host.c_str(), port, port_min, port_max);
}
