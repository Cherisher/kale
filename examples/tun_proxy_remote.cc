// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#include <unistd.h>

#include <atomic>
#include <cstdlib>
#include <map>
#include <set>
#include <string>
#include <thread>

#include "ip_packet.h"
#include "kl/bitset.h"
#include "kl/env.h"
#include "kl/epoll.h"
#include "kl/inet.h"
#include "kl/logger.h"
#include "kl/tcp.h"
#include "kl/udp.h"
#include "kl/wait_group.h"
#include "snappy/snappy.h"
#include "sniffer.h"
#include "tun.h"

// For NAT
// In host byte order
static std::map<uint16_t, std::string> udp_port_to_host;
static std::map<std::string, uint16_t> udp_host_to_port;
static std::map<uint16_t, std::string> tcp_port_to_host;
static std::map<std::string, uint16_t> tcp_host_to_port;
static kl::BitSet udp_port_allocator(65536);
static kl::BitSet tcp_port_allocator(65536);

namespace {
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
}

static int AllocateUDPPort(uint16_t port_min, uint16_t port_max) {
  int n = udp_port_allocator.SetFirstZeroBit();
  if (n < 0) {
    return n;
  }
  if (n + port_min > port_max) {
    udp_port_allocator.Clear(n);
    return -1;
  }
  return n + port_min;
}

static int AllocateTCPPort(uint16_t port_min, uint16_t port_max) {
  int n = tcp_port_allocator.SetFirstZeroBit();
  if (n < 0) {
    return n;
  }
  if (n + port_min > port_max) {
    tcp_port_allocator.Clear(n);
    return -1;
  }
  return n + port_min;
}

static void IPPacket(int datalink, struct pcap_pkthdr *header,
                     const uint8_t *packet, const uint8_t **ip, size_t *len) {
  switch (datalink) {
    case DLT_EN10MB:
      *ip = packet + 14;
      *len = header->len - 14;
      return;
    case DLT_SLIP:
    case DLT_PPP:
      *ip = packet + 24;
      *len = header->len - 24;
      return;
    case DLT_NULL:
      *ip = packet + 4;
      *len = header->len - 4;
      return;
    default:
      throw std::runtime_error("unrecognized datalink type");
  }
}

static int RunIt(const char *ifname, const char *host, uint16_t port,
                 uint16_t port_min, uint16_t port_max, const char *peer_host,
                 uint16_t peer_port) {
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
  std::thread([&sniffer, &wg, &stop, udp_fd, peer_host, peer_port] {
    kl::env::Defer defer([&wg, &stop] {
      stop.store(true);
      wg.Done();
    });
    struct pcap_pkthdr header;
    char buf[65536];
    while (!stop) {
      const uint8_t *raw_packet = sniffer.NextPacket(&header);
      if (raw_packet == nullptr) {
        KL_ERROR("recv null packet");
        // FIXME(Kai Luo): continue or break?
        break;
      }
      // Skip truncated packets
      if (header.len != header.caplen) {
        continue;
      }
      // Get ip packet and forward using udp_fd
      struct sockaddr_in addr;
      std::string dst_host;
      uint16_t dst_port;
      const uint8_t *ip_base = nullptr;
      size_t len = 0;
      IPPacket(sniffer.DataLink(), &header, raw_packet, &ip_base, &len);
      assert(ip_base != nullptr);
      assert(len <= sizeof(buf));
      uint8_t *packet = reinterpret_cast<uint8_t *>(buf);
      ::memcpy(packet, ip_base, len);
      if (kale::ip_packet::IsTCP(packet, len)) {
        uint16_t port = ntohs(kale::ip_packet::TCPDstPort(packet, len));
        if (!tcp_port_to_host.count(port)) {
          continue;
        }
        kl::inet::SplitAddr(tcp_port_to_host[port].c_str(), &dst_host,
                            &dst_port);
        addr = *kl::inet::InetSockAddr(dst_host.c_str(), dst_port);
        kale::ip_packet::ChangeDstAddr(packet, len, addr.sin_addr.s_addr);
        kale::ip_packet::ChangeTCPDstPort(packet, len, addr.sin_port);
        kale::ip_packet::TCPFillChecksum(packet, len);
        kale::ip_packet::IPFillChecksum(packet, len);
      } else if (kale::ip_packet::IsUDP(packet, len)) {
        uint16_t port = ntohs(kale::ip_packet::UDPDstPort(packet, len));
        if (!udp_port_to_host.count(port)) {
          continue;
        }
        kl::inet::SplitAddr(udp_port_to_host[port].c_str(), &dst_host,
                            &dst_port);
        addr = *kl::inet::InetSockAddr(dst_host.c_str(), dst_port);
        kale::ip_packet::ChangeDstAddr(packet, len, addr.sin_addr.s_addr);
        kale::ip_packet::ChangeUDPDstPort(packet, len, addr.sin_port);
        kale::ip_packet::UDPFillChecksum(packet, len);
        kale::ip_packet::IPFillChecksum(packet, len);
      }
      // send back to client
      std::string compress;
      size_t n = snappy::Compress(reinterpret_cast<const char *>(packet), len,
                                  &compress);
      (void)n;
      auto send = kl::inet::Sendto(udp_fd, compress.data(), compress.size(), 0,
                                   peer_host, peer_port);
      if (!send) {
        KL_ERROR(send.Err().ToCString());
      }
    }
  }).detach();
  // epoll thread
  wg.Add();
  std::thread([&wg, &stop, &epoll, udp_fd, host, port_min, port_max] {
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
            // NAT and forward using raw_fd
            std::string uncompress;
            bool ok = snappy::Uncompress(buf, nread, &uncompress);
            if (!ok) {
              KL_ERROR("failed to uncompress buf");
              continue;
            }
            assert(uncompress.size() <= sizeof(buf));
            ::memcpy(buf, uncompress.data(), uncompress.size());
            uint8_t *packet = reinterpret_cast<uint8_t *>(buf);
            size_t len = uncompress.size();
            if (kale::ip_packet::IsTCP(packet, len)) {
              uint16_t port = ntohs(kale::ip_packet::TCPSrcPort(packet, len));
              struct in_addr in {
                .s_addr = kale::ip_packet::SrcAddr(packet, len),
              };
              std::string s =
                  kl::string::FormatString("%s:%u", inet_ntoa(in), port);
              int local_port = -1;
              if (!tcp_host_to_port.count(s)) {
                local_port = AllocateTCPPort(port_min, port_max);
                if (local_port < 0) {
                  KL_ERROR("failed to allocate tcp port");
                  continue;
                }
                tcp_host_to_port[s] = local_port;
                tcp_port_to_host[local_port] = s;
              } else {
                local_port = tcp_host_to_port[s];
              }
              assert(local_port >= 0);
              inet_aton(host, &in);
              kale::ip_packet::ChangeSrcAddr(packet, len, in.s_addr);
              kale::ip_packet::ChangeTCPSrcPort(packet, len, htons(local_port));
              kale::ip_packet::TCPFillChecksum(packet, len);
              kale::ip_packet::IPFillChecksum(packet, len);
              int nwrite = ::write(raw_fd, packet, len);
              if (nwrite < 0) {
                KL_ERROR(std::strerror(errno));
                continue;
              }
            } else if (kale::ip_packet::IsUDP(packet, len)) {
              uint16_t port = ntohs(kale::ip_packet::UDPSrcPort(packet, len));
              struct in_addr in {
                .s_addr = kale::ip_packet::SrcAddr(packet, len),
              };
              std::string s =
                  kl::string::FormatString("%s:%u", inet_ntoa(in), port);
              int local_port = -1;
              if (!udp_host_to_port.count(s)) {
                local_port = AllocateUDPPort(port_min, port_max);
                if (local_port < 0) {
                  KL_ERROR("failed to allocate tcp port");
                  continue;
                }
                udp_host_to_port[s] = local_port;
                udp_port_to_host[local_port] = s;
              } else {
                local_port = udp_host_to_port[s];
              }
              assert(local_port >= 0);
              inet_aton(host, &in);
              kale::ip_packet::ChangeSrcAddr(packet, len, in.s_addr);
              kale::ip_packet::ChangeUDPSrcPort(packet, len, htons(local_port));
              kale::ip_packet::UDPFillChecksum(packet, len);
              kale::ip_packet::IPFillChecksum(packet, len);
              int nwrite = ::write(raw_fd, packet, len);
              if (nwrite < 0) {
                KL_ERROR(std::strerror(errno));
                continue;
              }
            }
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
  std::string peer_host;
  uint16_t peer_port = 0;                       // -p
  uint16_t port_min = 60000, port_max = 60255;  // -r
  int opt = 0;
  while ((opt = ::getopt(argc, argv, "i:l:r:p:h")) != -1) {
    // TODO(Kai Luo): Commandline parse
    switch (opt) {
      case 'i': {
        ifname = optarg;
        break;
      }
      case 'l': {
        auto split = kl::inet::SplitAddr(optarg, &host, &port);
        assert(split);
        break;
      }
      case 'p': {
        auto split = kl::inet::SplitAddr(optarg, &peer_host, &peer_port);
        assert(split);
        break;
      }
      case 'r': {
        auto split = kl::string::SplitString(optarg, ":");
        assert(split.size() == 2);
        port_min = atoi(split[0].c_str());
        port_max = atoi(split[1].c_str());
        assert(port_min <= port_max);
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
  return RunIt(ifname.c_str(), host.c_str(), port, port_min, port_max,
               peer_host.c_str(), peer_port);
}
