// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
// Use of this source code is governed by the BSD license that can be found in
// the LICENSE file.

#include <unistd.h>

#include <atomic>
#include <cstdlib>
#include <map>
#include <set>
#include <string>
#include <thread>

#include "arcfour.h"
#include "coding.h"
#include "demo_coding.h"
#include "ip_packet.h"
#include "kl/env.h"
#include "kl/epoll.h"
#include "kl/inet.h"
#include "kl/logger.h"
#include "kl/random.h"
#include "kl/rwlock.h"
#include "kl/string.h"
#include "kl/tcp.h"
#include "kl/udp.h"
#include "kl/wait_group.h"
#include "lru.h"
#include "sniffer.h"
#include "tun.h"

namespace {

kl::Status InsertIptablesRules(uint16_t port_min, uint16_t port_max) {
  static const char *kCheckRule = "iptables -C INPUT -s 0.0.0.0/0.0.0.0 -p %s "
                                  "--dport %u -j DROP 2> /dev/null";
  static const char *kInsertCommand = "iptables -A INPUT -s 0.0.0.0/0.0.0.0 -p "
                                      "%s --dport %u -j DROP 2> /dev/null";
  for (uint16_t i = port_min; i <= port_max; ++i) {
    auto check = kl::string::FormatString(kCheckRule, "udp", i);
    int ok = ::system(check.c_str());
    if (ok == 0) {
      continue;
    }
    auto insert = kl::string::FormatString(kInsertCommand, "udp", i);
    ok = ::system(insert.c_str());
    if (ok != 0) {
      return kl::Err("failed insert udp rule --dport %u DROP", i);
    }
  }
  for (uint16_t i = port_min; i <= port_max; ++i) {
    auto check = kl::string::FormatString(kCheckRule, "tcp", i);
    int ok = ::system(check.c_str());
    if (ok == 0) {
      continue;
    }
    auto command = kl::string::FormatString(kInsertCommand, "tcp", i);
    ok = ::system(command.c_str());
    if (ok != 0) {
      return kl::Err("failed insert tcp rule --dport %u DROP", i);
    }
  }
  return kl::Ok();
}

void StatTCP(const uint8_t *packet, size_t len) {
  const uint8_t *segment = kale::ip_packet::SegmentBase(packet, len);
  uint16_t actual_checksum = *reinterpret_cast<const uint16_t *>(segment + 16);
  uint16_t calculated_checksum = kale::ip_packet::TCPChecksum(packet, len);
  if (actual_checksum != calculated_checksum) {
    KL_ERROR("actual checksum: %u, calculated checksum: %u", actual_checksum,
             calculated_checksum);
    return;
  }
  KL_DEBUG("tcp segment, src addr %s, dst addr %s, data length: %u",
           kale::ip_packet::TCPSrcAddr(packet, len).c_str(),
           kale::ip_packet::TCPDstAddr(packet, len).c_str(),
           kale::ip_packet::TCPDataLength(packet, len));
}

void StatUDP(const uint8_t *packet, size_t len) {
  const uint8_t *segment = kale::ip_packet::SegmentBase(packet, len);
  uint16_t actual_checksum = *reinterpret_cast<const uint16_t *>(segment + 6);
  uint16_t calculated_checksum = kale::ip_packet::UDPChecksum(packet, len);
  if (actual_checksum != calculated_checksum) {
    KL_ERROR("actual checksum: %u, calculated checksum: %u", actual_checksum,
             calculated_checksum);
    return;
  }
  KL_DEBUG("udp segment, src addr %s, dst addr %s, data length: %u",
           kale::ip_packet::UDPSrcAddr(packet, len).c_str(),
           kale::ip_packet::UDPDstAddr(packet, len).c_str(),
           kale::ip_packet::UDPDataLength(packet, len));
}

void StatIPPacket(const uint8_t *packet, size_t len) {
  uint16_t actual_checksum = *reinterpret_cast<const uint16_t *>(packet + 10);
  uint16_t calculated_checksum = kale::ip_packet::IPHeaderChecksum(packet, len);
  if (actual_checksum != calculated_checksum) {
    KL_ERROR("actual checksum: %u, calculated checksum: %u", actual_checksum,
             calculated_checksum);
    return;
  }
  if (kale::ip_packet::IsTCP(packet, len)) {
    StatTCP(packet, len);
  }
  if (kale::ip_packet::IsUDP(packet, len)) {
    StatUDP(packet, len);
  }
}

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

const char *kHostAddrFormat = "%s:%u:%s:%u";

// Tow Level NAT
// <peer_addr>:<subnet_addr> -> local_port
// local_port -> <peer_addr>:<subnet_addr>
class NAT {
public:
  NAT(uint16_t port_min, uint16_t port_max)
      : port_min_(port_min), port_max_(port_max),
        lru_(port_max - port_min + 1) {}

  // RETURNS: local port allocated
  kl::Result<uint16_t> AddEntry(const char *peer_addr, uint16_t peer_port,
                                const char *subnet_addr, uint16_t subnet_port) {
    int local_port = AllocatePort();
    if (local_port < 0) {
      return kl::Err("failed to allocate port");
    }
    uint16_t port = local_port;
    std::string host(kl::string::FormatString(
        kHostAddrFormat, peer_addr, peer_port, subnet_addr, subnet_port));
    host_to_port_[host] = port;
    port_to_host_[port] = std::move(host);
    return kl::Ok(port);
  }

  kl::Result<uint16_t> QueryPort(const char *peer_addr, uint16_t peer_port,
                                 const char *subnet_addr,
                                 uint16_t subnet_port) {
    std::string host(kl::string::FormatString(
        kHostAddrFormat, peer_addr, peer_port, subnet_addr, subnet_port));
    auto iter = host_to_port_.find(host);
    if (iter == host_to_port_.end()) {
      return kl::Err("failed to find port");
    }
    return kl::Ok(iter->second);
  }

  kl::Result<std::tuple<std::string, uint16_t>> QueryPeer(uint16_t port) {
    auto iter = port_to_host_.find(port);
    if (iter == port_to_host_.end()) {
      return kl::Err("no such entry");
    }
    lru_.Use(port);
    auto split = kl::string::SplitString(iter->second.c_str(), ":");
    assert(split.size() == 4);
    return kl::Ok(std::make_tuple(
        std::move(split[0]), static_cast<uint16_t>(atoi(split[1].c_str()))));
  }

  kl::Result<std::tuple<std::string, uint16_t>> QuerySubnet(uint16_t port) {
    auto iter = port_to_host_.find(port);
    if (iter == port_to_host_.end()) {
      return kl::Err("no such entry");
    }
    lru_.Use(port);
    auto split = kl::string::SplitString(iter->second.c_str(), ":");
    assert(split.size() == 4);
    return kl::Ok(std::make_tuple(
        std::move(split[2]), static_cast<uint16_t>(atoi(split[3].c_str()))));
  }

  kl::Result<std::tuple<std::string, uint16_t, std::string, uint16_t>>
  QueryHost(uint16_t port) {
    auto iter = port_to_host_.find(port);
    if (iter == port_to_host_.end()) {
      return kl::Err("no such entry");
    }
    lru_.Use(port);
    auto split = kl::string::SplitString(iter->second.c_str(), ":");
    assert(split.size() == 4);
    return kl::Ok(std::make_tuple(
        std::move(split[0]), static_cast<uint16_t>(atoi(split[1].c_str())),
        std::move(split[2]), static_cast<uint16_t>(atoi(split[3].c_str()))));
  }

private:
  int AllocatePort() {
    int n = port_min_ + lru_.GetLRU();
    assert(n >= port_min_ && n <= port_max_);
    return n;
  }
  uint16_t port_min_, port_max_;
  kale::LRU lru_;
  std::map<uint16_t, std::string> port_to_host_;
  std::map<std::string, uint16_t> host_to_port_;
};

class Proxy {
public:
  Proxy(const char *ifname, const char *local_addr, uint16_t local_port,
        uint16_t port_min, uint16_t port_max)
      : stop_(false), ifname_(ifname), addr_(local_addr), port_min_(port_min),
        port_max_(port_max), port_(local_port), udp_nat_(port_min, port_max),
        tcp_nat_(port_min, port_max), sniffer_(ifname),
        coding_(kale::DemoCoding()), write_raw_fd_dropped_(0),
        write_udp_fd_dropped_(0) {
    inet_aton(addr_.c_str(), &in_addr_);
  }

  kl::Result<void> Run() {
    auto create = CreateSocket();
    if (!create) {
      return create;
    }
    kl::env::Defer defer([this] { DestroySocket(); });
    LaunchSnifferThread();
    LaunchEpollThread();
    sync_.Wait();
    if (!exit_reason_.empty()) {
      return kl::Err(std::move(exit_reason_));
    }
    return kl::Ok();
  }

private:
  void EpollWaitAndHandle();
  void SnifferWaitAndHandle();
  void SnifferSendBack(const char *addr, uint16_t port, const char *buf,
                       size_t len);

  static void FindIPPacket(int datalink, struct pcap_pkthdr *header,
                           uint8_t *packet, uint8_t **ip, size_t *len) {
    switch (datalink) {
      case DLT_LINUX_SLL:
        *ip = packet + 16;
        *len = header->len - 16;
        return;
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
        KL_ERROR("unrecognized datalink type: %d", datalink);
    }
  }

  kl::Result<void> CreateSocket() {
    udp_fd_ = *kl::udp::Socket();
    kl::env::SetNonBlocking(udp_fd_);
    auto bind = kl::inet::Bind(udp_fd_, addr_.c_str(), port_);
    if (!bind) {
      ::close(udp_fd_);
      return bind;
    }
    raw_fd_ = *kale::RawIPv4Socket();
    kl::env::SetNonBlocking(raw_fd_);
    return kl::Ok();
  }

  void DestroySocket() {
    ::close(raw_fd_);
    ::close(udp_fd_);
  }

  void SetExitReason(const char *reason) {
    mutex_.lock();
    exit_reason_ = reason;
    mutex_.unlock();
  }

  void LaunchSnifferThread() {
    sync_.Add();
    std::thread([this] {
      kl::env::Defer defer([this] {
        stop_.store(true);
        sync_.Done();
      });
      char filter_expr[1024];
      std::snprintf(filter_expr, sizeof(filter_expr),
                    "(udp or tcp) and host %s and dst portrange %u-%u",
                    addr_.c_str(), port_min_, port_max_);
      auto compile = sniffer_.CompileAndInstall(filter_expr);
      if (!compile) {
        KL_ERROR(compile.Err().ToCString());
        Stop(compile.Err().ToCString());
        return;
      }
      while (!stop_) {
        SnifferWaitAndHandle();
      }
    }).detach();
  }

  void Stop(const char *err) {
    stop_.store(true);
    SetExitReason(err);
  }

  void LaunchEpollThread() {
    sync_.Add();
    std::thread([this] {
      kl::env::Defer defer([this] {
        stop_.store(true);
        sync_.Done();
      });
      auto init_epoll = InitEpoll();
      if (!init_epoll) {
        SetExitReason(init_epoll.Err().ToCString());
        return;
      }
      while (!stop_) {
        EpollWaitAndHandle();
      }
    }).detach();
  }

  void SnifferHandleTCP(uint8_t *packet, size_t len);
  void SnifferHandleUDP(uint8_t *packet, size_t len);
  void EpollHandleTCP(const char *peer_addr, uint16_t peer_port,
                      uint8_t *packet, size_t len);
  void EpollHandleUDP(const char *peer_addr, uint16_t peer_port,
                      uint8_t *packet, size_t len);
  void OnUDPRecvFromPeer();

  void Stop() { stop_.store(true); }

  kl::Result<void> InitEpoll() {
    auto add_udp = epoll_.AddFd(udp_fd_, EPOLLET | EPOLLIN);
    if (!add_udp) {
      return add_udp;
    }
    return kl::Ok();
  }

  std::mutex mutex_;
  std::atomic<bool> stop_;
  std::string ifname_, addr_, exit_reason_;
  uint16_t port_min_, port_max_;
  struct in_addr in_addr_;
  uint16_t port_;
  NAT udp_nat_, tcp_nat_;
  kale::Sniffer sniffer_;
  kl::WaitGroup sync_;
  kl::Epoll epoll_;
  // Used to communicate with peer
  int udp_fd_;
  // Used to send IPv4 packets to inet host
  int raw_fd_;
  // kale::arcfour::Cipher cipher_;
  kale::Coding coding_;
  uint64_t write_raw_fd_dropped_;
  uint64_t write_udp_fd_dropped_;
};

void Proxy::EpollHandleTCP(const char *peer_addr, uint16_t peer_port,
                           uint8_t *packet, size_t len) {
  std::string subnet_addr(inet_ntoa(in_addr{
      .s_addr = kale::ip_packet::SrcAddr(packet, len),
  }));
  uint16_t subnet_port = ntohs(kale::ip_packet::TCPSrcPort(packet, len));
  auto query = tcp_nat_.QueryPort(peer_addr, peer_port, subnet_addr.c_str(),
                                  subnet_port);
  uint16_t port = 0;
  if (!query) {
    auto add = tcp_nat_.AddEntry(peer_addr, peer_port, subnet_addr.c_str(),
                                 subnet_port);
    if (!add) {
      return;
    }
    port = *add;
  } else {
    port = *query;
  }
  assert(port > 0);
  kale::ip_packet::ChangeSrcAddr(packet, len, in_addr_.s_addr);
  kale::ip_packet::ChangeTCPSrcPort(packet, len, htons(port));
  kale::ip_packet::TCPFillChecksum(packet, len);
  kale::ip_packet::IPFillChecksum(packet, len);
  std::string dst_addr(inet_ntoa(in_addr{
      .s_addr = kale::ip_packet::DstAddr(packet, len),
  }));
  uint16_t dst_port = ntohs(kale::ip_packet::TCPDstPort(packet, len));
  KL_DEBUG("tcp segment from host %s:%u's subnet  %s:%u -> %s:%u now is %s:%u "
           "-> %s:%u",
           peer_addr, peer_port, subnet_addr.c_str(), subnet_port,
           dst_addr.c_str(), dst_port, addr_.c_str(), port, dst_addr.c_str(),
           dst_port);
  auto send =
      kl::inet::Sendto(raw_fd_, packet, len, 0, dst_addr.c_str(), dst_port);
  // record number of packets dropped
  if (!send &&
      (send.Err().Code() == EAGAIN || send.Err().Code() == EWOULDBLOCK)) {
    uint64_t tmp = ++write_raw_fd_dropped_;
    KL_ERROR("current write_raw_fd_dropped_: %u", tmp);
  }
  if (!send && send.Err().Code() != EAGAIN &&
      send.Err().Code() != EWOULDBLOCK) {
    KL_ERROR(send.Err().ToCString());
  }
}

void Proxy::EpollHandleUDP(const char *peer_addr, uint16_t peer_port,
                           uint8_t *packet, size_t len) {
  std::string subnet_addr(inet_ntoa(in_addr{
      .s_addr = kale::ip_packet::SrcAddr(packet, len),
  }));
  uint16_t subnet_port = ntohs(kale::ip_packet::UDPSrcPort(packet, len));
  auto query = udp_nat_.QueryPort(peer_addr, peer_port, subnet_addr.c_str(),
                                  subnet_port);
  uint16_t port = 0;
  if (!query) {
    auto add = udp_nat_.AddEntry(peer_addr, peer_port, subnet_addr.c_str(),
                                 subnet_port);
    if (!add) {
      return;
    }
    port = *add;
  } else {
    port = *query;
  }
  assert(port > 0);
  kale::ip_packet::ChangeSrcAddr(packet, len, in_addr_.s_addr);
  kale::ip_packet::ChangeUDPSrcPort(packet, len, htons(port));
  kale::ip_packet::UDPFillChecksum(packet, len);
  kale::ip_packet::IPFillChecksum(packet, len);
  std::string dst_addr(inet_ntoa(in_addr{
      .s_addr = kale::ip_packet::DstAddr(packet, len),
  }));
  uint16_t dst_port = ntohs(kale::ip_packet::UDPDstPort(packet, len));
  KL_DEBUG("udp segment from host %s:%u's subnet  %s:%u -> %s:%u now is %s:%u "
           "-> %s:%u",
           peer_addr, peer_port, subnet_addr.c_str(), subnet_port,
           dst_addr.c_str(), dst_port, addr_.c_str(), port, dst_addr.c_str(),
           dst_port);
  auto send =
      kl::inet::Sendto(raw_fd_, packet, len, 0, dst_addr.c_str(), dst_port);
  if (!send && send.Err().Code() != EAGAIN &&
      send.Err().Code() != EWOULDBLOCK) {
    KL_ERROR(send.Err().ToCString());
  }
}

void Proxy::OnUDPRecvFromPeer() {
  // read until EAGAIN or EWOULDBLOCK
  char buf[65536];
  while (true) {
    auto recv = kl::inet::RecvFrom(udp_fd_, buf, sizeof(buf), 0);
    if (!recv) {
      if (recv.Err().Code() == EAGAIN || recv.Err().Code() == EWOULDBLOCK) {
        break;
      }
      KL_ERROR(recv.Err().ToCString());
      Stop(recv.Err().ToCString());
      return;
    }
    int nread = std::get<0>(*recv);
    assert(nread >= 0);
    std::string &peer_addr = std::get<1>(*recv);
    uint32_t peer_port = std::get<2>(*recv);
    std::vector<uint8_t> data;
    auto ok =
        coding_.Decode(reinterpret_cast<const uint8_t *>(buf), nread, &data);
    if (!ok) {
      KL_ERROR(ok.Err().ToCString());
      break;
    }
    assert(data.size() <= sizeof(buf));
    ::memcpy(buf, data.data(), data.size());
    uint8_t *packet = reinterpret_cast<uint8_t *>(buf);
    const size_t len = data.size();
    if (kale::ip_packet::IsTCP(packet, len)) {
      EpollHandleTCP(peer_addr.c_str(), peer_port, packet, len);
    } else if (kale::ip_packet::IsUDP(packet, len)) {
      EpollHandleUDP(peer_addr.c_str(), peer_port, packet, len);
    }
  }
}

void Proxy::EpollWaitAndHandle() {
  // wait for only udp_fd_
  auto wait = epoll_.Wait(1, -1);
  if (!wait) {
    KL_ERROR(wait.Err().ToCString());
    Stop(wait.Err().ToCString());
    return;
  }
  assert((*wait).size() == 1);
  auto &event = (*wait)[0];
  int fd = event.data.fd;
  assert(fd == udp_fd_);
  uint32_t events = event.events;
  if (events & EPOLLIN) {
    OnUDPRecvFromPeer();
  }
  if (events & EPOLLERR) {
    int error = 0;
    socklen_t len = sizeof(error);
    if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) == 0) {
      KL_ERROR(std::strerror(error));
    } else {
      KL_ERROR("EPOLLERR");
    }
  }
}

void Proxy::SnifferWaitAndHandle() {
  struct pcap_pkthdr header;
  char buf[65536];
  const uint8_t *raw_packet = sniffer_.NextPacket(&header);
  if (raw_packet == nullptr) {
    // KL_ERROR("recv NULL packet");
    // stop or continue
    return;
  }
  // ignore truncated packet
  if (header.len != header.caplen) {
    KL_ERROR("truncated packet, header.len %d, header.caplen %d", header.len,
             header.caplen);
    return;
  }
  // ignore too long packet
  if (header.len > sizeof(buf)) {
    KL_ERROR("too long packet: %d", header.len);
    return;
  }
  ::memcpy(buf, raw_packet, header.len);
  uint8_t *packet = nullptr;
  size_t len;
  FindIPPacket(sniffer_.DataLink(), &header, reinterpret_cast<uint8_t *>(buf),
               &packet, &len);
  // ignore unrecognized datalink
  if (packet == nullptr) {
    return;
  }
  if (kale::ip_packet::IsTCP(packet, len)) {
    SnifferHandleTCP(packet, len);
  } else if (kale::ip_packet::IsUDP(packet, len)) {
    SnifferHandleUDP(packet, len);
  }
}

void Proxy::SnifferSendBack(const char *addr, uint16_t port, const char *buf,
                            size_t len) {
  std::vector<uint8_t> data;
  coding_.Encode(reinterpret_cast<const uint8_t *>(buf), len, &data);
  auto send =
      kl::inet::Sendto(udp_fd_, data.data(), data.size(), 0, addr, port);
  // record number of packets dropped
  if (!send &&
      (send.Err().Code() == EAGAIN || send.Err().Code() == EWOULDBLOCK)) {
    uint64_t tmp = ++write_udp_fd_dropped_;
    KL_ERROR("current write_udp_fd_dropped_: %u", tmp);
  }
  if (!send && send.Err().Code() != EAGAIN &&
      send.Err().Code() != EWOULDBLOCK) {
    KL_ERROR(send.Err().ToCString());
  }
}

void Proxy::SnifferHandleTCP(uint8_t *packet, size_t len) {
  uint16_t port = ntohs(kale::ip_packet::TCPDstPort(packet, len));
  auto query = tcp_nat_.QueryHost(port);
  if (!query) {
    return;
  }
  auto &host = *query;
  // peer for sending across inet
  std::string &peer_addr = std::get<0>(host);
  uint16_t peer_port = std::get<1>(host);
  // subnet for client to send packet to right tun user
  std::string &subnet_addr = std::get<2>(host);
  uint16_t subnet_port = std::get<3>(host);
  // Modify essential tcp info
  struct sockaddr_in addr =
      *kl::inet::InetSockAddr(subnet_addr.c_str(), subnet_port);
  kale::ip_packet::ChangeDstAddr(packet, len, addr.sin_addr.s_addr);
  kale::ip_packet::ChangeTCPDstPort(packet, len, htons(subnet_port));
  kale::ip_packet::TCPFillChecksum(packet, len);
  kale::ip_packet::IPFillChecksum(packet, len);
  // Sending back to client
  StatIPPacket(packet, len);
  SnifferSendBack(peer_addr.c_str(), peer_port,
                  reinterpret_cast<const char *>(packet), len);
}

void Proxy::SnifferHandleUDP(uint8_t *packet, size_t len) {
  uint16_t port = ntohs(kale::ip_packet::UDPDstPort(packet, len));
  auto query = udp_nat_.QueryHost(port);
  if (!query) {
    return;
  }
  auto &host = *query;
  std::string &peer_addr = std::get<0>(host);
  uint16_t peer_port = std::get<1>(host);
  std::string &subnet_addr = std::get<2>(host);
  uint16_t subnet_port = std::get<3>(host);
  struct sockaddr_in addr =
      *kl::inet::InetSockAddr(subnet_addr.c_str(), subnet_port);
  kale::ip_packet::ChangeDstAddr(packet, len, addr.sin_addr.s_addr);
  kale::ip_packet::ChangeUDPDstPort(packet, len, htons(subnet_port));
  kale::ip_packet::UDPFillChecksum(packet, len);
  kale::ip_packet::IPFillChecksum(packet, len);
  // Sending back to client
  StatIPPacket(packet, len);
  SnifferSendBack(peer_addr.c_str(), peer_port,
                  reinterpret_cast<const char *>(packet), len);
}

kl::Result<void> BindPortRange(FdManager *fd_manager, const char *host,
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
}  // namespace (anonymous)

static void PrintUsage(int argc, char *argv[]) {
  std::fprintf(stderr,
               "%s:\n"
               "    -l <local_host:local_port> local listen address\n"
               "    -i <ifname> interface connected to inet\n"
               "    -r <port_start-port_end> port range to be reserved\n"
               "    -d daemon\n"
               "    -o <logfile> logfile\n",
               argv[0]);
}

int main(int argc, char *argv[]) {
  std::string ifname("eth0");  // -i
  std::string host("0.0.0.0");
  uint16_t port = 4000;                         // -l
  uint16_t port_min = 60000, port_max = 60255;  // -r
  std::string log_file;                         // -o
  bool daemonize = false;                       // -d
  kl::env::Defer defer;                         // for some clean work
  int opt = 0;
  while ((opt = ::getopt(argc, argv, "i:l:r:o:hd")) != -1) {
    switch (opt) {
      case 'o':
        log_file = optarg;
        break;
      case 'd': {
        daemonize = true;
        break;
      }
      case 'i': {
        ifname = optarg;
        break;
      }
      case 'l': {
        auto split = kl::inet::SplitAddr(optarg, &host, &port);
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
        PrintUsage(argc, argv);
        ::exit(1);
    }
  }
  // daemonize
  if (daemonize) {
    int err = ::daemon(1, 1);
    if (err < 0) {
      KL_ERROR(std::strerror(errno));
      ::exit(1);
    }
  }
  // Bind ports so that OS won't use these ports
  FdManager fd_manager;
  auto bind_range =
      BindPortRange(&fd_manager, host.c_str(), port_min, port_max);
  if (!bind_range) {
    KL_ERROR(bind_range.Err().ToCString());
  }
  auto insert = InsertIptablesRules(port_min, port_max);
  if (!insert) {
    KL_ERROR(insert.Err().ToCString());
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
  Proxy proxy(ifname.c_str(), host.c_str(), port, port_min, port_max);
  auto run = proxy.Run();
  if (!run) {
    KL_ERROR(run.Err().ToCString());
    ::exit(1);
  }
  return 0;
}
