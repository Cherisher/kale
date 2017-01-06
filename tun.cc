// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if_tun.h>

#include <cerrno>
#include <cstring>
#include <cstring>

#include "kl/netdev.h"
#include "kl/random.h"
#include "tun.h"

namespace kale {

const char *kTunDevRoot = "/dev/net/tun";

kl::Result<int> AllocateTun(const char *ifname) {
  struct ifreq ifr;
  int fd = ::open(kTunDevRoot, O_RDWR);
  if (fd < 0) {
    return kl::Err(errno, std::strerror(errno));
  }
  ::memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  if (ifname) {
    ::strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
  }
  int err = ::ioctl(fd, TUNSETIFF, static_cast<void *>(&ifr));
  if (err < 0) {
    ::close(fd);
    return kl::Err(errno, std::strerror(errno));
  }
  return kl::Ok(fd);
}

std::string RandomTunName() {
  static const int kMaxTunNum = 1024;
  int num = kMaxTunNum * kl::random::UniformSampleFloat();
  return kl::FormatString("tun%d", num);
}

kl::Result<int> AllocateTunInterface(const char *ifname, const char *addr,
                                     const char *dstaddr, const char *mask) {
  auto alloc_tun = AllocateTun(ifname);
  if (!alloc_tun) {
    return kl::Err(alloc_tun.MoveErr());
  }
  int tun_fd = *alloc_tun;
  auto set_addr = kl::netdev::SetAddress(ifname, addr);
  if (!set_addr) {
    ::close(tun_fd);
    return kl::Err(set_addr.MoveErr());
  }
  auto set_dstaddr = kl::netdev::SetDestAddress(ifname, dstaddr);
  if (!set_dstaddr) {
    ::close(tun_fd);
    return kl::Err(set_dstaddr.MoveErr());
  }
  auto set_mask = kl::netdev::SetNetMask(ifname, mask);
  if (!set_mask) {
    ::close(tun_fd);
    return kl::Err(set_mask.MoveErr());
  }
  return kl::Ok(tun_fd);
}

kl::Result<int> RawIPv4Socket() {
  int fd = ::socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (fd < 0) {
    return kl::Err(errno, "failed creating socket: %s", std::strerror(errno));
  }
  const int on = 1;
  if (::setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
    ::close(fd);
    return kl::Err(errno, std::strerror(errno));
  }
  return kl::Ok(fd);
}

}  // namespace kale
