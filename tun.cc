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
#include "kl/string.h"
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
  return kl::string::FormatString("tun%d", num);
}

kl::Result<int> RawIPv4Socket() {
  int fd = ::socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (fd < 0) {
    return kl::Err(errno, "failed creating socket: %s", std::strerror(errno));
  }
  return kl::Ok(fd);
}

}  // namespace kale
