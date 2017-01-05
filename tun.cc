// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include <cerrno>
#include <cstring>
#include <cstring>

#include "kl/random.h"
#include "tun.h"

namespace kale {
namespace {
const int kMaxTunNum = 1024;
}
const char *kTunDevRoot = "/dev/net/tun";
kl::Result<std::tuple<int, std::string>> AllocateTun(const char *ifname) {
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
  return kl::Ok(std::make_tuple(fd, std::string(ifr.ifr_name)));
}

std::string RandomTunName() {
  int num = kMaxTunNum * kl::random::UniformSampleFloat();
  return kl::FormatString("tun%d", num);
}

}  // namespace kale
