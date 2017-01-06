// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.

#include "lo_tun.h"
#include "kl/env.h"
#include "kl/logger.h"

namespace kale {
LoTun::LoTun(const char *ifname, const char *addr, const char *dstaddr,
             const char *mask)
    : ifname_(ifname), addr_(addr), dstaddr_(dstaddr), mask_(mask),
      tun_fd_(-1) {}

void LoTun::Close() {
  if (tun_fd_ >= 0) {
    ::close(tun_fd_);
    tun_fd_ = -1;
  }
}

kl::Result<void> LoTun::EventLoop() {
  char buf[65536];
  int nread = 0, nwrite = 0;
  while (true) {
    auto wait = epoll_.Wait(1, -1);
    if (!wait) {
      return kl::Err(wait.MoveErr());
    }
    assert((*wait).size() == 1);
    const auto &event = (*wait)[0];
    assert(tun_fd_ == event.data.fd);
    uint32_t events = event.events;
    if (events & EPOLLIN) {
      nread = ::read(tun_fd_, buf, sizeof(buf));
      if (nread < 0) {
        return kl::Err(errno, std::strerror(errno));
      }
      KL_DEBUG("read %d bytes", nread);
      nwrite = ::write(tun_fd_, buf, nread);
      if (nwrite < 0) {
        return kl::Err(errno, std::strerror(errno));
      }
      assert(nread == nwrite);
      KL_DEBUG("write %d bytes", nwrite);
      nread = 0;
    }
    if (events & EPOLLHUP) {
      return kl::Err("tun_fd_ closed");
    }
    if (events & EPOLLERR) {
      return kl::Err("EPOLLERR");
    }
  }
  return kl::Ok();
}

kl::Result<void> LoTun::Run() {
  auto alloc = AllocateTunInterface(ifname_.c_str(), addr_.c_str(),
                                    dstaddr_.c_str(), mask_.c_str());
  if (!alloc) {
    return kl::Err(alloc.MoveErr());
  }
  tun_fd_ = *alloc;
  assert(tun_fd_ >= 0);
  auto nb = kl::env::SetNonBlocking(tun_fd_);
  if (!nb) {
    return kl::Err(nb.MoveErr());
  }
  auto add = epoll_.AddFd(tun_fd_, EPOLLIN);
  if (!add) {
    return kl::Err(add.MoveErr());
  }
  return EventLoop();
}

kl::Result<void> LoTun::RunWithoutEventLoop() {
  auto alloc = AllocateTunInterface(ifname_.c_str(), addr_.c_str(),
                                    dstaddr_.c_str(), mask_.c_str());
  if (!alloc) {
    return kl::Err(alloc.MoveErr());
  }
  tun_fd_ = *alloc;
  assert(tun_fd_ >= 0);
  auto nb = kl::env::SetNonBlocking(tun_fd_);
  if (!nb) {
    return kl::Err(nb.MoveErr());
  }
  auto add = epoll_.AddFd(tun_fd_, EPOLLIN);
  if (!add) {
    return kl::Err(add.MoveErr());
  }
  return kl::Ok();
}

LoTun::~LoTun() { Close(); }

}  // namespace kale
