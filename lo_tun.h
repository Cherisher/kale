// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#ifndef KALE_LO_TUN_H
#define KALE_LO_TUN_H
#include "kl/epoll.h"
#include "kl/error.h"
#include "tun.h"

namespace kale {
class LoTun {
public:
  LoTun() = delete;
  LoTun(const LoTun &) = delete;
  LoTun(LoTun &&) = default;
  LoTun(const char *ifname, const char *addr, const char *dstaddr,
        const char *mask);
  virtual kl::Result<void> Run();
  virtual ~LoTun();

protected:
  kl::Result<void> RunWithoutEventLoop();
  virtual kl::Result<void> EventLoop();

private:
  void Close();
  std::string ifname_, addr_, dstaddr_, mask_;
  int tun_fd_;
  kl::Epoll epoll_;
};

}  // namespace kale
#endif
