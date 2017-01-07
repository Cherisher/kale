// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#include <sys/socket.h>
#include <sys/types.h>

#include <stdexcept>

#include "libnet++.h"

namespace kale {
namespace libnet {

Injector::Injector(int injection_type, const char *ifname) : handle_(nullptr) {
  char dev[IFNAMSIZ];
  ::strncpy(dev, ifname, IFNAMSIZ - 1);
  handle_ = libnet_init(injection_type, dev, errbuf_);
  if (handle_ == nullptr) {
    throw std::runtime_error(errbuf_);
  }
}

void Injector::Destroy() {
  if (handle_) {
    libnet_destroy(handle_);
    handle_ = nullptr;
  }
}

Injector::~Injector() { Destroy(); }

}  // namespace libnet
}  // namespace kale
