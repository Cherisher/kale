// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#ifndef KALE_LIBNET_H_
#define KALE_LIBNET_H_
#include "error.h"
#include "libnet.h"

namespace kale {
namespace libnet {

class Injector {
public:
  Injector(int injection_type, const char *ifname);
  void Destroy();
  ~Injector();

private:
  char errbuf_[LIBNET_ERRBUF_SIZE];
  libnet_t *handle_;
};

}  // namespace libnet
}  // namespace kale
#endif
