// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#ifndef KALE_PCAP_H_
#define KALE_PCAP_H_
#include <string>

#include "kl/error.h"
#include "pcap/pcap.h"

namespace kale {
namespace pcap {

inline kl::Result<std::string> DefaultDevice() {
  char *dev, errbuf[PCAP_ERRBUF_SIZE];
  dev = pcap_lookupdev(errbuf);
  if (dev == nullptr) {
    return kl::Err("Couldn't find default device: %s\n", errbuf);
  }
  return kl::Ok(std::string(dev));
}

}  // namespace pcap
}  // namespace
#endif
