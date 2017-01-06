// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#include <net/if.h>

#include <cstring>
#include <stdexcept>

#include "pcap++.h"

namespace kale {
namespace pcap {

Sniffer::Sniffer(const char *ifname) : ifname_(ifname), handle_(nullptr) {
  char dev[IFNAMSIZ], errbuf[PCAP_ERRBUF_SIZE];
  ::strncpy(dev, ifname, IFNAMSIZ - 1);
  int err = pcap_lookupnet(dev, &net_, &mask_, errbuf);
  if (err < 0) {
    throw std::runtime_error(errbuf);
  }
  handle_ = pcap_open_live(dev, BUFSIZ, 1, 1024, errbuf);
  if (handle_ == nullptr) {
    throw std::runtime_error(errbuf);
  }
}

void Sniffer::Close() {
  if (handle_) {
    pcap_close(handle_);
    handle_ = nullptr;
  }
}

kl::Result<void> Sniffer::CompileAndInstall(const char *filter_expr) {
  int err = pcap_compile(handle_, &filter_, filter_expr, 0, net_);
  if (err < 0) {
    return kl::Err("%s: Couldn't parse filter %s: %s\n", ifname_.c_str(),
                   filter_expr, pcap_geterr(handle_));
  }
  err = pcap_setfilter(handle_, &filter_);
  if (err < 0) {
    kl::Err("%s: Couldn't install filter %s: %s\n", ifname_.c_str(),
            filter_expr, pcap_geterr(handle_));
  }
  return kl::Ok();
}

const uint8_t *Sniffer::NextPacket(struct pcap_pkthdr *header) {
  return pcap_next(handle_, header);
}

Sniffer::~Sniffer() { Close(); }

}  // namespace pcap
}  // namespace kale
