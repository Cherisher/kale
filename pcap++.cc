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

kl::Result<void>
Sniffer::Loop(int count,
              std::function<void(const struct pcap_pkthdr *header,
                                 const uint8_t *packet)> &&callback) {
  callback_ = std::move(callback);
  int err = pcap_loop(handle_, count, &Sniffer::ExcecutePcapHandler,
                      reinterpret_cast<uint8_t *>(this));
  if (err < 0) {
    kl::Err("%s: pcap_loop internal error %s\n", ifname_.c_str(),
            pcap_geterr(handle_));
  }
  return kl::Ok();
}

void Sniffer::ExcecutePcapHandler(uint8_t *user,
                                  const struct pcap_pkthdr *header,
                                  const uint8_t *packet) {
  return reinterpret_cast<Sniffer *>(user)->callback_(header, packet);
}

void Sniffer::BreakLoop() { return pcap_breakloop(handle_); }

Sniffer::~Sniffer() { Close(); }

}  // namespace pcap
}  // namespace kale
