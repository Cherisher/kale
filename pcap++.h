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

class Sniffer {
public:
  explicit Sniffer(const char *ifname);
  kl::Result<void> CompileAndInstall(const char *filter_expr);
  kl::Result<int> Loop(int count,
                       std::function<void(const struct pcap_pkthdr *header,
                                          const uint8_t *packet)> &&callback);
  void BreakLoop();
  void Close();
  const uint8_t *NextPacket(struct pcap_pkthdr *header);
  ~Sniffer();

private:
  static void ExcecutePcapHandler(uint8_t *user,
                                  const struct pcap_pkthdr *header,
                                  const uint8_t *packet);
  std::string ifname_;
  pcap_t *handle_;
  bpf_u_int32 net_, mask_;
  struct bpf_program filter_;
  std::function<void(const struct pcap_pkthdr *header, const uint8_t *packet)>
      callback_;
};

}  // namespace pcap
}  // namespace
#endif
