// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#ifndef KALE_PCAP_H_
#define KALE_PCAP_H_
#include <string>

#include "kl/error.h"
#include "pcap/pcap.h"

namespace kale {

class Sniffer {
public:
  static kl::Result<std::string> DefaultDevice();
  explicit Sniffer(const char *ifname);
  kl::Result<void> CompileAndInstall(const char *filter_expr);
  kl::Result<void> Loop(int count,
                        std::function<void(const struct pcap_pkthdr *header,
                                           const uint8_t *packet)> &&callback);
  void BreakLoop();
  void Close();
  int DataLink() const;
  const uint8_t *NextPacket(struct pcap_pkthdr *header);
  ~Sniffer();

private:
  static void ExcecutePcapHandler(uint8_t *user,
                                  const struct pcap_pkthdr *header,
                                  const uint8_t *packet);
  std::string ifname_;
  pcap_t *handle_;
  bpf_u_int32 net_, mask_;
  int data_link_;
  struct bpf_program filter_;
  std::function<void(const struct pcap_pkthdr *header, const uint8_t *packet)>
      callback_;
  char errbuf_[PCAP_ERRBUF_SIZE];
};

}  // namespace
#endif
