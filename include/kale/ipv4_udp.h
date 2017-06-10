// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
// Use of this source code is governed by the BSD license that can be found in
// the LICENSE file.

#ifndef KALE_IPV4_UDP_H_
#define KALE_IPV4_UDP_H_

#include "kale/ipv4.h"

namespace kale {
namespace ipv4 {
namespace udp {

#pragma pack(1)
struct UDPRep {
  uint16_t source_port;
  uint16_t dest_port;
  uint16_t length;
  uint16_t checksum;
  uint8_t data;
};

class UDPSegmentEditor {
 public:
  UDPSegmentEditor(PacketRef packet, uint8_t* segment, size_t len);
  void ChangeSourcePort(uint16_t new_port);
  void ChangeDestPort(uint16_t new_port);
  void SwapPort();
  SegmentRef<UDPRep> ref() const { return SegmentRef<UDPRep>(rep_, len_); }
  void FillChecksum();
  bool ValidateChecksum() const;

 private:
  PacketRef packet_;
  UDPRep* rep_;
  size_t len_;
};

}  // namespace udp
}  // namespace ipv4
}  // namespace kale
#endif  // KALE_IPV4_UDP_H_
