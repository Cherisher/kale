// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
// Use of this source code is governed by the BSD license that can be found in
// the LICENSE file.

#ifndef KALE_IPV4_TCP_H_
#define KALE_IPV4_TCP_H_

#include "kale/ipv4.h"

namespace kale {
namespace ipv4 {
namespace tcp {

#pragma pack(1)
struct TCPRep {
  uint16_t source_port;
  uint16_t dest_port;
  uint32_t sequence_number;
  uint32_t ack_number;
  uint8_t ns : 1, reserved : 3, data_offset : 4;
  uint8_t fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1,
      cwr : 1;
  uint16_t window_size;
  uint16_t checksum;
  uint16_t urgent_pointer;
  uint8_t data;
};

class TCPSegmentEditor {
 public:
  TCPSegmentEditor(PacketRef packet, uint8_t* segment, size_t len);
  void ChangeSourcePort(uint16_t new_port);
  void ChangeDestPort(uint16_t new_port);
  void SwapPort();
  SegmentRef<TCPRep> ref() const { return SegmentRef<TCPRep>(rep_, len_); }
  void FillChecksum();
  bool ValidateChecksum() const;

 private:
  PacketRef packet_;
  TCPRep* rep_;
  size_t len_;
};

}  // namespace tcp
}  // namespace ipv4
}  // namespace kale
#endif  // KALE_IPV4_TCP_H_
