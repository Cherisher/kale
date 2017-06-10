// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
// Use of this source code is governed by the BSD license that can be found in
// the LICENSE file.

#ifndef KALE_IPV4_H_
#define KALE_IPV4_H_

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cassert>
#include <memory>

namespace kale {

namespace ipv4 {

namespace tcp {
struct TCPRep;
class TCPSegmentEditor;
}  // namespace tcp

namespace udp {
struct UDPRep;
class UDPSegmentEditor;
}  // namespace udp

enum Protocol {
  kTCP = 0x06,
  kUDP = 0x11,
};

#pragma pack(1)
struct Rep {
  uint8_t ihl : 4, version : 4;
  uint8_t ecn : 4, dscp : 4;
  uint16_t total_length;
  uint16_t identification;
  uint8_t fragment_offset_low : 5, flags : 3;
  uint8_t fragment_offset_high;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum;
  uint32_t source_addr;
  uint32_t dest_addr;
  uint8_t data;
};

template <typename Rep>
struct SegmentRef {
  size_t segment_len;
  const Rep *rep;
  SegmentRef() : rep(nullptr), segment_len(0) {}
  SegmentRef(const Rep *r, size_t l) : rep(r), segment_len(l) {}
};

struct Packet;

struct PacketRef {
  PacketRef(const uint8_t *packet, size_t l)
      : rep(reinterpret_cast<const Rep *>(packet)), len(l) {}

  const Rep *rep;
  size_t len;

  bool IsTCP() const;
  bool IsUDP() const;
  size_t HeaderLength() const;

  template <typename Rep>
  void GetSegmentRef(SegmentRef<Rep> *segment_ref) const {
    const uint8_t *packet = reinterpret_cast<const uint8_t *>(rep);
    const uint8_t *segment = packet + HeaderLength();
    segment_ref->rep = reinterpret_cast<const Rep *>(segment);
    segment_ref->segment_len = packet + len - segment;
  }

  bool GetTCPSegmentRef(SegmentRef<tcp::TCPRep> *tcp) const;
  bool GetUDPSegmentRef(SegmentRef<udp::UDPRep> *udp) const;

  size_t DataLength() const {
    return reinterpret_cast<const uint8_t *>(rep) + len -
           reinterpret_cast<const uint8_t *>(&(rep->data));
  }
};

inline uint16_t ChecksumCarry(uint32_t x) {
  // fprintf(stderr, "%#02x\n", x);
  x = (x & 0xffff) + (x >> 16);
  // fprintf(stderr, "%#02x\n", x);
  x = (x & 0xffff) + (x >> 16);
  // fprintf(stderr, "%#02x\n", x);
  return x;
}

uint32_t InternetChecksum(const uint8_t *packet, size_t len);

class PacketEditor {
 public:
  PacketEditor(uint8_t *buffer, size_t len);
  void ChangeSourceAddr(uint32_t new_source_addr);
  void ChangeDestAddr(uint32_t new_dest_addr);
  void FillChecksum();
  bool ValidateChecksum() const;
  void SwapAddr();
  PacketRef ref() const {
    return PacketRef(reinterpret_cast<uint8_t *>(rep_), len_);
  }

  std::unique_ptr<tcp::TCPSegmentEditor> CreateTCPSegmentEditor();

  std::unique_ptr<udp::UDPSegmentEditor> CreateUDPSegmentEditor();

 private:
  Rep *rep_;
  size_t len_;
};

}  // namespace ipv4
}  // namespace kale
#endif  // KALE_IPV4_H_
