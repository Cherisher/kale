// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
// Use of this source code is governed by the BSD license that can be found in
// the LICENSE file.

#include "kale/ipv4.h"
#include "kale/ipv4_tcp.h"
#include "kale/ipv4_udp.h"

#include <iostream>

namespace kale {
namespace ipv4 {

bool PacketRef::IsTCP() const { return rep->protocol == Protocol::kTCP; }

bool PacketRef::IsUDP() const { return rep->protocol == Protocol::kUDP; }

size_t PacketRef::HeaderLength() const { return rep->ihl << 2; }

bool PacketRef::GetTCPSegmentRef(SegmentRef<tcp::TCPRep> *tcp) const {
  if (!IsTCP()) {
    return false;
  }
  GetSegmentRef(tcp);
  return true;
}

bool PacketRef::GetUDPSegmentRef(SegmentRef<udp::UDPRep> *udp) const {
  if (!IsUDP()) {
    return false;
  }
  GetSegmentRef(udp);
  return true;
}

uint32_t InternetChecksum(const uint8_t *packet, size_t len) {
  uint32_t sum = 0;
  for (size_t i = 0; i < len - 1; i += 2) {
    sum += *reinterpret_cast<const uint16_t *>(packet + i);
  }
  if (len & 1) {
    sum += *(packet + len - 1);
  }
  return sum;
}

PacketEditor::PacketEditor(uint8_t *buffer, size_t len) {
  rep_ = reinterpret_cast<Rep *>(buffer);
  len_ = len;
}

void PacketEditor::ChangeSourceAddr(uint32_t new_source_addr) {
  rep_->source_addr = new_source_addr;
}

void PacketEditor::ChangeDestAddr(uint32_t new_dest_addr) {
  rep_->dest_addr = new_dest_addr;
}

void PacketEditor::SwapAddr() { std::swap(rep_->source_addr, rep_->dest_addr); }

bool PacketEditor::ValidateChecksum() const {
  uint8_t *packet = reinterpret_cast<uint8_t *>(rep_);
  uint16_t sum = ChecksumCarry(
      InternetChecksum(packet, PacketRef(packet, len_).HeaderLength()));
  // std::cerr << "IP all sum: " << sum << "\n";
  return static_cast<uint16_t>(~sum) == 0;
}

// http://www.rfc-archive.org/getrfc.php?rfc=1624
// Seems both +0 and -0 in the checksum field is correct
void PacketEditor::FillChecksum() {
  uint8_t *packet = reinterpret_cast<uint8_t *>(rep_);
  rep_->checksum = 0;
  rep_->checksum = static_cast<uint16_t>(~ChecksumCarry(InternetChecksum(
      packet, PacketRef(packet, len_).HeaderLength())));
}

std::unique_ptr<tcp::TCPSegmentEditor> PacketEditor::CreateTCPSegmentEditor() {
  PacketRef packet_ref = ref();
  if (!packet_ref.IsTCP()) {
    return nullptr;
  }
  uint8_t *packet = reinterpret_cast<uint8_t *>(rep_);
  uint8_t *segment = packet + packet_ref.HeaderLength();
  size_t segment_len = packet + len_ - segment;
  return std::make_unique<tcp::TCPSegmentEditor>(packet_ref, segment,
                                                 segment_len);
}

std::unique_ptr<udp::UDPSegmentEditor> PacketEditor::CreateUDPSegmentEditor() {
  PacketRef packet_ref = ref();
  if (!packet_ref.IsUDP()) {
    return nullptr;
  }
  uint8_t *packet = reinterpret_cast<uint8_t *>(rep_);
  uint8_t *segment = packet + packet_ref.HeaderLength();
  size_t segment_len = packet + len_ - segment;
  return std::make_unique<udp::UDPSegmentEditor>(packet_ref, segment,
                                                 segment_len);
}

}  // namespace ipv4
}  // namespace kale
