// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
// Use of this source code is governed by the BSD license that can be found in
// the LICENSE file.

#include <arpa/inet.h>

#include "kale/ipv4_tcp.h"

#include <iostream>

namespace kale {
namespace ipv4 {
namespace tcp {

TCPSegmentEditor::TCPSegmentEditor(PacketRef packet, uint8_t *segment,
                                   size_t len)
    : packet_(packet), rep_(reinterpret_cast<TCPRep *>(segment)), len_(len) {}

void TCPSegmentEditor::ChangeSourcePort(uint16_t new_port) {
  rep_->source_port = new_port;
}

void TCPSegmentEditor::ChangeDestPort(uint16_t new_port) {
  rep_->dest_port = new_port;
}

void TCPSegmentEditor::SwapPort() {
  std::swap(rep_->source_port, rep_->dest_port);
}

bool TCPSegmentEditor::ValidateChecksum() const {
  uint32_t sum = 0;
  // Pseudo header
  sum += InternetChecksum(
      reinterpret_cast<const uint8_t *>(&packet_.rep->source_addr),
      sizeof(packet_.rep->source_addr));
  sum += InternetChecksum(
      reinterpret_cast<const uint8_t *>(&packet_.rep->dest_addr),
      sizeof(packet_.rep->dest_addr));
  sum += htons(static_cast<uint16_t>(Protocol::kTCP));
  sum += htons(static_cast<uint16_t>(len_));
  // Segment
  sum += InternetChecksum(reinterpret_cast<uint8_t *>(rep_), len_);
  // fprintf(stderr, "%#08x\n", sum);
  sum = ChecksumCarry(sum);
  // std::cerr << "TCP all sum: " << ~static_cast<uint16_t>(sum) << "\n";
  return static_cast<uint16_t>(~sum) == 0;
}

void TCPSegmentEditor::FillChecksum() {
  rep_->checksum = 0;
  uint32_t sum = 0;
  // Pseudo header
  sum += InternetChecksum(
      reinterpret_cast<const uint8_t *>(&packet_.rep->source_addr),
      sizeof(packet_.rep->source_addr));
  sum += InternetChecksum(
      reinterpret_cast<const uint8_t *>(&packet_.rep->dest_addr),
      sizeof(packet_.rep->dest_addr));
  sum += htons(static_cast<uint16_t>(Protocol::kTCP));
  sum += htons(static_cast<uint16_t>(len_));
  // Segment
  sum += InternetChecksum(reinterpret_cast<uint8_t *>(rep_), len_);
  // fprintf(stderr, "%#2x\n", sum);
  rep_->checksum = static_cast<uint16_t>(~ChecksumCarry(sum));
}

}  // namespace tcp
}  // namespace ipv4
}  // namespace kale
