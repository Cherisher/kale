// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#include <arpa/inet.h>

#include "ip_packet.h"
#include "kl/logger.h"

namespace kale {
// https://en.wikipedia.org/wiki/IPv4
namespace ip_packet {
uint16_t IPHeaderLength(const uint8_t *packet, size_t len) {
  return (0x0f & packet[0]) << 2;
}

bool IsUDP(const uint8_t *packet, size_t len) {
  assert(len >= 10);
  return packet[9] == 0x11;
}

bool IsTCP(const uint8_t *packet, size_t len) {
  assert(len >= 10);
  return packet[9] == 0x06;
}

void ChangeSrcAddr(uint8_t *packet, size_t len, uint32_t addr) {
  *reinterpret_cast<uint32_t *>(packet + 12) = addr;
  uint16_t checksum = IPHeaderCheckSum(packet, len);
  *reinterpret_cast<uint16_t *>(packet + 10) = checksum;
}

void ChangeDstAddr(uint8_t *packet, size_t len, uint32_t addr) {
  *reinterpret_cast<uint32_t *>(packet + 16) = addr;
  uint16_t checksum = IPHeaderCheckSum(packet, len);
  *reinterpret_cast<uint16_t *>(packet + 10) = checksum;
}

uint16_t IPHeaderCheckSum(const uint8_t *packet, size_t len) {
  uint16_t header_len = IPHeaderLength(packet, len);
  assert(len >= header_len);
  uint32_t sum = 0;
  for (int i = 0; i < header_len; i = i + 2) {
    // checksum field as zero
    uint16_t x =
        (i == 10) ? 0 : *reinterpret_cast<const uint16_t *>(&packet[i]);
    sum += htons(x);
    if (sum > 0xffff) {
      sum -= 0xffff;
    }
  }
  return htons(~sum);
}

}  // namespace ip_packet
}  // namespace kale
