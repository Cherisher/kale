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
  uint16_t checksum = IPHeaderChecksum(packet, len);
  *reinterpret_cast<uint16_t *>(packet + 10) = checksum;
}

void ChangeDstAddr(uint8_t *packet, size_t len, uint32_t addr) {
  *reinterpret_cast<uint32_t *>(packet + 16) = addr;
  uint16_t checksum = IPHeaderChecksum(packet, len);
  *reinterpret_cast<uint16_t *>(packet + 10) = checksum;
}

uint32_t ChecksumCarry(uint32_t x) {
  x = (x >> 16) + (x & 0xffff);
  return ~(x + (x >> 16)) & 0xffff;
}

// https://tools.ietf.org/html/rfc791
uint16_t IPHeaderChecksum(const uint8_t *packet, size_t len) {
  uint16_t header_len = IPHeaderLength(packet, len);
  assert(len >= header_len);
  uint32_t sum = 0;
  for (int i = 0; i < header_len; i = i + 2) {
    // checksum field as zero
    uint16_t x =
        (i == 10) ? 0 : *reinterpret_cast<const uint16_t *>(packet + i);
    sum += x;
  }
  return ChecksumCarry(sum);
}

uint16_t TCPChecksum(const uint8_t *packet, size_t len) {}

uint16_t UDPChecksum(const uint8_t *packet, size_t len) {
  size_t ip_header_len = IPHeaderLength(packet, len);
  size_t udp_len = len - ip_header_len;
  const uint8_t *segment = packet + ip_header_len;
  assert(udp_len == ntohs(*reinterpret_cast<const uint16_t *>(segment + 4)));
  uint32_t sum = 0;
  // pseudo header
  // src/dst addr
  sum += *reinterpret_cast<const uint16_t *>(packet + 12);
  sum += *reinterpret_cast<const uint16_t *>(packet + 14);
  sum += *reinterpret_cast<const uint16_t *>(packet + 16);
  sum += *reinterpret_cast<const uint16_t *>(packet + 18);
  // protocol & len
  sum += 0x1100 + *reinterpret_cast<const uint16_t *>(segment + 4);
  // udp segment
  for (int i = 0; i < udp_len; i = i + 2) {
    uint16_t x =
        (i == 6) ? 0 : *reinterpret_cast<const uint16_t *>(segment + i);
    sum += x;
  }
  if (udp_len & 1) {
    sum += static_cast<uint16_t>(*(segment + udp_len + 1)) << 8;
  }
  return ChecksumCarry(sum);
}

}  // namespace ip_packet
}  // namespace kale
