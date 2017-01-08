// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#ifndef KALE_IP_PACKET_H_
#define KALE_IP_PACKET_H_
#include "kl/error.h"

namespace kale {
namespace ip_packet {
// All these functions won't validate packet.
bool IsUDP(const uint8_t *packet, size_t len);
bool IsTCP(const uint8_t *packet, size_t len);

uint16_t IPHeaderLength(const uint8_t *packet, size_t len);

// @addr, @port in network byte order.
void ChangeSrcAddr(uint8_t *packet, size_t len, uint32_t addr);
void ChangeDstAddr(uint8_t *packet, size_t len, uint32_t addr);
void ChangeUDPPort(uint8_t *segment, size_t len, uint16_t port);
void ChangeTCPPort(uint8_t *segment, size_t len, uint16_t port);

// @return: in network byte order
uint32_t ChecksumCarry(uint32_t x);
uint16_t IPHeaderChecksum(const uint8_t *packet, size_t len);
uint16_t TCPChecksum(const uint8_t *packet, size_t len);
uint16_t UDPChecksum(const uint8_t *packet, size_t len);

}  // namespace packet
}  // namespace kale
#endif
