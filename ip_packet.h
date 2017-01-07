// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#ifndef KALE_IP_PACKET_H_
#define KALE_IP_PACKET_H_
#include "kl/error.h"

namespace kale {
namespace ip_packet {

bool IsUDP(const uint8_t *packet, size_t len);
bool IsTCP(const uint8_t *packet, size_t len);

// All these functions won't validate packet.
// @addr, @port in network byte order.
void ChangeDstAddr(uint8_t *packet, size_t len, uint32_t addr);
void ChangeSrcAddr(uint8_t *packet, size_t len, uint32_t addr);
void ChangeUDPPort(uint8_t *segment, size_t len, uint16_t port);
void ChangeTCPPort(uint8_t *segment, size_t len, uint16_t port);
// https://tools.ietf.org/html/rfc791
uint16_t IPHeaderCheckSum(const uint8_t *packet, size_t len);
uint16_t TCPCheckSum(const uint8_t *segment, size_t len);
uint16_t UDPCheckSum(const uint8_t *segment, size_t len);

}  // namespace packet
}  // namespace kale
#endif
