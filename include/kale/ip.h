// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
// Use of this source code is governed by the BSD license that can be found in
// the LICENSE file.

// Some routines operating on IP packets.
#ifndef KALE_IP_H_
#define KALE_IP_H_
#include "kl/error.h"

namespace kale {
namespace ip {
// All these functions won't validate packet.
bool IsUDP(const uint8_t *packet, size_t len);
bool IsTCP(const uint8_t *packet, size_t len);

uint16_t IPHeaderLength(const uint8_t *packet, size_t len);

// @addr, @port in network byte order.
uint32_t SrcAddr(const uint8_t *packet, size_t len);
uint32_t DstAddr(const uint8_t *packet, size_t len);
uint16_t UDPSrcPort(const uint8_t *packet, size_t len);
uint16_t UDPDstPort(const uint8_t *packet, size_t len);
uint16_t TCPSrcPort(const uint8_t *packet, size_t len);
uint16_t TCPDstPort(const uint8_t *packet, size_t len);
void ChangeSrcAddr(uint8_t *packet, size_t len, uint32_t addr);
void ChangeDstAddr(uint8_t *packet, size_t len, uint32_t addr);
void ChangeUDPSrcPort(uint8_t *packet, size_t len, uint16_t port);
void ChangeUDPDstPort(uint8_t *packet, size_t len, uint16_t port);
void ChangeTCPSrcPort(uint8_t *packet, size_t len, uint16_t port);
void ChangeTCPDstPort(uint8_t *packet, size_t len, uint16_t port);
uint8_t *SegmentBase(uint8_t *packet, size_t len);
const uint8_t *SegmentBase(const uint8_t *packet, size_t len);
void IPFillChecksum(uint8_t *packet, size_t len);
void UDPFillChecksum(uint8_t *packet, size_t len);
void TCPFillChecksum(uint8_t *packet, size_t len);

// human readable string
std::string TCPSrcAddr(const uint8_t *packet, size_t len);
std::string TCPDstAddr(const uint8_t *packet, size_t len);
std::string UDPSrcAddr(const uint8_t *packet, size_t len);
std::string UDPDstAddr(const uint8_t *packet, size_t len);

uint16_t TCPHeaderLength(const uint8_t *packet, size_t len);
uint16_t UDPHeaderLength(const uint8_t *packet, size_t len);

// data length of the segment
size_t TCPDataLength(const uint8_t *packet, size_t len);
size_t UDPDataLength(const uint8_t *packet, size_t len);

// @return: in network byte order
// @x: in network byte order
uint32_t ChecksumCarry(uint32_t x);
uint16_t IPHeaderChecksum(const uint8_t *packet, size_t len);
uint16_t TCPChecksum(const uint8_t *packet, size_t len);
uint16_t UDPChecksum(const uint8_t *packet, size_t len);

void Dump(FILE *out, const uint8_t *packet, size_t len);

// format: ([bwq]|[[<num>|#]s])*
// b for uint8_t, w for uint16_t, q for uint32_t, all in network byte order
// <num> # for number placeholder, indicates number of chars fowllowing
int BuildNetworkBuffer(uint8_t *buf, size_t size, const char *format, ...);

int BuildNetworkBuffer(uint8_t *buf, size_t size, const char *format,
                       va_list args);

// swap src/dst addr and port
void UDPEcho(uint8_t *packet, size_t len);

}  // namespace packet
}  // namespace kale
#endif
