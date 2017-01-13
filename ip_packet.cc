// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#include <arpa/inet.h>

#include <iostream>

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

uint32_t SrcAddr(const uint8_t *packet, size_t len) {
  return *reinterpret_cast<const uint32_t *>(packet + 12);
}

uint32_t DstAddr(const uint8_t *packet, size_t len) {
  return *reinterpret_cast<const uint32_t *>(packet + 16);
}

uint16_t TCPSrcPort(const uint8_t *packet, size_t len) {
  const uint8_t *segment = SegmentBase(packet, len);
  return *reinterpret_cast<const uint16_t *>(segment);
}

uint16_t TCPDstPort(const uint8_t *packet, size_t len) {
  const uint8_t *segment = SegmentBase(packet, len);
  return *reinterpret_cast<const uint16_t *>(segment + 2);
}

uint16_t UDPSrcPort(const uint8_t *packet, size_t len) {
  const uint8_t *segment = SegmentBase(packet, len);
  return *reinterpret_cast<const uint16_t *>(segment);
}

uint16_t UDPDstPort(const uint8_t *packet, size_t len) {
  const uint8_t *segment = SegmentBase(packet, len);
  return *reinterpret_cast<const uint16_t *>(segment + 2);
}

void ChangeSrcAddr(uint8_t *packet, size_t len, uint32_t addr) {
  *reinterpret_cast<uint32_t *>(packet + 12) = addr;
}

void ChangeDstAddr(uint8_t *packet, size_t len, uint32_t addr) {
  *reinterpret_cast<uint32_t *>(packet + 16) = addr;
}

void IPFillChecksum(uint8_t *packet, size_t len) {
  *reinterpret_cast<uint16_t *>(packet + 10) = IPHeaderChecksum(packet, len);
}

const uint8_t *SegmentBase(const uint8_t *packet, size_t len) {
  return packet + IPHeaderLength(packet, len);
}

uint8_t *SegmentBase(uint8_t *packet, size_t len) {
  return packet + IPHeaderLength(packet, len);
}

void UDPFillChecksum(uint8_t *packet, size_t len) {
  uint8_t *segment = SegmentBase(packet, len);
  *reinterpret_cast<uint16_t *>(segment + 6) = UDPChecksum(packet, len);
}

void ChangeUDPSrcPort(uint8_t *packet, size_t len, uint16_t port) {
  uint8_t *segment = SegmentBase(packet, len);
  *reinterpret_cast<uint16_t *>(segment) = port;
}

void ChangeUDPDstPort(uint8_t *packet, size_t len, uint16_t port) {
  uint8_t *segment = SegmentBase(packet, len);
  *reinterpret_cast<uint16_t *>(segment + 2) = port;
}

void TCPFillChecksum(uint8_t *packet, size_t len) {
  uint8_t *segment = SegmentBase(packet, len);
  *reinterpret_cast<uint16_t *>(segment + 16) = TCPChecksum(packet, len);
}

void ChangeTCPSrcPort(uint8_t *packet, size_t len, uint16_t port) {
  uint8_t *segment = SegmentBase(packet, len);
  *reinterpret_cast<uint16_t *>(segment) = port;
}

void ChangeTCPDstPort(uint8_t *packet, size_t len, uint16_t port) {
  uint8_t *segment = SegmentBase(packet, len);
  *reinterpret_cast<uint16_t *>(segment + 2) = port;
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

uint16_t TCPChecksum(const uint8_t *packet, size_t len) {
  size_t ip_header_len = IPHeaderLength(packet, len);
  size_t tcp_len = len - ip_header_len;
  const uint8_t *segment = packet + ip_header_len;
  uint32_t sum = 0;
  // pseudo header
  // src/dst addr
  sum += *reinterpret_cast<const uint16_t *>(packet + 12);
  sum += *reinterpret_cast<const uint16_t *>(packet + 14);
  sum += *reinterpret_cast<const uint16_t *>(packet + 16);
  sum += *reinterpret_cast<const uint16_t *>(packet + 18);
  // protocol & len
  sum += 0x0600 + htons(tcp_len);
  // tcp segment
  for (size_t i = 0; i < tcp_len; i = i + 2) {
    uint16_t x =
        (i == 16) ? 0 : *reinterpret_cast<const uint16_t *>(segment + i);
    sum += x;
  }
  if (tcp_len & 1) {
    sum += static_cast<uint16_t>(*(segment + tcp_len + 1)) << 8;
  }
  return ChecksumCarry(sum);
}

uint16_t UDPChecksum(const uint8_t *packet, size_t len) {
  size_t ip_header_len = IPHeaderLength(packet, len);
  size_t udp_len = len - ip_header_len;
  const uint8_t *segment = packet + ip_header_len;
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
  for (size_t i = 0; i < udp_len; i = i + 2) {
    uint16_t x =
        (i == 6) ? 0 : *reinterpret_cast<const uint16_t *>(segment + i);
    sum += x;
  }
  if (udp_len & 1) {
    sum += static_cast<uint16_t>(*(segment + udp_len + 1)) << 8;
  }
  return ChecksumCarry(sum);
}

void Dump(FILE *out, const uint8_t *packet, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    fprintf(out, "%02x", *(packet + i));
    if (((i + 1) & 15) == 0) {
      fprintf(out, "\n");
    } else if (i & 1) {
      fprintf(out, " ");
    }
  }
  fprintf(out, "\n");
  fflush(out);
}

static void WriteBufferAt(uint8_t *buf, size_t size, int index, char c) {
  if (buf && index < static_cast<int>(size)) {
    buf[index] = static_cast<uint8_t>(c);
  }
}

static void WriteBufferAt(uint8_t *buf, size_t size, int index,
                          const char *data, int count) {
  int i = 0;
  while (buf && data && index < static_cast<int>(size) && i < count) {
    buf[index++] = static_cast<uint8_t>(data[i++]);
  }
}

// if buf == nullptr, returns the size of buffer that is required to contain the
// whole data to be packed.
int BuildNetworkBuffer(uint8_t *buf, size_t size, const char *format,
                       va_list args) {
  int result_len = 0;
  int str_len = -1;
  char ch = 0;
  while ((ch = *format++) != 0) {
    if (::isdigit(ch)) {
      str_len = ch - '0';
      while ((ch = *format++) != 0) {
        if (::isdigit(ch)) {
          str_len = (str_len * 10) + (ch - '0');
        } else {
          break;
        }
      }
      if (ch != 's') {
        str_len = -1;
      }
    }
    if (ch == '#' && *format == 's') {
      str_len = va_arg(args, int);
    }
    if (ch == 's') {
      const char *str_ptr = va_arg(args, char *);
      if (str_len >= 0) {
        WriteBufferAt(buf, size, result_len, str_ptr, str_len);
        result_len += str_len;
        str_len = -1;
      } else {
        while (*str_ptr) {
          WriteBufferAt(buf, size, result_len, *str_ptr);
          ++str_ptr;
          ++result_len;
        }
      }
    }
    if (ch == 'b') {
      uint8_t x = va_arg(args, int);
      WriteBufferAt(buf, size, result_len, static_cast<char>(x));
      ++result_len;
    }
    if (ch == 'w') {
      uint16_t x = va_arg(args, int);
      WriteBufferAt(buf, size, result_len, reinterpret_cast<const char *>(&x),
                    sizeof(x));
      result_len += sizeof(x);
    }
    if (ch == 'q') {
      uint32_t x = va_arg(args, uint32_t);
      WriteBufferAt(buf, size, result_len, reinterpret_cast<const char *>(&x),
                    sizeof(x));
      result_len += sizeof(x);
    }
  }
  return result_len;
}

int BuildNetworkBuffer(uint8_t *buf, size_t size, const char *fmt, ...) {
  va_list args;
  int len;
  va_start(args, fmt);
  len = BuildNetworkBuffer(buf, size, fmt, args);
  va_end(args);
  return len;
}

void UDPEcho(uint8_t *packet, size_t len) {
  uint32_t *src_addr = reinterpret_cast<uint32_t *>(packet + 12);
  uint32_t *dst_addr = reinterpret_cast<uint32_t *>(packet + 16);
  std::swap(*src_addr, *dst_addr);
  uint8_t *segment = SegmentBase(packet, len);
  uint16_t *src_port = reinterpret_cast<uint16_t *>(segment);
  uint16_t *dst_port = reinterpret_cast<uint16_t *>(segment + 2);
  std::swap(*src_port, *dst_port);
}

}  // namespace ip_packet
}  // namespace kale
