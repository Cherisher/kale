// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
// Use of this source code is governed by the BSD license that can be found in
// the LICENSE file.

#include "kale/ipv4.h"
#include "kale/ipv4_tcp.h"
#include "kale/ipv4_udp.h"
#include "kl/logger.h"
#include "kl/testkit.h"
#include "kl/hexdump.h"

#include <iostream>
#include <vector>

namespace {

class IPv4Test {};
using namespace kale::ipv4;

TEST(IPv4Test, ChecksumCarryTest) {
  uint32_t sum = 0x6fff9;
  ASSERT(ChecksumCarry(sum) == 0xffff);
  sum = 0xffff;
  ASSERT(ChecksumCarry(sum) == 0xffff);
}

TEST(IPv4Test, OnesComplement) {
  uint16_t sum = 0xffff;
  fprintf(stderr, "%#04x\n", static_cast<uint16_t>(~sum));
  ASSERT(static_cast<uint16_t>(~sum) == 0);
}

TEST(IPv4Test, IPv4Packet) {
  const uint8_t packet[] = {
      0x45, 0x00, 0x00, 0x34, 0x9d, 0x8a, 0x40, 0x00, 0x40, 0x06, 0xe1,
      0x74, 0x0a, 0x00, 0x00, 0x01, 0x4a, 0x7d, 0x67, 0x47, 0x90, 0x10,
      0x01, 0xbb, 0x44, 0xc6, 0xc0, 0x30, 0x61, 0x4e, 0x74, 0xcd, 0x80,
      0x10, 0x58, 0x64, 0xff, 0xff, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a,
      0x00, 0x3e, 0x27, 0xdb, 0x96, 0xa5, 0x36, 0xf7,
  };
  ASSERT(sizeof(packet) == 52);
  PacketRef ip(packet, sizeof(packet));
  ASSERT(ip.HeaderLength() == 20);
  ASSERT(ip.DataLength() == 32);
  SegmentRef<tcp::TCPRep> tcp;
  bool is_udp = ip.GetUDPSegmentRef(nullptr);
  ASSERT(!is_udp);
  bool is_tcp = ip.GetTCPSegmentRef(&tcp);
  ASSERT(is_tcp);
  ASSERT(tcp.segment_len == 32);
  ASSERT(tcp.rep->checksum == 65535);
}

// It's a IPv6 packet anyway...
TEST(IPv4Test, IPv4Packet1) {
  // const uint8_t packet[] = {
  //     0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0xff, 0xfe, 0x80, 0x00, 0x00,
  //     0x00, 0x00, 0x00, 0x00, 0x31, 0x32, 0x06, 0x6c, 0x47, 0x60, 0x06, 0xe0,
  //     0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  //     0x00, 0x00, 0x00, 0x02, 0x85, 0x00, 0xf7, 0x58, 0x00, 0x00, 0x00, 0x00,
  // };
  // std::vector<uint8_t> to_be_edit(packet, packet + sizeof(packet));
  // PacketRef origin(packet, sizeof(packet));
  // fprintf(stderr, "origin checksum: %#04x\n", origin.rep->checksum);
  // PacketEditor editor(to_be_edit.data(), to_be_edit.size());
  // ASSERT(editor.ref().rep->checksum == 0);
  // ASSERT(editor.ValidateChecksum());
  // editor.FillChecksum();
  // PacketRef edited = editor.ref();
  // ASSERT(edited.rep->checksum == origin.rep->checksum);
}

TEST(IPv4Test, IPv4Packet2) {
  const uint8_t packet[] = {
      0x45, 0x00, 0x00, 0x34, 0x9d, 0x8a, 0x40, 0x00, 0x40, 0x06, 0xe1,
      0x74, 0x0a, 0x00, 0x00, 0x01, 0x4a, 0x7d, 0x67, 0x47, 0x90, 0x10,
      0x01, 0xbb, 0x44, 0xc6, 0xc0, 0x30, 0x61, 0x4e, 0x74, 0xcd, 0x80,
      0x10, 0x58, 0x64, 0xff, 0xff, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a,
      0x00, 0x3e, 0x27, 0xdb, 0x96, 0xa5, 0x36, 0xf7,
  };
  std::vector<uint8_t> to_be_edit(packet, packet + sizeof(packet));
  PacketRef origin(packet, sizeof(packet));
  SegmentRef<tcp::TCPRep> origin_tcp;
  ASSERT(origin.GetTCPSegmentRef(&origin_tcp));
  PacketEditor editor(to_be_edit.data(), to_be_edit.size());
  auto tcp_editor = editor.CreateTCPSegmentEditor();
  ASSERT(tcp_editor);
  ASSERT(tcp_editor->ValidateChecksum());
  tcp_editor->FillChecksum();
  auto edited = tcp_editor->ref();
  fprintf(stderr, "origin tcp checksum: %#02x\n", origin_tcp.rep->checksum);
  std::string origin_buffer;
  kl::HexDump(kl::Slice(reinterpret_cast<const char *>(origin_tcp.rep),
                        origin_tcp.segment_len),
              &origin_buffer);
  std::cerr << "origin buffer: " << origin_buffer << "\n";
  fprintf(stderr, "edited tcp checksum: %#02x\n", edited.rep->checksum);
  std::string edited_buffer;
  kl::HexDump(
      kl::Slice(reinterpret_cast<const char *>(edited.rep), edited.segment_len),
      &edited_buffer);
  std::cerr << "edited buffer: " << edited_buffer << "\n";
  ASSERT(tcp_editor->ValidateChecksum());
  // Regarding http://www.rfc-archive.org/getrfc.php?rfc=1624
  ASSERT(edited.rep->checksum == 0);
}

}  // namespace
