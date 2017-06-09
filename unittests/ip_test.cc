// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
// Use of this source code is governed by the BSD license that can be found in
// the LICENSE file.

#include "kale/ip.h"
#include "kl/logger.h"
#include "kl/testkit.h"

namespace {
class T {};

TEST(T, BuildNetworkBuffer0) {
  int len;
  len = kale::ip::BuildNetworkBuffer(nullptr, 0, "bbbb", 0, 1, 2, 3);
  ASSERT(len == 4);
  len = kale::ip::BuildNetworkBuffer(nullptr, 0, "wwww", 0, 1, 2, 3);
  ASSERT(len == 8);
  len = kale::ip::BuildNetworkBuffer(nullptr, 0, "qqqq", 0, 1, 2, 3);
  ASSERT(len == 16);
  len = kale::ip::BuildNetworkBuffer(nullptr, 0, "s", "");
  ASSERT(len == 0);
  len = kale::ip::BuildNetworkBuffer(nullptr, 0, "0s", "abcd");
  ASSERT(len == 0);
  len = kale::ip::BuildNetworkBuffer(nullptr, 0, "1s", "abcd");
  ASSERT(len == 1);
}

TEST(T, BuildNetworkBuffer1) {
  uint8_t buf[65536];
  uint8_t *packet = &buf[0];
  int len;
  len = kale::ip::BuildNetworkBuffer(buf, sizeof(buf), "b", 0x11);
  ASSERT(len == 1);
  ASSERT(*reinterpret_cast<uint8_t *>(packet) == 0x11);
  len = kale::ip::BuildNetworkBuffer(buf, sizeof(buf), "w", 0xff00);
  ASSERT(len == 2);
  ASSERT(*reinterpret_cast<uint16_t *>(packet) == 0xff00);
  len = kale::ip::BuildNetworkBuffer(buf, sizeof(buf), "q", 0xaabbccdd);
  ASSERT(len == 4);
  ASSERT(*reinterpret_cast<uint32_t *>(packet) == 0xaabbccdd);
  const char *message = "wtf~rekt~imfao~";
  len = kale::ip::BuildNetworkBuffer(buf, sizeof(buf), "s", message);
  ASSERT(len == static_cast<int>(::strlen(message)));
  ASSERT(std::string(reinterpret_cast<char *>(packet)) == message);
  len = kale::ip::BuildNetworkBuffer(buf, sizeof(buf), "sqwb", message,
                                     0xaabbccdd, 0xff00, 0x11);
  ASSERT(len == 1 + 2 + 4 + static_cast<int>(::strlen(message)));
  len = kale::ip::BuildNetworkBuffer(buf, sizeof(buf), "#s", 0, message);
  ASSERT(len == 0);
  len = kale::ip::BuildNetworkBuffer(buf, sizeof(buf), "#s", 1, message);
  ASSERT(len == 1);
}

TEST(T, CheckSum) {
  const uint8_t packet[] = {
      0x45, 0x00, 0x00, 0x34, 0x9d, 0x8a, 0x40, 0x00, 0x40, 0x06, 0xe1,
      0x74, 0x0a, 0x00, 0x00, 0x01, 0x4a, 0x7d, 0x67, 0x47, 0x90, 0x10,
      0x01, 0xbb, 0x44, 0xc6, 0xc0, 0x30, 0x61, 0x4e, 0x74, 0xcd, 0x80,
      0x10, 0x58, 0x64, 0xff, 0xff, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a,
      0x00, 0x3e, 0x27, 0xdb, 0x96, 0xa5, 0x36, 0xf7,
  };
  uint16_t checksum = kale::ip::TCPChecksum(packet, sizeof(packet));
  ASSERT(checksum = 65535);
}

}  // namespace
