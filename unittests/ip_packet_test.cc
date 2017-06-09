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

}  // namespace
