// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
// Use of this source code is governed by the BSD license that can be found in
// the LICENSE file.

#include <string>

#include "ip_packet.h"
#include "kl/logger.h"
#include "kl/testkit.h"
#include "zstd++.h"

class T {};
TEST(T, CompressAndDecompress) {
  const std::string message(
      "Zstd can also offer stronger compression ratios at the cost of "
      "compression speed. Speed vs Compression trade-off is configurable by "
      "small increments. Decompression speed is preserved and remains roughly "
      "the same at all settings, a property shared by most LZ compression "
      "algorithms, such as zlib or lzma.");
  char buf[1024];
  int len = kale::ip_packet::BuildNetworkBuffer(
      reinterpret_cast<uint8_t *>(buf), sizeof(buf), "#s", message.size(),
      message.data());
  KL_DEBUG("original size: %u", len);
  auto compress =
      kale::zstd::Compress(reinterpret_cast<const uint8_t *>(buf), len);
  ASSERT(compress);
  KL_DEBUG("compressed size: %u", (*compress).size());
  auto decompress =
      kale::zstd::Decompress((*compress).data(), (*compress).size());
  ASSERT(decompress);
  std::string result((*decompress).begin(), (*decompress).end());
  KL_DEBUG("%s", result.c_str());
  ASSERT(result == message);
}

int main() { return KL_TEST(); }
