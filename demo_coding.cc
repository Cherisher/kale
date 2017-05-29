// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
// Use of this source code is governed by the BSD license that can be found in
// the LICENSE file.

#include "kale/demo_coding.h"
#include "kale/arcfour.h"
#include "kl/error.h"

namespace kale {

namespace {

uint8_t kKey[4] = {0xc0, 0xde, 0xc0, 0xde};

kale::arcfour::Cipher cipher(kKey, sizeof(kKey));

void Encode(const uint8_t *buffer, size_t len, std::vector<uint8_t> *encode) {
  *encode = cipher.Encrypt(buffer, len);
}

kl::Status Decode(const uint8_t *buffer, size_t len,
                  std::vector<uint8_t> *decode) {
  *decode = cipher.Decrypt(buffer, len);
  return kl::Ok();
}

}  // namespace (anonymous)

Coding DemoCoding() {
  Coding ret;
  ret.Encode = std::bind(&Encode, std::placeholders::_1, std::placeholders::_2,
                         std::placeholders::_3);
  ret.Decode = std::bind(&Decode, std::placeholders::_1, std::placeholders::_2,
                         std::placeholders::_3);
  return ret;
}

}  // namespace kale
