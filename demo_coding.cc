// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
// Use of this source code is governed by the BSD license that can be found in
// the LICENSE file.

#include "kale/demo_coding.h"
#include "kale/arcfour.h"
#include "kl/error.h"

namespace kale {

Coding DemoCoding(const uint8_t *key, size_t len) {
  auto cipher = std::make_shared<arcfour::Cipher>(key, len);
  Coding ret;
  ret.Encode = [cipher](const uint8_t *buffer, size_t len,
                        std::vector<uint8_t> *encode) {
    *encode = cipher->Decrypt(buffer, len);
  };
  ret.Decode = [cipher](const uint8_t *buffer, size_t len,
                        std::vector<uint8_t> *decode) {
    *decode = cipher->Decrypt(buffer, len);
    return kl::Ok();
  };
  return ret;
}

}  // namespace kale
