// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#include "demo_coding.h"
#include "arcfour.h"
#include "kl/error.h"
#include "snappy.h"

namespace kale {

namespace {

uint8_t kKey[4] = {0xc0, 0xde, 0xc0, 0xde};

kale::arcfour::Cipher cipher(kKey, sizeof(kKey));

void Encode(const uint8_t *buffer, size_t len, std::vector<uint8_t> *encode) {
  *encode = cipher.Encrypt(buffer, len);
  std::string compress;
  snappy::Compress(reinterpret_cast<const char *>(encode->data()),
                   encode->size(), &compress);
  *encode = std::vector<uint8_t>(compress.begin(), compress.end());
}

kl::Status Decode(const uint8_t *buffer, size_t len,
                  std::vector<uint8_t> *decode) {
  std::string uncompress;
  bool ok = snappy::Uncompress(reinterpret_cast<const char *>(buffer), len,
                               &uncompress);
  if (!ok) {
    return kl::Err("failed to uncompress from buffer");
  }
  *decode = cipher.Decrypt(reinterpret_cast<const uint8_t *>(uncompress.data()),
                           uncompress.size());
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
