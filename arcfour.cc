// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#include <algorithm>

#include "arcfour.h"

namespace kale {
namespace arcfour {

Cipher::Cipher(const uint8_t *key, size_t len) {
  for (size_t i = 0; i < sizeof(state_); ++i) {
    state_[i] = i;
  }
  for (size_t i = 0, j = 0; i < sizeof(state_); ++i) {
    j = (j + state_[i] + key[i % len]) & 0xff;
    std::swap(state_[i], state_[j]);
  }
}

std::vector<uint8_t> Cipher::Encrypt(const uint8_t *buffer, size_t len) {
  std::vector<uint8_t> result;
  size_t j = 0, k = 0;
  for (size_t i = 0; i < len; ++i) {
    j = (j + 1) & 0xff;
    k = (k + state_[j]) & 0xff;
    result.push_back(buffer[i] ^ state_[(state_[j] + state_[k]) & 0xff]);
  }
  return result;
}

std::vector<uint8_t> Cipher::Decrypt(const uint8_t *buffer, size_t len) {
  return Encrypt(buffer, len);
}

}  // arcfour
}  // namespace kale
