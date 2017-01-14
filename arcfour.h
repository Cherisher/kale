// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#ifndef KALE_ARCFOUR_H_
#define KALE_ARCFOUR_H_
#include <cstdint>
#include <cstdlib>
#include <vector>

namespace kale {
namespace arcfour {
class Cipher {
public:
  Cipher(const uint8_t *key, size_t len);
  std::vector<uint8_t> Encrypt(const uint8_t *buffer, size_t len);
  std::vector<uint8_t> Decrypt(const uint8_t *buffer, size_t len);

private:
  uint8_t state_[256];
};

}  // namespace arcfour
}  // namespace kale
#endif
