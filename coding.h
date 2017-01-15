// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#ifndef KALE_CODING_H_
#define KALE_CODING_H_
#include <cstdint>
#include <functional>
#include <vector>

#include "kl/error.h"

namespace kale {

struct Coding {
  std::function<void(const uint8_t *buffer, size_t len,
                     std::vector<uint8_t> *encode)>
      Encode;
  std::function<kl::Status(const uint8_t *buffer, size_t len,
                           std::vector<uint8_t> *decode)>
      Decode;
};

}  // namespace kale

#endif
