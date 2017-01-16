// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
// Use of this source code is governed by the BSD license that can be found in
// the LICENSE file.

// Just a simple wrapper for zstd's c library.

#ifndef KALE_ZSTD_H_
#define KALE_ZSTD_H_
#include <cstdint>
#include <cstdlib>
#include <vector>

#include "kl/error.h"
#include "zstd.h"

namespace kale {
namespace zstd {

inline kl::Result<std::vector<uint8_t>> Compress(const uint8_t *source,
                                                 size_t len) {
  size_t capacity = ZSTD_compressBound(len);
  std::vector<uint8_t> result;
  result.resize(capacity);
  size_t real_size =
      ZSTD_compress(reinterpret_cast<char *>(&result[0]), result.size(),
                    reinterpret_cast<const char *>(source), len, 1);
  if (ZSTD_isError(real_size)) {
    return kl::Err(ZSTD_getErrorName(real_size));
  }
  result.resize(real_size);
  return kl::Ok(std::move(result));
}

inline kl::Result<std::vector<uint8_t>> Decompress(const uint8_t *source,
                                                   size_t len) {
  size_t capacity =
      ZSTD_getDecompressedSize(reinterpret_cast<const char *>(source), len);
  if (capacity == 0) {
    return kl::Err("unkonwn original size");
  }
  std::vector<uint8_t> result;
  result.resize(capacity);
  size_t real_size =
      ZSTD_decompress(reinterpret_cast<char *>(&result[0]), result.size(),
                      reinterpret_cast<const char *>(source), len);
  if (real_size != capacity) {
    return kl::Err(ZSTD_getErrorName(real_size));
  }
  return kl::Ok(std::move(result));
}

}  // namespace zstd
}  // namespace kale
#endif
