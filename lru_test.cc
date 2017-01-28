// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
// Use of this source code is governed by the BSD license that can be found in
// the LICENSE file.

#include <algorithm>
#include <vector>

#include "kl/logger.h"
#include "kl/testkit.h"
#include "lru.h"

TEST(kale::LRU, Constructor, 16) {}

TEST(kale::LRU, CheckSize, 1024) {
  for (size_t i = 0; i < 1024; ++i) {
    Use(i);
  }
  auto p = head_;
  ASSERT(p != nullptr);
  size_t size = 0;
  while (p) {
    ++size;
    p = p->next;
  }
  ASSERT(size == 1024);
}

TEST(kale::LRU, GetLRU, 16) {
  std::vector<uint32_t> v;
  for (uint32_t i = 0; i < 16; ++i) {
    v.push_back(i);
  }
  std::random_shuffle(v.begin(), v.end());
  for (size_t i = 0; i < v.size() - 1; ++i) {
    Use(v[i]);
    ASSERT(Head() == v[i]);
  }
  uint32_t tail = Tail();
  ASSERT(tail == v.back());
  ASSERT(GetLRU() == tail);
}

TEST(kale::LRU, GetLRU1, 16) {
  for (uint32_t i = 0; i < 16; ++i) {
    KL_DEBUG("%u", GetLRU());
  }
}

int main() { return KL_TEST(); }
