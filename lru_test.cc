// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#include "lru.h"
#include "kl/logger.h"
#include "kl/testkit.h"

TEST(kale::LRU, Constructor, 16) {}

TEST(kale::LRU, GetLRU, 16) {
  for (uint32_t i = 0; i < 15; ++i) {
    Use(i);
  }
  ASSERT(GetLRU() == 15);
}

TEST(kale::LRU, GetLRU1, 16) {
  for (uint32_t i = 0; i < 16; ++i) {
    KL_DEBUG("%u", GetLRU());
  }
}

int main() { return KL_TEST(); }
