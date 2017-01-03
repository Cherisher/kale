// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#include <unistd.h>

#include "kl/testkit.h"
#include "tun.h"

class T {};

TEST(T, Allocation) {
  auto alloc = kale::AllocateTun("tun17");
  ASSERT(alloc);
  ::close(std::get<0>(*alloc));
}

int main() { return KL_TEST(); }
