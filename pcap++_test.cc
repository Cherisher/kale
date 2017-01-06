// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#include "pcap++.h"
#include "kl/logger.h"
#include "kl/testkit.h"

class T {};

TEST(T, DefaultDevice) {
  auto device = kale::pcap::DefaultDevice();
  ASSERT(device);
  KL_DEBUG("default device %s", (*device).c_str());
}

int main() { return KL_TEST(); }
