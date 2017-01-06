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

TEST(kale::pcap::Sniffer, Constructor, "lo") {}

TEST(T, CompileAndInstall) {
  auto device = kale::pcap::DefaultDevice();
  ASSERT(device);
  kale::pcap::Sniffer sniffer((*device).c_str());
  auto compile = sniffer.CompileAndInstall("udp and portrange 50000-65535");
  ASSERT(compile);
  auto fail_compile =
      sniffer.CompileAndInstall("udp and portrange 50000-65536");
  ASSERT(!fail_compile);
}

int main() { return KL_TEST(); }
