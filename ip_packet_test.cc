// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#include "ip_packet.h"
#include "kl/logger.h"
#include "kl/testkit.h"

class T {};

TEST(T, BuildNetworkBuffer0) {
  int len;
  len = kale::ip_packet::BuildNetworkBuffer(nullptr, 0, "bbbb", 0, 1, 2, 3);
  ASSERT(len == 4);
  len = kale::ip_packet::BuildNetworkBuffer(nullptr, 0, "wwww", 0, 1, 2, 3);
  ASSERT(len == 8);
  len = kale::ip_packet::BuildNetworkBuffer(nullptr, 0, "qqqq", 0, 1, 2, 3);
  ASSERT(len == 16);
  len = kale::ip_packet::BuildNetworkBuffer(nullptr, 0, "s", "");
  ASSERT(len == 0);
  len = kale::ip_packet::BuildNetworkBuffer(nullptr, 0, "0s", "abcd");
  ASSERT(len == 0);
  len = kale::ip_packet::BuildNetworkBuffer(nullptr, 0, "1s", "abcd");
  ASSERT(len == 1);
}

int main() { return KL_TEST(); }
