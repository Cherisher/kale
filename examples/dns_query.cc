// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
// Use of this source code is governed by the BSD license that can be found in
// the LICENSE file.

#include "kl/logger.h"
#include "kl/netdev.h"
#include "kl/udp.h"
#include "resolver.h"

int main() {
  const char *server = "8.8.8.8";
  uint16_t port = 53;
  auto udp = kl::udp::Socket();
  assert(udp);
  kale::Resolver resolver(*udp);
  auto query = resolver.SendQuery("www.facebook.com", server, port);
  assert(query);
  KL_DEBUG("local addr %s", resolver.LocalAddr().c_str());
  auto resp = resolver.WaitForResult(*query, 10000);
  assert(resp);
  for (auto &answer : *resp) {
    KL_DEBUG("%s", answer.c_str());
  }
  return 0;
}
