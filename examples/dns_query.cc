// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#include "kl/logger.h"
#include "kl/netdev.h"
#include "kl/udp.h"
#include "resolver.h"

int main() {
  const char *ifname = "tun0";
  const char *server = "8.8.8.8";
  uint16_t port = 53;
  auto udp = kl::udp::Socket();
  assert(udp);
  auto bind_if = kl::netdev::BindInterface(*udp, ifname);
  assert(bind_if);
  kl::netdev::AddRoute(ifname, server);
  kale::Resolver resolver(*udp);
  auto query = resolver.SendQuery("www.facebook.com", server, port);
  assert(query);
  KL_DEBUG("local addr %s", resolver.LocalAddr().c_str());
  auto resp = resolver.WaitForResult(*query);
  assert(resp);
  return 0;
}
