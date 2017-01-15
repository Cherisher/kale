// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
// Use of this source code is governed by the BSD license that can be found in
// the LICENSE file.

#include "resolver.h"
#include "ip_packet.h"
#include "kl/logger.h"
#include "kl/testkit.h"
#include "kl/udp.h"

class T {};

TEST(T, BuildQuery) {
  auto query = kale::Resolver::BuildQuery("www.google.com", 0x2c13);
  const char *origin = "\x2c\x13\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03"
                       "\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f"
                       "\x6d\x00\x00\x01\x00\x01";
  for (size_t i = 0; i < query.size(); ++i) {
    // KL_DEBUG("%d\t0x%02x 0x%02x", i, origin[i], query[i]);
    ASSERT(query[i] == static_cast<uint8_t>(origin[i]));
  }
}

TEST(T, DNSName) {
  uint8_t buf[65536];
  int len;
  len = kale::ip_packet::BuildNetworkBuffer(buf, sizeof(buf), "bsbsbsb", 0x03,
                                            "www", 0x06, "google", 0x03, "com",
                                            0x0);
  std::string name = kale::Resolver::DNSName("www.google.com");
  ASSERT(len == static_cast<int>(name.size()));
  char *buf_str = reinterpret_cast<char *>(buf);
  ASSERT(name == std::string(buf_str, buf_str + len));
  std::string domain = kale::Resolver::FromDNSName(
      reinterpret_cast<const uint8_t *>(name.data()));
  ASSERT(domain == "www.google.com");
  int skip = kale::Resolver::SkipDNSName(
      reinterpret_cast<const uint8_t *>(name.data()));
  ASSERT(skip == static_cast<int>(name.size()));
}

TEST(T, Query) {
  auto udp_sock = kl::udp::Socket();
  ASSERT(udp_sock);
  int fd = *udp_sock;
  kale::Resolver resovler(fd);
  auto query = resovler.SendQuery("www.google.com", "8.8.8.8", 53);
  ASSERT(query);
  auto response = resovler.WaitForResult(*query, 5000);
  ASSERT(response);
  for (auto &answer : *response) {
    KL_DEBUG("%s", answer.c_str());
  }
}

int main() { return KL_TEST(); }
