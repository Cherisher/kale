// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#include <arpa/inet.h>
#include <unistd.h>

#include "ip_packet.h"
#include "resolver.h"

namespace kale {

Resolver::Resolver(int fd) : fd_(fd), transaction_id_(0) { assert(fd_ >= 0); }

Resolver::~Resolver() {
  if (fd_ >= 0) {
    ::close(fd_);
  }
}

std::string Resolver::DNSName(const char *name) {
  const char *ptr = name;
  while (*ptr != 0) {
    ++ptr;
  }
  std::string result;
  result.resize(ptr - name + 2);
  int i = result.size() - 1;
  uint8_t count = 0xff;
  while (ptr >= name) {
    assert(i >= 0);
    if (*ptr == '.') {
      result[i--] = static_cast<char>(count);
      count = 0;
    } else {
      result[i--] = *ptr;
      ++count;
    }
    --ptr;
  }
  assert(i == 0);
  result[i] = static_cast<char>(count);
  return result;
}

std::vector<uint8_t> Resolver::BuildQuery(const char *name,
                                          uint16_t transaction_id) {
  std::vector<uint8_t> result;
  uint8_t header[12];
  int len = ip_packet::BuildNetworkBuffer(header, sizeof(header), "wbbwwww",
                                          htons(transaction_id), 0x01, 0x00,
                                          htons(1), 0, 0, 0);
  assert(len == 12);
  result.insert(result.end(), header, header + len);
  std::string domain = DNSName(name);
  result.insert(result.end(), domain.data(), domain.data() + domain.size());
  result.insert(result.end(), 0x00);
  result.insert(result.end(), 0x01);
  result.insert(result.end(), 0x00);
  result.insert(result.end(), 0x01);
  return result;
}

}  // namespace kale
