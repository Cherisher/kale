// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#include "arcfour.h"
#include "ip_packet.h"
#include "kl/testkit.h"

static uint8_t kKey[4] = {0xff, 0xbb, 0xcc, 0xdd};

TEST(kale::arcfour::Cipher, Encryption, kKey, sizeof(kKey)) {
  const std::string message("Reorders the elements in the given range [first, "
                            "last) such that each possible permutation of "
                            "those elements has equal probability of "
                            "appearance. ");
  auto enc = Encrypt(reinterpret_cast<const uint8_t *>(message.data()),
                     message.size());
  const std::string message1("Linear in the distance between first and last ");
  auto enc1 = Encrypt(reinterpret_cast<const uint8_t *>(message1.data()),
                      message1.size());
  // kale::ip_packet::Dump(stderr, enc.data(), enc.size());
  auto dec = Decrypt(enc.data(), enc.size());
  std::string check(dec.begin(), dec.end());
  auto dec1 = Decrypt(enc1.data(), enc1.size());
  std::string check1(dec1.begin(), dec1.end());
  ASSERT(check == message);
  ASSERT(check1 == message1);
}

int main() { return KL_TEST(); }
