// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#include <atomic>
#include <vector>

#include "kl/error.h"

namespace kale {

class Resolver {
public:
  static std::vector<uint8_t> BuildQuery(const char *name,
                                         uint16_t transaction_id);
  static std::string DNSName(const char *name);
  explicit Resolver(int fd);
  // RETURNS: transaction id
  kl::Result<uint16_t> SendQuery(const char *name, const char *server,
                                 uint16_t port);
  kl::Result<std::vector<std::string>> WaitForResult(uint16_t transaction_id);
  ~Resolver();

private:
  int fd_;
  std::atomic<uint16_t> transaction_id_;
};

}  // namespace kale
