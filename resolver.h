// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#include <vector>

#include "kl/error.h"

namespace kale {

class Resolver {
public:
  static kl::Result<std::vector<std::string>> NsLookup(int fd, const char *name,
                                                       const char *server);
  static std::vector<uint8_t> BuildQuery(const char *name,
                                         uint16_t transaction_id);
  static std::string DNSName(const char *name);
  explicit Resolver(int fd);
  ~Resolver();

private:
  int fd_;
  uint16_t transaction_id_;
};

}  // namespace kale
