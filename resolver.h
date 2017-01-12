// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#include <vector>

#include "kl/error.h"

namespace kale {

class Resolver {
public:
  static kl::Result<std::vector<std::string>>
  Query(int fd, const char *name, const char *server, uint16_t port);

  static std::vector<uint8_t> BuildQuery(const char *name,
                                         uint16_t transaction_id);
  static std::string DNSName(const char *name);
  explicit Resolver(int fd);
  kl::Result<std::vector<std::string>> Query(const char *name,
                                             const char *server, uint16_t port);
  ~Resolver();

private:
  int fd_;
  uint16_t transaction_id_;
};

}  // namespace kale
