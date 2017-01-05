// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#ifndef KALE_TUN_H_
#define KALE_TUN_H_
#include <string>
#include <tuple>

#include "kl/error.h"

namespace kale {

extern const char *kTunDevRoot;

// RETURN: (fd, ifname)
kl::Result<std::tuple<int, std::string>> AllocateTun(const char *ifname);
std::string RandomTunName();

}  // namespace kale
#endif
