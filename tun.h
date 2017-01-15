// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
// Use of this source code is governed by the BSD license that can be found in
// the LICENSE file.

#ifndef KALE_TUN_H_
#define KALE_TUN_H_
#include <string>
#include <tuple>

#include "kl/epoll.h"
#include "kl/error.h"

namespace kale {

extern const char *kTunDevRoot;

// RETURN: fd
kl::Result<int> AllocateTun(const char *ifname);
std::string RandomTunName();

kl::Result<int> RawIPv4Socket();

}  // namespace kale
#endif
