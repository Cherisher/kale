// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#include "lo_tun.h"
#include "kl/testkit.h"

TEST(kale::LoTun, RunWithoutEventLoop, "tun17", "10.0.0.1", "10.0.0.2",
     "255.255.255.0") {
  ASSERT(RunWithoutEventLoop());
}

TEST(kale::LoTun, Run, "tun17", "10.0.0.1", "10.0.0.2", "255.255.255.0") {
  ASSERT(Run());
}

int main() { KL_TEST(); }
