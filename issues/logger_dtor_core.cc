#include <unistd.h>

#include <atomic>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "kale/arcfour.h"
#include "kale/coding.h"
#include "kale/demo_coding.h"
// FIXME(luokai): These headers placed before kl/logger.h leads to coredump
// #include "kale/ipv4.h"
// #include "kale/ipv4_tcp.h"
// #include "kale/ipv4_udp.h"
#include "kale/tun.h"
#include "kl/env.h"
#include "kl/epoll.h"
#include "kl/hexdump.h"
#include "kl/inet.h"
#include "kl/logger.h"
// Note: Put here will work.
#include "kale/ipv4.h"
#include "kale/ipv4_tcp.h"
#include "kale/ipv4_udp.h"
#include "kl/netdev.h"
#include "kl/scheduler.h"
#include "kl/slice.h"
#include "kl/string.h"
#include "kl/udp.h"

int main() {
  kl::logging::Logger new_logger([](const std::string& message) {
    ::write(2, message.data(), message.size());
  });
  return 0;
}
