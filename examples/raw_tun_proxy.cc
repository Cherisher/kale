// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#include <unistd.h>

#include <cstdlib>
#include <iostream>
#include <string>

#include "ip_packet.h"
#include "kl/inet.h"
#include "kl/logger.h"
#include "kl/string.h"
#include "kl/udp.h"
#include "tun.h"

void PrintUsage(int argc, char *argv[]) {
  std::fprintf(stderr, "%s: \n"
                       "    -r <remote_host:remote_port>\n"
                       "    -t <tun_name>\n"
                       "    -a <tun_addr>\n"
                       "    -d <tun_dstaddr>\n"
                       "    -m <tun_mask>\n",
               argv[0]);
}

int main(int argc, char *argv[]) {
  std::string remote_host;
  uint16_t remote_port = 0;                 // -r
  std::string tun_name("tun0");             // -t
  std::string tun_addr("10.0.0.1");         // -a
  std::string tun_dstaddr("10.0.0.2");      // -d
  std::string tun_mask("255.255.255.255");  // -m
  int opt = 0;
  while ((opt = ::getopt(argc, argv, "r:t:a:d:m:h")) != -1) {
    switch (opt) {
      case 'r': {
        auto split = kl::inet::SplitAddr(optarg, &remote_host, &remote_port);
        if (!split) {
          std::cerr << split.Err().ToCString() << "\n";
          ::exit(1);
        }
        // KL_DEBUG("remote host %s:%u", remote_host.c_str(), remote_port);
        break;
      }
      case 't': {
        tun_name = optarg;
        break;
      }
      case 'a': {
        tun_addr = optarg;
        break;
      }
      case 'd': {
        tun_dstaddr = optarg;
        break;
      }
      case 'm': {
        tun_mask = optarg;
        break;
      }
      case 'h':
      default:
        PrintUsage(argc, argv);
        ::exit(1);
    }
  }
  if (remote_host.empty() || remote_port == 0) {
    std::fprintf(stderr, "%s: invalid remote host %s:%u\n", argv[0],
                 remote_host.c_str(), remote_port);
    PrintUsage(argc, argv);
    ::exit(1);
  }
  return 0;
}
