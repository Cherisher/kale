// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <iostream>
#include <sstream>
#include <thread>

#include "kl/env.h"
#include "kl/epoll.h"
#include "kl/inet.h"
#include "kl/logger.h"
#include "kl/netdev.h"
#include "kl/tcp.h"
#include "kl/testkit.h"
#include "kl/udp.h"
#include "kl/wait_group.h"
#include "tun.h"

class T {};

TEST(T, Allocation) {
  std::string tun_name(kale::RandomTunName());
  auto alloc = kale::AllocateTun(tun_name.c_str());
  ASSERT(alloc);
  auto ifindex = kl::netdev::RetrieveIFIndex(tun_name.c_str());
  ASSERT(ifindex);
  ::close(*alloc);
}

TEST(T, UDPTun) {
  const std::string message("imfao|wtf|rofl");
  const char *addr = "10.0.0.1";
  const char *dstaddr = "10.0.0.2";
  const char *mask = "255.255.255.255";
  uint16_t port = 4000;
  auto tun_if = kale::AllocateTunInterface("tun23", addr, dstaddr, mask);
  ASSERT(tun_if);
  int tun_fd = *tun_if;
  kl::env::Defer defer([fd = tun_fd] { ::close(fd); });
  ASSERT(kl::netdev::InterfaceUp("tun23"));
  auto add_route = kl::netdev::AddRoute("tun23", addr, mask);
  if (!add_route) {
    KL_DEBUG(add_route.Err().ToCString());
  }
  ASSERT(add_route);
  auto send_thread = std::thread([addr, port, message, dstaddr] {
    auto sock = kl::udp::Socket();
    ASSERT(sock);
    kl::env::Defer defer([fd = *sock] { ::close(fd); });
    auto bind = kl::inet::Bind(*sock, addr, port);
    if (!bind) {
      KL_DEBUG(bind.Err().ToCString());
    }
    ASSERT(bind);
    auto send = kl::inet::Sendto(*sock, message.c_str(), message.size(), 0,
                                 dstaddr, 80);
    ASSERT(send);
    KL_DEBUG("send %d bytes", *send);
  });
  char buf[65536];
  KL_DEBUG("waiting for traffic...");
  int nread = ::read(tun_fd, buf, sizeof(buf));
  // minimum ip header size + minimum udp header size = 20 + 8 = 28
  ASSERT(nread >= 28);
  KL_DEBUG("read %d bytes", nread);
  buf[nread] = '\0';
  ASSERT(std::string(buf + 28) == message);
  send_thread.join();
}

TEST(T, LoopTun) {
  const std::string message("imfao|wtf|rofl");
  const char *addr = "10.0.0.1";
  const char *dstaddr = "10.0.0.2";
  const char *mask = "255.255.255.255";
  uint16_t port = 4000;
  // launch 3 threads, loop tun thread, listen thread and connect thread.
  // loop tun thread will wait for listen thread and connect thread exit.
  kl::WaitGroup tun_wait;
  tun_wait.Add();
  tun_wait.Add();
  auto tun_if = kale::AllocateTunInterface("tun23", addr, dstaddr, mask);
  ASSERT(tun_if);
  auto tun_thread = std::thread([&tun_wait, tun_fd = *tun_if ] {
    KL_DEBUG("tun thread starts to work");
    kl::env::Defer defer([] { KL_DEBUG("tun thread exiting"); });
    defer([tun_fd] { ::close(tun_fd); });
    // CAUTION: due to loopback link, i.e. 127.0.0.1, ip packets actually won't
    // go via the tun
    tun_wait.Wait();
  });
  // prepare listen
  auto listen = kl::tcp::Listen(addr, port);
  ASSERT(listen);
  int listen_fd = *listen;
  // listen thread
  std::thread([&message, &tun_wait, listen_fd] {
    KL_DEBUG("listen thread starts to work");
    kl::env::Defer defer([] { KL_DEBUG("listen thread exiting"); });
    defer([listen_fd] {
      ::close(listen_fd);
      KL_DEBUG("listen closed");
    });
    struct sockaddr_in addr;
    socklen_t len;
    int conn_fd =
        ::accept(listen_fd, reinterpret_cast<struct sockaddr *>(&addr), &len);
    ASSERT(conn_fd >= 0);
    defer([conn_fd] { ::close(conn_fd); });
    char buf[1024];
    int nread = ::read(conn_fd, buf, sizeof(buf));
    ASSERT(nread >= 0 && nread <= sizeof(buf));
    buf[nread] = '\0';
    ASSERT(message == buf);
    KL_DEBUG(buf);
    tun_wait.Done();
  }).detach();
  // connect thread
  std::thread([&tun_wait, &message, addr, port]() {
    KL_DEBUG("connect thread starts to work");
    kl::env::Defer defer([] { KL_DEBUG("connect thread exiting"); });
    auto connect = kl::tcp::BlockingConnect(addr, port);
    ASSERT(connect);
    int fd = *connect;
    defer([fd] {
      ::close(fd);
      KL_DEBUG("connection closed");
    });
    int nwrite = ::write(fd, &message[0], message.size());
    ASSERT(nwrite == message.size());
    tun_wait.Done();
  }).detach();
  tun_thread.join();
  // std::this_thread::sleep_for(std::chrono::duration<float>(10));
}

int main() { return KL_TEST(); }
