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
#include "kl/logger.h"
#include "kl/netdev.h"
#include "kl/tcp.h"
#include "kl/testkit.h"
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

TEST(T, LoopTun) {
  const std::string message("imfao|wtf|rofl");
  const char *host = "10.0.0.1";
  const char *mask = "255.255.255.255";
  uint16_t port = 4000;
  // launch 3 threads, loop tun thread, listen thread and connect thread.
  // loop tun thread will wait for listen thread and connect thread exit.
  kl::WaitGroup tun_wait;
  tun_wait.Add();
  tun_wait.Add();
  auto tun_if = kale::AllocateTunInterface("tun23", host, mask);
  ASSERT(tun_if);
  auto tun_thread = std::thread([&tun_wait, tun_fd = *tun_if ] {
    KL_DEBUG("tun thread starts to work");
    kl::env::Defer defer([] { KL_DEBUG("tun thread exiting"); });
    defer([tun_fd] { ::close(tun_fd); });
    tun_wait.Wait();
  });
  // prepare listen
  auto listen = kl::tcp::Listen(host, port);
  ASSERT(listen);
  int listen_fd = *listen;
  // listen thread
  std::thread([&message, &tun_wait, listen_fd] {
    KL_DEBUG("listen thread starts to work");
    kl::env::Defer defer([] { KL_DEBUG("listen thread exiting"); });
    defer([listen_fd] { ::close(listen_fd); });
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
  std::thread([&tun_wait, &message, host, port]() {
    KL_DEBUG("connect thread starts to work");
    kl::env::Defer defer([] { KL_DEBUG("connect thread exiting"); });
    auto connect = kl::tcp::BlockingConnect(host, port);
    ASSERT(connect);
    int fd = *connect;
    defer([fd] { ::close(fd); });
    int nwrite = ::write(fd, &message[0], message.size());
    ASSERT(nwrite == message.size());
    tun_wait.Done();
  }).detach();
  tun_thread.join();
  // std::this_thread::sleep_for(std::chrono::duration<float>(100));
}

int main() { return KL_TEST(); }
