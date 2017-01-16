// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
// Use of this source code is governed by the BSD license that can be found in
// the LICENSE file.

#ifndef KALE_RESOLVER_H_
#define KALE_RESOLVER_H_
#include <atomic>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "kl/error.h"
#include "kl/rwlock.h"

namespace kale {

class Resolver {
public:
  static std::vector<uint8_t> BuildQuery(const char *name,
                                         uint16_t transaction_id);
  static std::string DNSName(const char *name);
  static std::string FromDNSName(const uint8_t *base);
  // RETURNS: number of bytes skipped
  static int SkipDNSName(const uint8_t *base);
  // RETURNS: number of bytes skipped
  static kl::Result<int> RetrieveRecord(const uint8_t *base,
                                        std::string *record);
  // RETURNS: (transaction_id, query_result_list)
  static kl::Result<std::pair<uint16_t, std::vector<std::string>>>
  ParseResponse(const uint8_t *packet, size_t len);
  explicit Resolver(int fd);
  // RETURNS: <transaction id>
  kl::Result<uint16_t> SendQuery(const char *name, const char *server,
                                 uint16_t port);
  kl::Result<uint16_t> SendInverseQuery(const char *addr, const char *server,
                                        uint16_t port);
  // RETURNS: <list of resource records>
  kl::Result<std::vector<std::string>> WaitForResult(uint16_t transaction_id,
                                                     int timeout);
  std::string LocalAddr();
  ~Resolver();

private:
  void LaunchListenThread();
  void StopListenThread();
  void SetExitReason(const char *func, int line, const char *reason);
  int fd_;
  std::string addr_;
  uint16_t port_;
  std::atomic<uint16_t> transaction_id_;
  std::map<uint16_t, std::vector<std::string>> response_;
  std::atomic<bool> stop_listen_;
  std::unique_ptr<std::thread> listen_thread_;
  std::string exit_reason_;
  std::condition_variable cv_;
  std::mutex mutex_;
};

}  // namespace kale
#endif
