// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
// Use of this source code is governed by the BSD license that can be found in
// the LICENSE file.

#include <arpa/inet.h>
#include <thread>
#include <unistd.h>

#include "kale/ip_packet.h"
#include "kale/resolver.h"
#include "kl/env.h"
#include "kl/epoll.h"
#include "kl/inet.h"
#include "kl/logger.h"

namespace kale {

Resolver::Resolver(int fd) : fd_(fd), transaction_id_(0), stop_listen_(false) {
  assert(fd_ >= 0);
  // Launch a thread to receive response
  LaunchListenThread();
}

void Resolver::SetExitReason(const char *func, int line, const char *reason) {
  KL_ERROR("%s:%d: %s", func, line, reason);
  exit_reason_ = reason;
}

kl::Result<std::pair<uint16_t, std::vector<std::string>>>
Resolver::ParseResponse(const uint8_t *packet, size_t len) {
  if (len < 12) {
    return kl::Err("insufficient header length");
  }
  // refer to https://www.ietf.org/rfc/rfc1035.txt
  uint8_t response_code = *(packet + 3) & 0x0f;
  if (response_code != 0) {
    return kl::Err(response_code, "failed to fectch records, error code %u",
                   response_code);
  }
  std::vector<std::string> result;
  uint16_t transaction_id = ntohs(*reinterpret_cast<const uint16_t *>(packet));
  uint16_t question_count =
      ntohs(*reinterpret_cast<const uint16_t *>(packet + 4));
  // KL_DEBUG("number of questions: %u", question_count);
  uint16_t answer_count =
      ntohs(*reinterpret_cast<const uint16_t *>(packet + 6));
  // KL_DEBUG("number of answers: %u", answer_count);
  uint16_t nameserver_count =
      ntohs(*reinterpret_cast<const uint16_t *>(packet + 8));
  uint16_t additional_count =
      ntohs(*reinterpret_cast<const uint16_t *>(packet + 10));
  const uint8_t *ptr = packet + 12;
  for (uint16_t i = 0; i < question_count; ++i) {
    int count = SkipDNSName(ptr);
    ptr += count + 4;
  }
  std::string record;
  for (uint16_t i = 0; i < answer_count; ++i) {
    auto count = RetrieveRecord(ptr, &record);
    if (!count) {
      continue;
    }
    ptr += *count;
    result.push_back(std::move(record));
  }
  for (uint16_t i = 0; i < nameserver_count; ++i) {
    auto count = RetrieveRecord(ptr, &record);
    if (!count) {
      continue;
    }
    ptr += *count;
    result.push_back(std::move(record));
  }
  for (uint16_t i = 0; i < additional_count; ++i) {
    auto count = RetrieveRecord(ptr, &record);
    if (!count) {
      continue;
    }
    ptr += *count;
    result.push_back(std::move(record));
  }
  return kl::Ok(std::make_pair(transaction_id, std::move(result)));
}

// TODO(Kai Luo): support more type
// Support only IN class at present
kl::Result<int> Resolver::RetrieveRecord(const uint8_t *base,
                                         std::string *record) {
  const uint8_t *ptr = base;
  // is a pointer
  if ((*ptr & 0xc0) == 0xc0) {
    ptr += 2;
  } else {
    ptr += SkipDNSName(ptr);
  }
  uint16_t type = ntohs(*reinterpret_cast<const uint16_t *>(ptr));
  ptr += 2;
  uint16_t cls = ntohs(*reinterpret_cast<const uint16_t *>(ptr));
  if (type != 0x0001 || cls != 0x0001) {
    return kl::Err("unimplemented type or class");
  }
  ptr += 2;
  // skip ttl
  ptr += 4;
  uint16_t length = ntohs(*reinterpret_cast<const uint16_t *>(ptr));
  ptr += 2;
  assert(length == 4);
  *record = inet_ntoa(in_addr{
      .s_addr = *reinterpret_cast<const uint32_t *>(ptr),
  });
  ptr += 4;
  return kl::Ok(static_cast<int>(ptr - base));
}

void Resolver::LaunchListenThread() {
  listen_thread_ = std::make_unique<std::thread>([this] {
    kl::env::SetNonBlocking(fd_);
    kl::Epoll epoll;
    epoll.AddFd(fd_, EPOLLET | EPOLLIN);
    while (!stop_listen_) {
      auto wait = epoll.Wait(1, 1000);
      if (!wait) {
        SetExitReason(__FUNCTION__, __LINE__, wait.Err().ToCString());
        return;
      }
      auto &event_list = *wait;
      if (event_list.size() == 0) {
        continue;
      }
      auto &event = event_list[0];
      int fd = event.data.fd;
      uint32_t events = event.events;
      if (events & EPOLLIN) {
        char buf[65536];
        while (true) {
          int nread = ::read(fd, buf, sizeof(buf));
          if (nread < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
              SetExitReason(__FUNCTION__, __LINE__, std::strerror(errno));
              return;
            } else {
              break;
            }
          }
          assert(nread >= 0);
          auto parse =
              ParseResponse(reinterpret_cast<const uint8_t *>(buf), nread);
          if (!parse) {
            KL_ERROR(parse.Err().ToCString());
            continue;
          }
          // Due to incremental transaction id, lock might be not needed
          std::unique_lock<std::mutex> _(mutex_);
          response_.insert(std::move(*parse));
          cv_.notify_all();
        }
      }
      if (events & EPOLLERR) {
        int err = kl::inet::SocketError(fd);
        if (err != 0) {
          SetExitReason(__FUNCTION__, __LINE__, std::strerror(err));
        } else {
          SetExitReason(__FUNCTION__, __LINE__, "EPOLLERR");
        }
      }
    }
  });
}

void Resolver::StopListenThread() {
  stop_listen_.store(true);
  listen_thread_->join();
}

Resolver::~Resolver() {
  StopListenThread();
  if (fd_ >= 0) {
    ::close(fd_);
  }
}

std::string Resolver::FromDNSName(const uint8_t *base) {
  std::vector<char> tmp;
  uint8_t count = *base;
  while (count != 0) {
    while (count-- > 0) {
      tmp.push_back(*(++base));
    }
    count = *(++base);
    if (count) {
      tmp.push_back('.');
    }
  }
  return std::string(tmp.data(), tmp.size());
}

int Resolver::SkipDNSName(const uint8_t *ptr) {
  const uint8_t *base = ptr;
  uint8_t count = *base;
  while (count != 0) {
    ptr += (count + 1);
    count = *ptr;
  }
  return ptr - base + 1;
}

std::string Resolver::DNSName(const char *name) {
  const char *ptr = name;
  while (*ptr != 0) {
    ++ptr;
  }
  std::string result;
  result.resize(ptr - name + 2);
  int i = result.size() - 1;
  uint8_t count = 0xff;
  while (ptr >= name) {
    assert(i >= 0);
    if (*ptr == '.') {
      result[i--] = static_cast<char>(count);
      count = 0;
    } else {
      result[i--] = *ptr;
      ++count;
    }
    --ptr;
  }
  assert(i == 0);
  result[i] = static_cast<char>(count);
  return result;
}

kl::Result<uint16_t> Resolver::SendQuery(const char *name, const char *server,
                                         uint16_t port) {
  uint16_t id = transaction_id_++;
  auto query = BuildQuery(name, id);
  auto send =
      kl::inet::Sendto(fd_, query.data(), query.size(), 0, server, port);
  if (!send) {
    return kl::Err(send.MoveErr());
  }
  return kl::Ok(id);
}

kl::Result<std::vector<std::string>>
Resolver::WaitForResult(uint16_t transaction_id, int timeout) {
  std::unique_lock<std::mutex> l(mutex_);
  decltype(response_.begin()) iter;
  if (cv_.wait_for(l, std::chrono::milliseconds(timeout),
                   [&iter, this, transaction_id] {
                     iter = response_.find(transaction_id);
                     return iter != response_.end();
                   })) {
    auto result = std::move(iter->second);
    response_.erase(iter);
    return kl::Ok(std::move(result));
  }
  return kl::Err("timeout");
}

std::string Resolver::LocalAddr() {
  if (addr_.empty()) {
    auto inet_addr = kl::inet::InetAddr(fd_);
    addr_ = std::get<0>(*inet_addr);
    port_ = std::get<1>(*inet_addr);
  }
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%s:%u", addr_.c_str(), port_);
  return std::string(buf);
}

std::vector<uint8_t> Resolver::BuildQuery(const char *name,
                                          uint16_t transaction_id) {
  std::vector<uint8_t> result;
  uint8_t header[12];
  int len = ip_packet::BuildNetworkBuffer(header, sizeof(header), "wbbwwww",
                                          htons(transaction_id), 0x01, 0x00,
                                          htons(1), 0, 0, 0);
  assert(len == 12);
  result.insert(result.end(), header, header + len);
  std::string domain = DNSName(name);
  result.insert(result.end(), domain.data(), domain.data() + domain.size());
  result.insert(result.end(), 0x00);
  result.insert(result.end(), 0x01);
  result.insert(result.end(), 0x00);
  result.insert(result.end(), 0x01);
  return result;
}

}  // namespace kale
