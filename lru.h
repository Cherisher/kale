// Copyright (c) 2017 Kai Luo <gluokai@gmail.com>. All rights reserved.
// Use of this source code is governed by the BSD license that can be found in
// the LICENSE file.

// An implementation of Least-Recently-Used structure.
#ifndef KALE_LRU_H_
#define KALE_LRU_H_
#include <cassert>
#include <cstdint>
#include <map>

namespace kale {

class LRU {
public:
  // REQUIRES: size >= 1
  explicit LRU(size_t size);
  bool Use(uint32_t v);
  uint32_t GetLRU();
  uint32_t Head();
  uint32_t Tail();
  size_t Size();
  ~LRU();

protected:
  struct Node {
    uint32_t id;
    Node *prev, *next;
    explicit Node(uint32_t x) : id(x), prev(nullptr), next(nullptr) {}
  };
  Node *AllocateNode(uint32_t x);
  void InsertAfter(Node *n, Node *x);
  void InsertBefore(Node *n, Node *x);
  void Remove(Node *n);
  size_t size_;
  Node *head_, *tail_;
  std::map<uint32_t, Node *> location_;
};

inline bool LRU::Use(uint32_t v) {
  auto iter = location_.find(v);
  if (iter == location_.end()) {
    return false;
  }
  Node *n = iter->second;
  Remove(n);
  InsertBefore(head_, n);
  return true;
}

inline uint32_t LRU::Head() { return head_->id; }

inline uint32_t LRU::Tail() { return tail_->id; }

inline uint32_t LRU::GetLRU() {
  Node *n = tail_;
  assert(n);
  Remove(n);
  InsertBefore(head_, n);
  return n->id;
}

inline LRU::Node *LRU::AllocateNode(uint32_t x) {
  Node *n = new Node(x);
  location_.insert(std::make_pair(x, n));
  return n;
}

inline LRU::~LRU() {
  for (auto &n : location_) {
    delete n.second;
  }
}

inline LRU::LRU(size_t size) : size_(size), head_(nullptr), tail_(nullptr) {
  assert(size >= 1);
  for (size_t i = 0; i < size_; ++i) {
    Node *n = AllocateNode(i);
    InsertBefore(head_, n);
  }
}

inline void LRU::InsertBefore(Node *n, Node *x) {
  Node *next = n;
  Node *prev = nullptr;
  if (next) {
    prev = next->prev;
    next->prev = x;
  }
  if (x) {
    x->prev = prev;
    x->next = next;
  }
  if (prev) {
    prev->next = x;
  }
  if (x && x->prev == nullptr) {
    head_ = x;
  }
  if (x && x->next == nullptr) {
    tail_ = x;
  }
}

inline void LRU::InsertAfter(Node *n, Node *x) {
  Node *prev = n;
  Node *next = nullptr;
  if (prev) {
    next = prev->next;
    prev->next = x;
  }
  if (x) {
    x->prev = prev;
    x->next = next;
  }
  if (next) {
    next->prev = x;
  }
  if (x && x->prev == nullptr) {
    head_ = x;
  }
  if (x && x->next == nullptr) {
    tail_ = x;
  }
}

inline void LRU::Remove(Node *n) {
  if (n == nullptr) {
    return;
  }
  Node *prev = n->prev;
  Node *next = n->next;
  if (prev) {
    prev->next = next;
  }
  if (next) {
    next->prev = prev;
  }
  if (prev == nullptr) {
    head_ = next;
  }
  if (next == nullptr) {
    tail_ = prev;
  }
}

}  // namespace kale
#endif
