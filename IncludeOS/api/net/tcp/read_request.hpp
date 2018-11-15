// This file is a part of the IncludeOS unikernel - www.includeos.org
//
// Copyright 2015-2018 Oslo and Akershus University College of Applied Sciences
// and Alfred Bratterud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once
#ifndef NET_TCP_READ_REQUEST_HPP
#define NET_TCP_READ_REQUEST_HPP

#include "read_buffer.hpp"
#include <delegate>
#include <deque>

namespace net {
namespace tcp {

class Read_request {
public:
  using Buffer_ptr = std::unique_ptr<Read_buffer>;
  using Buffer_queue = std::deque<Buffer_ptr>;
  using ReadCallback = delegate<void(buffer_t)>;
  static constexpr size_t buffer_limit = 2;
  ReadCallback callback;

  Read_request(seq_t start, size_t min, size_t max, ReadCallback cb);

  size_t insert(seq_t seq, const uint8_t* data, size_t n, bool psh = false);

  size_t fits(const seq_t seq) const;

  size_t size() const;

  void set_start(seq_t seq);

  void reset(const seq_t seq);

  const Read_buffer& front() const
  { return *buffers.front(); }

  Read_buffer& front()
  { return *buffers.front(); }

  const Buffer_queue& queue() const
  { return buffers; }

private:
  Buffer_queue buffers;

  Read_buffer* get_buffer(const seq_t seq);

};

}
}

#endif // < NET_TCP_READ_REQUEST_HPP
