// This file is a part of the IncludeOS unikernel - www.includeos.org
//
// Copyright 2015 Oslo and Akershus University College of Applied Sciences
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

#ifndef KERNEL_EVENTS_HPP
#define KERNEL_EVENTS_HPP

#include <delegate>
#include <array>
#include <common>
#include <deque>
#include <smp>

#define IRQ_BASE    32
//#define DEBUG_ALL_INTERRUPTS

class alignas(SMP_ALIGN) Events {
public:
  typedef void (*intr_func) ();
  using event_callback = delegate<void()>;

  static const int  NUM_EVENTS = 128;

  uint8_t subscribe(event_callback);
  void subscribe(uint8_t evt, event_callback);
  void unsubscribe(uint8_t evt);

  // register event for deferred processing
  inline void trigger_event(uint8_t evt);

  // call event once, at a later time
  void defer(event_callback);

  /**
   * Get per-cpu instance
   */
  static Events& get();
  static Events& get(int cpu);

  /** process all pending events */
  void process_events();

  /** array of received events */
  auto& get_received_array() const noexcept
  { return received_array; }

  /** array of handled events */
  auto& get_handled_array() const noexcept
  { return handled_array; }

  void init_local();
  Events() = default;

private:
  Events(Events&) = delete;
  Events(Events&&) = delete;
  Events& operator=(Events&&) = delete;
  Events& operator=(Events&) = delete;

  event_callback callbacks[NUM_EVENTS];
  std::array<uint64_t, NUM_EVENTS> received_array;
  std::array<uint64_t, NUM_EVENTS> handled_array;

  std::array<bool, NUM_EVENTS>  event_subs;
  std::array<bool, NUM_EVENTS>  event_pend;
  // using deque because vector resize causes invalidation of ranged for
  // when something subscribes during processing of events
  std::deque<uint8_t> sublist;
};

inline void Events::trigger_event(const uint8_t evt)
{
#ifdef DEBUG_ALL_INTERRUPTS
  bool is_subbed = false;
  for (auto intr : sublist) {
    if (intr == evt) { is_subbed = true; break; }
  }
  if (UNLIKELY(is_subbed == false)) {
    printf("! Unhandled interrupt: %u\n", evt);
  }
#endif
  if (LIKELY(evt < NUM_EVENTS)) {
    event_pend[evt] = true;
    // increment events received
    received_array[evt]++;
  }
#ifdef DEBUG_ALL_INTERRUPTS
  else {
    printf("! Received out of range intr %u\n", evt);
  }
#endif
}

#endif //< KERNEL_EVENTS_HPP
