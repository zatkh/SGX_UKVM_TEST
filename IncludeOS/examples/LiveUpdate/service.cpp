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

#include <os>
#include <profile>
#include <timers>
#include "motd_array.h"
#define USE_STACK_SAMPLING
#define PERIOD_SECS    4

#include "../IRCd/ircd/ircd.hpp"
static std::unique_ptr<IrcServer> ircd = nullptr;
using namespace std::chrono;

void Service::start()
{
  // run a small self-test to verify parser is sane
  extern void selftest(); selftest();

  ircd = IrcServer::from_config();

  ircd->set_motd([] () -> const std::string& {
    static std::string motd(motd_array);
    return motd;
  });
  // motd spam
  //printf("%s\n", ircd->get_motd().c_str());
}

#include <ctime>
std::string now()
{
  auto  tnow = time(0);
  auto* curtime = localtime(&tnow);

  char buff[48];
  int len = strftime(buff, sizeof(buff), "%c", curtime);
  return std::string(buff, len);
}

void print_heap_info()
{
  static intptr_t last = 0;
  // show information on heap status, to discover leaks etc.
  auto heap_begin = OS::heap_begin();
  auto heap_end   = OS::heap_end();
  auto heap_usage = OS::heap_usage();
  intptr_t heap_size = heap_end - heap_begin;
  last = heap_size - last;
  printf("Heap begin  %#lx  size %lu Kb\n",     heap_begin, heap_size / 1024);
  printf("Heap end    %#lx  diff %lu (%ld Kb)\n", heap_end,  last, last / 1024);
  printf("Heap usage  %lu kB\n", heap_usage / 1024);
  last = (int32_t) heap_size;
}

#include <kernel/elf.hpp>
void print_stats(int)
{
#ifdef USE_STACK_SAMPLING
  StackSampler::set_mask(true);
#endif

  static std::deque<int> M;
  static int last = 0;
  // only keep 5 measurements
  if (M.size() > 4) M.pop_front();

  int diff = ircd->get_counter(STAT_TOTAL_CONNS) - last;
  last = ircd->get_counter(STAT_TOTAL_CONNS);
  // @PERIOD_SECS between measurements
  M.push_back(diff / PERIOD_SECS);

  double cps = 0.0;
  for (int C : M) cps += C;
  cps /= M.size();

  printf("[%s] Conns/sec %.1f  Heap %.1f kb\n",
      now().c_str(), cps, OS::heap_usage() / 1024.0);
  // client and channel stats
  auto& inet = net::Inet::stack<0>();

  printf("Syns: %u  Conns: %lu  Users: %u  RAM: %lu bytes Chans: %u\n",
         ircd->get_counter(STAT_TOTAL_CONNS),
         inet.tcp().active_connections(),
         ircd->get_counter(STAT_LOCAL_USERS),
         ircd->club(),
         ircd->get_counter(STAT_CHANNELS));
  printf("*** ---------------------- ***\n");
#ifdef USE_STACK_SAMPLING
  // stack sampler results
  StackSampler::print(10);
  printf("*** ---------------------- ***\n");
#endif
  // heap statistics
  print_heap_info();
  printf("*** ---------------------- ***\n");

#ifdef USE_STACK_SAMPLING
  StackSampler::set_mask(false);
#endif
}

#include "liu.hpp"
static void save_state(liu::Storage& store, const liu::buffer_t*)
{

}

void Service::ready()
{
#ifdef USE_STACK_SAMPLING
  StackSampler::begin();
  //StackSampler::set_mode(StackSampler::MODE_CALLER);
#endif

  Timers::periodic(seconds(5), seconds(PERIOD_SECS), print_stats);

  // raw TCP liveupdate server
  auto& inet = net::Super_stack::get(0);
  setup_liveupdate_server(inet, 666, save_state);

  // profiler statistics
  printf("%s\n", ScopedProfiler::get_statistics(false).c_str());
}
