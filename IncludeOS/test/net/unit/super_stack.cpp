// This file is a part of the IncludeOS unikernel - www.includeos.org
//
// Copyright 2018 Oslo and Akershus University College of Applied Sciences
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

#include <common.cxx>

#include <nic_mock.hpp>
#include <hw/devices.hpp>
#include <net/super_stack.hpp>
#include <net/inet>

using namespace net;

CASE("Super stack functionality")
{
  bool stack_not_found = false;
  bool stack_err = false;
  auto& nics = hw::Devices::devices<hw::Nic>();

  // Add 3 nics
  nics.push_back(std::make_unique<Nic_mock>());
  nics.push_back(std::make_unique<Nic_mock>());
  nics.push_back(std::make_unique<Nic_mock>());

  // 3 stacks are preallocated
  EXPECT(Super_stack::inet().stacks().size() == 3);

  // Retreiving the first stack creates an interface on the first nic
  auto& stack1 = Super_stack::get(0);
  EXPECT(&stack1.nic() == nics[0].get());

  // Trying to get a stack that do not exists will throw
  stack_not_found = false;
  try {
    Super_stack::get(3);
  } catch(const Stack_not_found&) {
    stack_not_found = true;
  }
  EXPECT(stack_not_found == true);

  // Getting by mac addr works
  const MAC::Addr my_mac{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  // hehe..
  reinterpret_cast<Nic_mock*>(nics[0].get())->mac_ = my_mac;
  auto& stack_by_mac = Super_stack::get(my_mac.to_string());
  EXPECT(&stack_by_mac.nic() == nics[0].get());

  // Throws if mac addr isnt found
  stack_not_found = false;
  try {
    Super_stack::get("FF:FF:FF:00:00:00");
  } catch(const Stack_not_found&) {
    stack_not_found = true;
  }
  EXPECT(stack_not_found == true);

  // Creating substacks works alrite
  Nic_mock my_nic;
  auto& my_sub_stack = Super_stack::inet().create(my_nic, 2, 42);
  EXPECT(&my_sub_stack == &Super_stack::get(2,42));

  // Not allowed to create if already occupied tho
  stack_err = false;
  try {
    Super_stack::inet().create(my_nic, 0, 0);
  } catch(const Super_stack_err&) {
    stack_err = true;
  }
  EXPECT(stack_err == true);

}

