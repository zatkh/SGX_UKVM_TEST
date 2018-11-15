// This file is a part of the IncludeOS unikernel - www.includeos.org
//
// Copyright 2017-2018 IncludeOS AS, Oslo, Norway
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
//
// Autogenerated by NaCl

#include <iostream>
#include <net/inet>
#include <net/super_stack.hpp>
#include <net/ip4/cidr.hpp>
#include <net/vlan_manager.hpp>
#include <hw/devices.hpp>
#include <syslogd>

using namespace net;

namespace nacl {
  class Filter {
  public:
    virtual Filter_verdict<IP4> operator()(IP4::IP_packet_ptr pckt, Inet& stack, Conntrack::Entry_ptr ct_entry) = 0;
    virtual ~Filter() {}
  };
}

void register_plugin_nacl() {
	INFO("NaCl", "Registering NaCl plugin");

	// vlan vlan2_eth4
	Super_stack::inet().create(VLAN_manager::get(4).add(hw::Devices::nic(4), 63), 4, 63);
	auto& vlan2_eth4 = Super_stack::get(4, 63);
	vlan2_eth4.network_config(IP4::addr{10,200,100,3}, IP4::addr{255,255,255,0}, 0);
	// vlan vlan2_eth3
	Super_stack::inet().create(VLAN_manager::get(3).add(hw::Devices::nic(3), 23), 3, 23);
	auto& vlan2_eth3 = Super_stack::get(3, 23);
	vlan2_eth3.network_config(IP4::addr{10,100,0,20}, IP4::addr{255,255,255,0}, 0);
	// vlan vlan2_eth2
	Super_stack::inet().create(VLAN_manager::get(2).add(hw::Devices::nic(2), 23), 2, 23);
	auto& vlan2_eth2 = Super_stack::get(2, 23);
	vlan2_eth2.network_config(IP4::addr{10,100,0,20}, IP4::addr{255,255,255,0}, 0);
	// vlan vlan1_eth4
	Super_stack::inet().create(VLAN_manager::get(4).add(hw::Devices::nic(4), 62), 4, 62);
	auto& vlan1_eth4 = Super_stack::get(4, 62);
	vlan1_eth4.network_config(IP4::addr{10,200,100,2}, IP4::addr{255,255,255,0}, 0);
	auto& eth3 = Super_stack::get(3);
	eth3.network_config(IP4::addr{10,100,100,100}, IP4::addr{255,255,255,0}, IP4::addr{100,100,100,1});
	// vlan no1
	Super_stack::inet().create(VLAN_manager::get(0).add(hw::Devices::nic(0), 2), 0, 2);
	auto& no1 = Super_stack::get(0, 2);
	no1.network_config(IP4::addr{10,60,0,10}, IP4::addr{255,255,255,0}, 0);
	// vlan vlan1_eth2
	Super_stack::inet().create(VLAN_manager::get(2).add(hw::Devices::nic(2), 22), 2, 22);
	auto& vlan1_eth2 = Super_stack::get(2, 22);
	vlan1_eth2.network_config(IP4::addr{10,100,0,10}, IP4::addr{255,255,255,0}, 0);
	// vlan no2
	Super_stack::inet().create(VLAN_manager::get(1).add(hw::Devices::nic(1), 13), 1, 13);
	auto& no2 = Super_stack::get(1, 13);
	no2.network_config(IP4::addr{10,50,0,20}, IP4::addr{255,255,255,0}, 0);
	// vlan no3
	Super_stack::inet().create(VLAN_manager::get(1).add(hw::Devices::nic(1), 24), 1, 24);
	auto& no3 = Super_stack::get(1, 24);
	no3.network_config(IP4::addr{10,60,0,20}, IP4::addr{255,255,255,0}, 0);
	// vlan vlan1_eth3
	Super_stack::inet().create(VLAN_manager::get(3).add(hw::Devices::nic(3), 24), 3, 24);
	auto& vlan1_eth3 = Super_stack::get(3, 24);
	vlan1_eth3.network_config(IP4::addr{10,100,0,10}, IP4::addr{255,255,255,0}, 0);
	auto& eth4 = Super_stack::get(4);
	eth4.network_config(IP4::addr{10,200,100,100}, IP4::addr{255,255,255,0}, IP4::addr{100,200,100,1});
	// vlan no0
	Super_stack::inet().create(VLAN_manager::get(0).add(hw::Devices::nic(0), 5), 0, 5);
	auto& no0 = Super_stack::get(0, 5);
	no0.network_config(IP4::addr{10,50,0,10}, IP4::addr{255,255,255,0}, 0);
	auto& eth2 = Super_stack::get(2);
	eth2.network_config(IP4::addr{10,10,10,50}, IP4::addr{255,255,255,0}, IP4::addr{10,10,10,1});
	auto& eth1 = Super_stack::get(1);
	eth1.network_config(IP4::addr{10,0,10,45}, IP4::addr{255,255,255,0}, IP4::addr{10,0,10,1});
	auto& eth0 = Super_stack::get(0);
	eth0.network_config(IP4::addr{10,0,0,30}, IP4::addr{255,255,255,0}, IP4::addr{10,0,0,1});

}
