// This file is a part of the IncludeOS unikernel - www.includeos.org
//
// Copyright 2015-2017 Oslo and Akershus University College of Applied Sciences
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

#ifndef NET_INET_HPP
#define NET_INET_HPP

#include <vector>
#include <chrono>
#include <unordered_set>
#include <net/inet_common.hpp>
#include <hw/mac_addr.hpp>
#include <hw/nic.hpp>
#include <map>
#include <net/port_util.hpp>
#include "conntrack.hpp"

#include "ip4/ip4.hpp"
#include "ip4/udp.hpp"
#include "ip4/icmp4.hpp"
#include "ip4/arp.hpp"
#include "ip6/ip6.hpp"
#include "ip6/icmp6.hpp"
#include "dns/client.hpp"
#include "tcp/tcp.hpp"
#include "super_stack.hpp"

namespace net {

  class DHClient;

  /** A complete IP network stack */
  class Inet {
  public:

    using Stack          = class Inet;
    using IP_packet_ptr  = IP4::IP_packet_ptr;
    using IP6_packet_ptr = IP6::IP_packet_ptr;
    using IP_addr        = IP4::addr;

    using Forward_delg  = delegate<void(IP_packet_ptr, Stack& source, Conntrack::Entry_ptr)>;
    using Route_checker = delegate<bool(IP_addr)>;
    using IP_packet_factory  = delegate<IP_packet_ptr(Protocol)>;
    using IP6_packet_factory = delegate<IP6_packet_ptr(Protocol)>;

    using resolve_func = delegate<void(IP4::addr, const Error&)>;
    using on_configured_func = delegate<void(Stack&)>;
    using dhcp_timeout_func = delegate<void(bool timed_out)>;

    using Port_utils  = std::map<net::Addr, Port_util>;
    using Vip4_list = std::vector<IP4::addr>;
    using Vip6_list = std::vector<IP6::addr>;

    std::string ifname() const
    { return nic_.device_name(); }

    MAC::Addr link_addr() const
    { return nic_.mac(); }

    hw::Nic& nic() const
    { return nic_; }

    IP4::addr ip_addr() const
    { return ip4_addr_; }

    IP4::addr netmask() const
    { return netmask_; }

    IP4::addr gateway() const
    { return gateway_; }

    IP4::addr dns_addr() const
    { return dns_server_; }

    IP4::addr broadcast_addr() const
    { return ip4_addr_ | ( ~ netmask_); }

    const ip6::Addr& ip6_addr() const noexcept
    { return ip6_addr_; }

    uint8_t netmask6() const
     { return ip6_prefix_; }

    IP6::addr gateway6() const
    { return ip6_gateway_; }

    void cache_link_addr(IP4::addr ip, MAC::Addr mac);
    void flush_link_cache();
    void set_link_cache_flush_interval(std::chrono::minutes min);

    /** Get the IP-object belonging to this stack */
    IP4& ip_obj()
    { return ip4_; }

    /** Get the IP6-object belonging to this stack */
    IP6& ip6_obj()
    { return ip6_; }

    /** Get the TCP-object belonging to this stack */
    TCP& tcp() { return tcp_; }

    /** Get the UDP-object belonging to this stack */
    UDP& udp() { return udp_; }

    /** Get the ICMP-object belonging to this stack */
    ICMPv4& icmp() { return icmp_; }

    /** Get the ICMP-object belonging to this stack */
    ICMPv6& icmp6() { return icmp6_; }

    /** Get the DHCP client (if any) */
    auto dhclient() { return dhcp_;  }

    /**
     * @brief      Disable or enable Path MTU Discovery (enabled by default)
     *             RFC 1191
     *             If enabled, it sets the Don't Fragment flag on each IP4 packet
     *             TCP and UDP acts based on this being enabled or not
     *
     * @param[in]  on    Enables Path MTU Discovery if true, disables if false
     * @param[in]  aged  Number of minutes that indicate that a PMTU value
     *                   has grown stale and should be reset/increased
     *                   This could be set to "infinity" (PMTU should never be
     *                   increased) by setting the value to IP4::INFINITY
     */
    void set_path_mtu_discovery(bool on, uint16_t aged = 10)
    { ip4_.set_path_mtu_discovery(on, aged); }

    /**
     * @brief      Triggered by IP when a Path MTU value has grown stale and the value
     *             is reset (increased) to check if the PMTU for the path could have increased
     *             This is NOT a change in the Path MTU in response to receiving an ICMP Too Big message
     *             and no retransmission of packets should take place
     *
     * @param[in]  dest  The destination/path
     * @param[in]  pmtu  The reset PMTU value
     */
    void reset_pmtu(Socket dest, IP4::PMTU pmtu);

    /**
     *  Error reporting
     *
     *  Including ICMP error report in accordance with RFC 1122 and handling of ICMP
     *  too big messages in accordance with RFC 1191, 1981 and 4821 (Path MTU Discovery
     *  and Packetization Layer Path MTU Discovery)
     *
     *  Forwards errors to the transport layer (UDP and TCP)
    */
    void error_report(Error& err, Packet_ptr orig_pckt);

    /**
     * Set the forwarding delegate used by this stack.
     * If set it will get all incoming packets not intended for this stack.
     * NOTE: This delegate is expected to call the forward chain
     */
    void set_forward_delg(Forward_delg fwd) {
      ip4_.set_packet_forwarding(fwd);
    }

    /**
     * Assign a delegate that checks if we have a route to a given IP
     */
    void set_route_checker(Route_checker delg);

    /**
     * Get the forwarding delegate used by this stack.
     */
    Forward_delg forward_delg()
    { return ip4_.forward_delg(); }


    Packet_ptr create_packet() {
      return nic_.create_packet(nic_.frame_offset_link());
    }

    /**
     * Provision an IP packet
     * @param proto : IANA protocol number.
     */
    IP4::IP_packet_ptr create_ip_packet(Protocol proto) {
      auto raw = nic_.create_packet(nic_.frame_offset_link());
      auto ip_packet = static_unique_ptr_cast<IP4::IP_packet>(std::move(raw));

      ip_packet->init(proto);

      return ip_packet;
    }

    IP6::IP_packet_ptr create_ip6_packet(Protocol proto) {
      auto raw = nic_.create_packet(nic_.frame_offset_link());
      auto ip_packet = static_unique_ptr_cast<IP6::IP_packet>(std::move(raw));

      ip_packet->init(proto);

      return ip_packet;
    }

    IP_packet_factory ip_packet_factory()
    { return IP_packet_factory{this, &Inet::create_ip_packet}; }

    IP6_packet_factory ip6_packet_factory()
    { return IP6_packet_factory{this, &Inet::create_ip6_packet}; }

    /** MTU retreived from Nic on construction */
    uint16_t MTU () const
    { return MTU_; }

    /**
     * @func  a delegate that provides a hostname and its address, which is 0 if the
     * name @hostname was not found. Note: Test with INADDR_ANY for a 0-address.
     **/
    void resolve(const std::string& hostname,
                 resolve_func       func,
                 bool               force = false);

    void resolve(const std::string& hostname,
                  IP4::addr         server,
                  resolve_func      func,
                  bool              force = false);

    void set_domain_name(std::string domain_name)
    { this->domain_name_ = std::move(domain_name); }

    const std::string& domain_name() const
    { return this->domain_name_; }

    void set_gateway(IP4::addr gateway)
    {
      this->gateway_ = gateway;
    }

    void set_dns_server(IP4::addr server)
    {
      this->dns_server_ = server;
    }

    /**
     * @brief Try to negotiate DHCP
     * @details Initialize DHClient if not present and tries to negotitate dhcp.
     * Also takes an optional timeout parameter and optional timeout function.
     *
     * @param timeout number of seconds before request should timeout
     * @param dhcp_timeout_func DHCP timeout handler
     */
    void negotiate_dhcp(double timeout = 10.0, dhcp_timeout_func = nullptr);

    bool is_configured() const
    {
      return ip4_addr_ != 0;
    }

    bool is_configured_v6() const
    {
      return ip6_addr_ != IP6::ADDR_ANY;
    }

    // handler called after the network is configured,
    // either by DHCP or static network configuration
    void on_config(on_configured_func handler)
    {
      configured_handlers_.push_back(handler);
    }

    /** We don't want to copy or move an IP-stack. It's tied to a device. */
    Inet(Inet&) = delete;
    Inet(Inet&&) = delete;
    Inet& operator=(Inet) = delete;
    Inet operator=(Inet&&) = delete;

    void network_config(IP4::addr addr,
                        IP4::addr nmask,
                        IP4::addr gateway,
                        IP4::addr dns = IP4::ADDR_ANY);

    void network_config6(IP6::addr addr6 = IP6::ADDR_ANY,
                        uint8_t prefix6 = 0,
                        IP6::addr gateway6 = IP6::ADDR_ANY);

    void
    reset_config()
    {
      this->ip4_addr_ = IP4::ADDR_ANY;
      this->gateway_ = IP4::ADDR_ANY;
      this->netmask_ = IP4::ADDR_ANY;
      //this->ip6_addr_ = IP6::ADDR_ANY;
      //this->ip6_gateway_ = IP6::ADDR_ANY;
      //this->ip6_prefix_ = 0;
    }

    // register a callback for receiving signal on free packet-buffers
    void
    on_transmit_queue_available(transmit_avail_delg del) {
      tqa.push_back(del);
    }

    size_t transmit_queue_available() {
      return nic_.transmit_queue_available();
    }

    void force_start_send_queues();

    void move_to_this_cpu();

    int  get_cpu_id() const noexcept {
      return this->cpu_id;
    }

    /** Return the stack on the given Nic */
    template <int N = 0>
    static auto&& stack()
    {
      return Super_stack::get(N);
    }

    /** Static IP config */
    template <int N = 0>
    static auto&& ifconfig(
      IP4::addr addr,
      IP4::addr nmask,
      IP4::addr gateway,
      IP4::addr dns = IP4::ADDR_ANY)
    {
      stack<N>().network_config(addr, nmask, gateway, dns);
      return stack<N>();
    }

    /** DHCP config */
    template <int N = 0>
    static auto& ifconfig(double timeout = 10.0, dhcp_timeout_func on_timeout = nullptr)
    {
      if (timeout > 0.0)
          stack<N>().negotiate_dhcp(timeout, on_timeout);
      return stack<N>();
    }

    const Vip4_list virtual_ips() const noexcept
    { return vip4s_; }

    const Vip6_list virtual_ip6s() const noexcept
    { return vip6s_; }

    /** Check if IP4 address is virtual loopback */
    bool is_loopback(IP4::addr a) const
    {
      return a.is_loopback()
        or std::find( vip4s_.begin(), vip4s_.end(), a) != vip4s_.end();
    }

    /** Check if IP6 address is virtual loopback */
    bool is_loopback(IP6::addr a) const
    {
      return a.is_loopback()
        or std::find( vip6s_.begin(), vip6s_.end(), a) != vip6s_.end();
    }

    /** add ip address as virtual loopback */
    void add_vip(IP4::addr a)
    {
      if (not is_loopback(a)) {
        INFO("inet", "adding virtual ip address %s", a.to_string().c_str());
        vip4s_.emplace_back(a);
      }
    }

    void add_vip(IP6::addr a)
    {
      if (not is_loopback(a)) {
        INFO("inet", "adding virtual ip6 address %s", a.to_string().c_str());
        vip6s_.emplace_back(a);
      }
    }

    /** Remove IP address as virtual loopback */
    void remove_vip(IP4::addr a)
    {
      auto it = std::find(vip4s_.begin(), vip4s_.end(), a);
      if (it != vip4s_.end())
        vip4s_.erase(it);
    }

    void remove_vip(IP6::addr a)
    {
      auto it = std::find(vip6s_.begin(), vip6s_.end(), a);
      if (it != vip6s_.end())
        vip6s_.erase(it);
    }

    IP4::addr get_source_addr(IP4::addr dest)
    {
      if (dest.is_loopback())
        return {127,0,0,1};

      if (is_loopback(dest))
        return dest;

      return ip_addr();
    }

    IP6::addr get_source_addr(IP6::addr dest)
    {
      if (dest.is_loopback())
        return ip6::Addr{0,0,0,1};

      if (is_loopback(dest))
        return dest;

      return ip6_addr();
    }

    bool is_valid_source(const Addr& addr) const
    { return addr.is_v4() ? is_valid_source4(addr.v4()) : is_valid_source6(addr.v6()); }

    bool is_valid_source4(IP4::addr src) const
    { return src == ip_addr(); }

    bool is_valid_source6(const IP6::addr& src) const
    { return src == ip6_addr() or src.is_multicast(); }

    std::shared_ptr<Conntrack>& conntrack()
    { return conntrack_; }

    void enable_conntrack(std::shared_ptr<Conntrack> ct);

    Port_utils& tcp_ports()
    { return tcp_ports_; }

    Port_utils& udp_ports()
    { return udp_ports_; }

    /** Initialize with ANY_ADDR */
    Inet(hw::Nic& nic);

  private:

    void process_sendq(size_t);
    // delegates registered to get signalled about free packets
    std::vector<transmit_avail_delg> tqa;

    IP4::addr ip4_addr_;
    IP4::addr netmask_;
    IP4::addr gateway_;
    IP4::addr dns_server_;

    IP6::addr ip6_addr_;
    IP6::addr ip6_gateway_;
    uint8_t   ip6_prefix_;

    Vip4_list vip4s_ = {{127,0,0,1}};
    Vip6_list vip6s_ = {{IP6::ADDR_LOOPBACK}};

    // This is the actual stack
    hw::Nic& nic_;
    Arp    arp_;
    IP4    ip4_;
    IP6    ip6_;
    ICMPv4 icmp_;
    ICMPv6 icmp6_;
    UDP    udp_;
    TCP    tcp_;

    Port_utils tcp_ports_;
    Port_utils udp_ports_;

    std::shared_ptr<Conntrack> conntrack_;

    // we need this to store the cache per-stack
    DNSClient dns_;
    std::string domain_name_;

    std::shared_ptr<net::DHClient> dhcp_{};

    std::vector<on_configured_func> configured_handlers_;

    int   cpu_id;
    const uint16_t MTU_;

    friend class Super_stack;
  };
}

#endif
