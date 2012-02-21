/*
 Libnetvirt - the network virtualization library
 Copyright (C) 2011  Daniel Turull <danieltt@kth.se>

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.

 */
#ifndef PACKET_HH_
#define PACKET_HH_
#include "buffer.hh"
#include <boost/smart_ptr/shared_ptr.hpp>

using namespace vigil;
class PacketUtil {
public:
	/* Definitions for TC when is used to know what ethertype should be use when poping MPLS tag*/
	static const int TC_IPV4 = 0x1;
	static const int TC_ARP = 0x2;
	static const int TC_IPV6 = 0x3;

	static boost::shared_ptr<Buffer> pkt_arp_request(uint32_t nw_src,
			uint32_t nw_dst, uint8_t dl_src[]);
	static boost::shared_ptr<Buffer> pkt_arp_reply(uint32_t nw_src,
			uint32_t nw_dst, uint8_t dl_src[], uint8_t dl_dst[]);

	/* VLAN packet modifications*/
	static boost::shared_ptr<Buffer> pkt_swap_vlan(const Buffer& buff,
			uint16_t vlanid);
	static boost::shared_ptr<Buffer> pkt_pop_vlan(const Buffer& buff);
	static boost::shared_ptr<Buffer> pkt_push_vlan(const Buffer& buff,
			uint16_t vlanid);

#ifdef NOX_OF11
	/* MPLS packet modification */
	static uint8_t get_eth_type_from_mplstc(uint8_t tc);
	static uint8_t get_mplstc_from_eth_type(uint8_t type);

	static boost::shared_ptr<Buffer> pkt_swap_mpls(const Buffer& buff, uint16_t vlanid);
	static boost::shared_ptr<Buffer> pkt_pop_mpls(const Buffer& buff);
	static boost::shared_ptr<Buffer> pkt_push_mpls(const Buffer& buff, uint16_t vlanid);
#endif
};
#endif /* PACKET_HH_ */
