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

#include "packet_util.hh"
#include "packets.h"
#include "netinet++/ethernet.hh"

boost::shared_ptr<Buffer> PacketUtil::pkt_arp_request(uint32_t nw_src,
		uint32_t nw_dst, uint8_t dl_src[]) {
	struct eth_header* eth;
	struct arp_eth_header* arp;
	size_t size = sizeof(struct eth_header) + sizeof(struct arp_eth_header);
	uint8_t *pkt = new uint8_t[size];
	memset(pkt, 0, size);

	eth = (struct eth_header*) pkt;
	eth->eth_type = htons(ETH_TYPE_ARP);
	memset(eth->eth_dst, 0xff, 6);
	memcpy(eth->eth_src, dl_src, sizeof(eth->eth_src));
	arp = (struct arp_eth_header*) ((uint8_t*)pkt + sizeof(struct eth_header));
	/* Generic members. */
	arp->ar_hrd = htons(1); 		/* Hardware type. */
	arp->ar_pro = htons(0x0800); 	/* Protocol type. */
	arp->ar_hln = 6; 				/* Hardware address length. */
	arp->ar_pln = 4;				/* Protocol address length. */
	arp->ar_op = htons(1); 			/* Opcode. */

	/* Ethernet+IPv4 specific members. */
	memcpy(arp->ar_sha, dl_src, sizeof(arp->ar_sha)); 	/* Sender hardware address. */
	arp->ar_spa=nw_src; 								/* Sender protocol address. */
	//uint8_t ar_tha[ETH_ADDR_LEN]; 					/* Target hardware address. */
	arp->ar_tpa=nw_dst; 								/* Target protocol address. */

	return boost::shared_ptr<Buffer>(new Array_buffer(pkt, size));
}

boost::shared_ptr<Buffer> PacketUtil::pkt_arp_reply(uint32_t nw_src,
		uint32_t nw_dst, uint8_t dl_src[], uint8_t dl_dst[]) {
	struct eth_header* eth;
	struct arp_eth_header* arp;
	size_t size = sizeof(struct eth_header) + sizeof(struct arp_eth_header);
	uint8_t *pkt = new uint8_t[size];
	memset(pkt, 0, size);

	eth = (struct eth_header*) pkt;
	eth->eth_type = htons(ETH_TYPE_ARP);
	memset(eth->eth_dst, 0xff, 6);
	memcpy(eth->eth_src, dl_src, sizeof(eth->eth_src));
	arp = (struct arp_eth_header*) ((uint8_t*)pkt + sizeof(struct eth_header));
	/* Generic members. */
	arp->ar_hrd = htons(1); 		/* Hardware type. */
	arp->ar_pro = htons(0x0800); 	/* Protocol type. */
	arp->ar_hln = 6; 				/* Hardware address length. */
	arp->ar_pln = 4;				/* Protocol address length. */
	arp->ar_op = htons(2); 			/* Opcode. */

	/* Ethernet+IPv4 specific members. */
	memcpy(arp->ar_sha, dl_src, sizeof(arp->ar_sha)); 	/* Sender hardware address. */
	arp->ar_spa=nw_src; 								/* Sender protocol address. */
	memcpy(arp->ar_tha, dl_dst, sizeof(arp->ar_tha));  	/* Target hardware address. */
	arp->ar_tpa=nw_dst;									/* Target protocol address. */

	return boost::shared_ptr<Buffer>(new Array_buffer(pkt, size));
}

boost::shared_ptr<Buffer> PacketUtil::pkt_swap_vlan(const Buffer& buff,
		uint16_t vlanid) {
	struct eth_header* eth;
	struct vlan_header* vlan;
	size_t size = buff.size();
	uint8_t *pkt = new uint8_t[size];
	memcpy(pkt, buff.data(), buff.size());
	eth = (struct eth_header*) pkt;
	if (ntohs(eth->eth_type) == ETH_TYPE_VLAN) {
		vlan = (struct vlan_header*) (pkt + sizeof(struct eth_header));
		vlan->vlan_tci = htons(vlanid & VLAN_VID_MASK);
	}
	return boost::shared_ptr<Buffer>(new Array_buffer(pkt, size));
}

boost::shared_ptr<Buffer> PacketUtil::pkt_pop_vlan(const Buffer& buff) {
	struct eth_header* eth;
	struct vlan_header* vlan;
	size_t size = buff.size() - sizeof(struct vlan_header);
	uint8_t *pkt = new uint8_t[size];
	memset(pkt, 0, size);
	memcpy(pkt, buff.data(), sizeof(struct eth_header));
	memcpy(pkt + sizeof(struct eth_header), buff.data()
			+ sizeof(struct eth_header) + sizeof(struct vlan_header),
			buff.size() - sizeof(struct eth_header)
					- sizeof(struct vlan_header));
	eth = (struct eth_header*) pkt;
	vlan = (struct vlan_header*) (buff.data() + sizeof(struct eth_header));
	eth->eth_type = vlan->vlan_next_type;
	return boost::shared_ptr<Buffer>(new Array_buffer(pkt, size));
}

boost::shared_ptr<Buffer> PacketUtil::pkt_push_vlan(const Buffer& buff,
		uint16_t vlanid) {
	struct eth_header* eth0, *eth;
	struct vlan_header* vlan;
	size_t size = buff.size() + sizeof(struct vlan_header);
	uint8_t *pkt = new uint8_t[size]; // eth=14,tlv1=9,tlv2=7,tlv3=4,tlv0=2
	eth0 = (struct eth_header*) buff.data();
	memset(pkt, 0, size);
	memcpy(pkt, buff.data(), sizeof(struct eth_header));
	memcpy(&pkt[sizeof(struct eth_header) + sizeof(struct vlan_header)],
			buff.data() + sizeof(struct eth_header), buff.size()
					- sizeof(struct eth_header));
	eth = (struct eth_header*) pkt;
	vlan = (struct vlan_header*) (pkt + sizeof(struct eth_header));
	vlan->vlan_next_type = eth0->eth_type;
	eth->eth_type = htons(ETH_TYPE_VLAN);
	vlan->vlan_tci = htons(vlanid & VLAN_VID_MASK);
	return boost::shared_ptr<Buffer>(new Array_buffer(pkt, size));
}
#ifdef NOX_OF11
boost::shared_ptr<Buffer> PacketUtil::pkt_swap_mpls(const Buffer& buff,
		uint16_t mplsid) {
	struct eth_header* eth;
	struct mpls_header* mpls;
	size_t size = buff.size();
	uint8_t *pkt = new uint8_t[size];
	memcpy(pkt, buff.data(), buff.size());
	eth = (struct eth_header*) pkt;
	if (ntohs(eth->eth_type) == ETH_TYPE_MPLS) {
		mpls = (struct mpls_header*) (pkt + sizeof(struct eth_header));
		mpls->fields |= htonl(mplsid << MPLS_LABEL_SHIFT & MPLS_LABEL_MASK);
	}
	return boost::shared_ptr<Buffer>(new Array_buffer(pkt, size));

}

boost::shared_ptr<Buffer> PacketUtil::pkt_pop_mpls(const Buffer& buff) {
	struct eth_header* eth;
	struct mpls_header* mpls;
	uint8_t mpls_tc = 0;
	size_t size = buff.size() - sizeof(struct mpls_header);
	uint8_t *pkt = new uint8_t[size];
	eth = (struct eth_header*) pkt;
	if (ntohs(eth->eth_type) == ETH_TYPE_MPLS) {
		mpls = (struct mpls_header*) (buff.data() + sizeof(struct eth_header));
		/* Read TC to know class of traffic */
		mpls_tc = (ntohl(mpls->fields) & MPLS_TC_MASK) >> MPLS_TC_SHIFT;

		memset(pkt, 0, size);
		memcpy(pkt, buff.data(), sizeof(struct eth_header));
		memcpy(pkt + sizeof(struct eth_header), buff.data()
				+ sizeof(struct eth_header) + sizeof(struct mpls_header),
				buff.size() - sizeof(struct eth_header)
				- sizeof(struct mpls_header));

		mpls = (struct mpls_header*) (buff.data() + sizeof(struct eth_header));
		/* Map eth type to TC type */
		eth->eth_type = get_eth_type_from_mplstc(mpls_tc);
	}
	return boost::shared_ptr<Buffer>(new Array_buffer(pkt, size));
}

boost::shared_ptr<Buffer> PacketUtil::pkt_push_mpls(const Buffer& buff,
		uint16_t mplsid) {
	struct eth_header* eth;
	struct mpls_header* mpls;
	size_t size = buff.size() + sizeof(struct mpls_header);
	uint8_t *pkt = new uint8_t[size]; // eth=14,tlv1=9,tlv2=7,tlv3=4,tlv0=2


	memset(pkt, 0, size);
	memcpy(pkt, buff.data(), sizeof(struct eth_header));
	memcpy(&pkt[sizeof(struct eth_header) + sizeof(struct mpls_header)],
			buff.data() + sizeof(struct eth_header), buff.size()
			- sizeof(struct eth_header));

	eth = (struct eth_header*) pkt;
	mpls = (struct mpls_header*) (pkt + sizeof(struct eth_header));

	mpls->fields |= htonl(mplsid << MPLS_LABEL_SHIFT & MPLS_LABEL_MASK);
	mpls->fields |= htonl(get_mplstc_from_eth_type(eth->eth_type)
			<< MPLS_TC_SHIFT & MPLS_TC_MASK);
	mpls->fields |= htonl(0xffffffff & MPLS_S_MASK);
	mpls->fields |= htonl(0xffffffff & MPLS_TTL_MASK);
	eth->eth_type = htons(ETH_TYPE_MPLS);
	return boost::shared_ptr<Buffer>(new Array_buffer(pkt, size));
}

/** Function to map the ethtype from the TC information*/
uint8_t PacketUtil::get_eth_type_from_mplstc(uint8_t mpls_tc) {
	uint8_t type;
	switch (mpls_tc) {
		case TC_ARP:
		type = htons(ETH_TYPE_ARP);
		break;
		case TC_IPV4:
		type = htons(ETH_TYPE_IP);
		break;
		default:
		type = htons(ETH_TYPE_IP);
	}
	return type;
}
/** Function to map the ethtype from the TC information*/
uint8_t PacketUtil::get_mplstc_from_eth_type(uint8_t type) {
	uint8_t tc;
	switch (ntohs(type)) {
		case ETH_TYPE_ARP:
		tc = TC_ARP;
		break;
		case ETH_TYPE_IP:
		tc = TC_IPV4;
		break;
		default:
		tc = TC_IPV4;
	}
	return tc;
}
#endif
