/* Copyright 2011 Daniel Turull (KTH) <danieltt@kth.se>
 *
 * This file is part of NOX.
 *
 * NOX is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * NOX is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with NOX.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "assert.hh"
#include "netinet++/ethernet.hh"
#include <cstdlib>
#include "fns.hh"
#include "libnetvirt/fns.h"

#include "packets.h"
#include "packet_util.hh"

#ifdef NOX_OF10
#include "openflow-action.hh"
#include "packet-in.hh"

#else
#include "../discovery/discovery.hh"
#endif

namespace vigil {
static Vlog_module lg("fns");

Disposition fns::handle_link_event(const Event& e) {
	const Link_event& le = assert_cast<const Link_event&> (e);
	int cost = 1;
	lg.dbg("Adding link to finder");
	if (le.action == le.ADD) {
		finder.addEdge(le.dpsrc.as_host(), le.dpdst.as_host(), new LinkAtr(
				cost, le.sport, le.dport),
				new LinkAtr(cost, le.dport, le.sport));
	}
	return CONTINUE;
}

Disposition fns::handle_datapath_join(const Event& e) {
	const Datapath_join_event& le = assert_cast<const Datapath_join_event&> (e);

#ifdef NOX_OF10
	finder.addNode(le.datapath_id.as_host(), le.ports.size());
#else
	finder.addNode(le.dpid.as_host(),
			((struct ofl_msg_features_reply *) **le.msg)->ports_num);
#endif
	return CONTINUE;
}

Disposition fns::handle_datapath_leave(const Event& e) {
	const Datapath_leave_event& le = assert_cast<const Datapath_leave_event&> (
			e);
	finder.removeNode(le.datapath_id.as_host());
	return CONTINUE;
}

Disposition fns::handle_packet_in(const Event& e) {
	uint64_t dpid;
	int port;
	uint32_t vlan;
	uint32_t mpls = 0;
	ethernetaddr dl_src;

#ifdef NOX_OF10
	const Packet_in_event& pi = assert_cast<const Packet_in_event&> (e);
	const Buffer& b = *pi.get_buffer();
	Flow flow(pi.in_port, b);
	dpid = pi.datapath_id.as_host();
	port = pi.in_port;
	dl_src = ethernetaddr(flow.dl_src);
	vlan = flow.dl_vlan;
#else
	const Ofp_msg_event& ome = assert_cast<const Ofp_msg_event&> (e);
	struct ofl_msg_packet_in *in = (struct ofl_msg_packet_in *) **ome.msg;
	Nonowning_buffer b(in->data, in->data_length);
	Flow flow(in->in_port, b);
	dpid = ome.dpid.as_host();
	port = in->in_port;
	vlan = flow.match.dl_vlan;
	mpls = flow.match.mpls_label;
	dl_src = ethernetaddr(flow.match.dl_src);
#endif

	/* drop all LLDP packets */
#ifdef NOX_OF10
	if (flow.dl_type == ethernet::LLDP) {
#else
		if (flow.match.dl_type == LLDP_TYPE) {
#endif
		return CONTINUE;
	}

	uint64_t key = EPoint::generate_key(dpid, port, vlan, mpls);
	boost::shared_ptr<EPoint> ep = rules.getEpoint(key);

	if (ep == NULL) {
		lg.dbg("EPoint not found. %ld:%d v:%d m:%d k:%lu", dpid, port, vlan,
				mpls, key);
		/*DROP packet*/
	} else {
		if (locator.insertClient(dl_src, ep))
			locator.printLocations();
		/*TODO fix buffer id -1*/
		process_packet_in(ep, flow, b, -1);
	}

	return CONTINUE;
}

void fns::process_packet_in(boost::shared_ptr<EPoint> ep_src, const Flow& flow,
		const Buffer& buff, int buf_id) {
	boost::shared_ptr<EPoint> ep_dst;
	ofp_match match;
	vector<Node*> path;
	int in_port = 0, out_port = 0;
	int psize;
	buf_id = -1;
	pair<int, int> ports;
	boost::shared_ptr<FNS> fns = rules.getFNS(ep_src->fns_uuid);
	boost::shared_ptr<Buffer> buff1;// = boost::shared_ptr<Buffer>();

	lg.dbg("Processing and installing rule for %ld:%d in fns: %ld\n",
			ep_src->ep_id, ep_src->in_port, fns->getUuid());
	/* Is destination broadcast address and ARP?*/
#ifdef NOX_OF10
	ethernetaddr dl_dst = ethernetaddr(flow.dl_dst);
	ethernetaddr dl_src = ethernetaddr(flow.dl_src);
	if (flow.dl_type == ethernet::ARP) {
#else
		ethernetaddr dl_dst = ethernetaddr(flow.match.dl_dst);
		ethernetaddr dl_src = ethernetaddr(flow.match.dl_src);
		if (flow.match.dl_type == ETH_TYPE_ARP) {
#endif
		lg.dbg("Sending ARP to all endpoints: src %s dst: %s",
				dl_src.string().c_str(), dl_dst.string().c_str());
		for (int j = 0; j < fns->numEPoints(); j++) {
			boost::shared_ptr<EPoint> ep = fns->getEPoint(j);

			if (ep->key == ep_src->key) {
				continue;
			}

			/* VLAN MANIPULATION */
			if (ep->vlan != ep_src->vlan && ep->vlan != fns::VLAN_NONE
					&& ep_src->vlan != fns::VLAN_NONE) {
				/* Change VLAN*/
				lg.dbg("Sending VLAN SWAP");
				buff1 = PacketUtil::pkt_swap_vlan(buff, ep->vlan);
				forward_via_controller(ep->ep_id, buff1, ep->in_port);
			} else if (ep_src->vlan != fns::VLAN_NONE && ep->vlan
					== fns::VLAN_NONE) {
				/* Remove tag*/
				lg.dbg("Sending VLAN POP");
				buff1 = PacketUtil::pkt_pop_vlan(buff);
				forward_via_controller(ep->ep_id, buff1, ep->in_port);
			} else if (ep_src->vlan == fns::VLAN_NONE && ep->vlan
					!= fns::VLAN_NONE) {
				/* Append VLAN */
				lg.dbg("Sending VLAN PUSH");
				buff1 = PacketUtil::pkt_push_vlan(buff, ep->vlan);
				forward_via_controller(ep->ep_id, buff1, ep->in_port);
			}

			forward_via_controller(ep->ep_id, buff, ep->in_port);
		}
	}

	/*Get location of destination*/
	ep_dst = locator.getLocation(dl_dst);
	if (ep_dst == NULL) {
		lg.warn("NO destination for this packet in the LOCATOR: %s",
				dl_dst.string().c_str());
		locator.printLocations();
		return;
	}

	/* Compute path from source*/
	/* TODO Caching is required if the network is big*/
	if (finder.compute(ep_src->ep_id) < 0) {
		printf("error computing path\n");
		return;
	}

	/*Check that the endpoint is valid: ISOLATION*/
	lg.dbg("Checking isolation");
	if (ep_dst->fns_uuid != ep_src->fns_uuid) {
		lg.warn("Destination not in the FNS");
		return;
	}

	/*Get shortest path*/
	//	finder.PrintShortestRouteTo(ep_dst->ep_id);
	path = finder.getPath(ep_dst->ep_id);
	psize = path.size();

	/*Install specific rules with src and destination L2*/
	lg.dbg("VLAN src: %d dst: %d", ep_src->vlan, ep_dst->vlan);

	for (int k = psize - 1; k >= 0; k--) {
		if (psize == 1) {
			/*Endpoint in the same node*/
			ports = pair<int, int> (ep_dst->in_port, ep_src->in_port);
		} else if (k > 0) {
			ports = path.at(k)->getPortTo(path.at(k - 1));
		}
		out_port = ports.first;
		if (k == 0) {
			out_port = ep_dst->in_port;
		}
		if (k == path.size() - 1) {
			in_port = ep_src->in_port;
		}

		/*Conflict resolution*/
		//flow = getMatchFlow(path.at(k)->id, flow);


		/*dst node and no expect vlan*/
		if (k == path.size() - 1 && ep_dst->vlan == fns::VLAN_NONE
				&& ep_src->vlan != fns::VLAN_NONE) {
			/*pop vlan*/
			match = install_rule_vlan_pop(path.at(k)->id, out_port, dl_dst,
					buf_id, ep_src->vlan);
		} else if (k == path.size() - 1 && ep_dst->vlan != fns::VLAN_NONE
				&& ep_src->vlan == fns::VLAN_NONE) {
			/*push vlan*/
			match = install_rule_vlan_push(path.at(k)->id, out_port, dl_dst,
					buf_id, ep_dst->vlan);
		} else if (k == path.size() - 1 && ep_dst->vlan != ep_src->vlan
				&& ep_src->vlan != fns::VLAN_NONE) {
			/*change vlan*/
			match = install_rule_vlan_swap(path.at(k)->id, out_port, dl_dst,
					buf_id, ep_src->vlan, ep_dst->vlan);
		} else {
			/*none*/
			match = install_rule(path.at(k)->id, out_port, dl_dst, buf_id,
					ep_dst->vlan, 0);
		}

		/* Keeping track of the installed rules */
		boost::shared_ptr<FNSRule> rule = boost::shared_ptr<FNSRule>(
				new FNSRule(path.at(k)->id, match));
		ep_src->addRule(rule);
		ep_dst->addRule(rule);

		if ((k == 0) && (ep_src->vlan == fns::VLAN_NONE) && (ep_dst->vlan
				!= fns::VLAN_NONE)) {
			/*src node*/

			/*pop vlan*/
			match = install_rule_vlan_pop(path.at(k)->id, in_port, dl_src,
					buf_id, ep_dst->vlan);
		} else if ((k == 0) && ep_src->vlan != fns::VLAN_NONE && ep_dst->vlan
				== fns::VLAN_NONE) {
			/*push vlan*/
			match = install_rule_vlan_push(path.at(k)->id, in_port, dl_src,
					buf_id, ep_src->vlan);
		} else if ((k == 0) && ep_dst->vlan != ep_src->vlan && ep_src->vlan
				!= fns::VLAN_NONE) {
			/*change vlan*/
			match = install_rule_vlan_swap(path.at(k)->id, in_port, dl_src,
					buf_id, ep_dst->vlan, ep_src->vlan);
		} else {
			/*none*/
			match = install_rule(path.at(k)->id, in_port, dl_src, buf_id,
					ep_src->vlan, 0);
		}
		/* Keeping track of the installed rules */

		rule = boost::shared_ptr<FNSRule>(new FNSRule(path.at(k)->id, match));
		ep_src->addRule(rule);
		ep_dst->addRule(rule);

		in_port = ports.second;

	}

}
#ifdef NOX_OF10
void fns::set_match(struct ofp_match* match, vigil::ethernetaddr dl_dst,
		uint16_t vlan) {
	memset(match, 0, sizeof(struct ofp_match));
	/*WILD cards*/
	uint32_t filter = OFPFW_ALL;
	/*Filter by port*/
	filter &= (~OFPFW_DL_DST);
	filter &= (~OFPFW_DL_VLAN);
	memcpy(match->dl_dst, dl_dst.octet, sizeof(dl_dst.octet));
	match->dl_vlan = vlan;
	match->wildcards = htonl(filter);
}

void fns::set_mod_def(struct ofp_flow_mod *ofm, int p_out, int buf) {
	ofm->buffer_id = buf;
	ofm->header.version = OFP_VERSION;
	ofm->header.type = OFPT_FLOW_MOD;

	/*Some more parameters*/
	ofm->cookie = htonl(cookie);
	ofm->command = htons(OFPFC_ADD);
	ofm->hard_timeout = htons(0);
	ofm->idle_timeout = htons(HARD_TIMEOUT);
	ofm->priority = htons(OFP_DEFAULT_PRIORITY);
	ofm->flags = ofd_flow_mod_flags();
}

ofp_match fns::install_rule(uint64_t id, int p_out, vigil::ethernetaddr dl_dst,
		int buf, uint16_t vlan, uint32_t mpls) {
	datapathid src;
	ofp_action_list actlist;
	lg.warn("Installing new path: %ld: %d ->  %s\n", id, p_out,
			dl_dst.string().c_str());

	/*OpenFlow command initialization*/
	ofp_flow_mod* ofm;
	size_t size = sizeof *ofm + sizeof(ofp_action_output);
	boost::shared_array<char> raw_of(new char[size]);
	ofm = (ofp_flow_mod*) raw_of.get();
	ofm->header.length = htons(size);
	src = datapathid::from_host(id);

	set_match(&ofm->match, dl_dst, vlan);
	set_mod_def(ofm, p_out, buf);

	/*Action*/
	ofp_action_output& action = *((ofp_action_output*) ofm->actions);
	memset(&action, 0, sizeof(ofp_action_output));

	action.type = htons(OFPAT_OUTPUT);
	action.len = htons(sizeof(ofp_action_output));
	action.max_len = htons(0);
	action.port = htons(p_out);

	/*Send command*/
	send_openflow_command(src, &ofm->header, true);
	cookie++;
	return ofm->match;
}

ofp_match fns::install_rule_vlan_push(uint64_t id, int p_out,
		vigil::ethernetaddr dl_dst, int buf, uint32_t vlan) {
	return install_rule_vlan_swap(id, p_out, dl_dst, buf, VLAN_NONE, vlan);
}

ofp_match fns::install_rule_vlan_pop(uint64_t id, int p_out,
		vigil::ethernetaddr dl_dst, int buf, uint32_t vlan) {
	datapathid src;
	ofp_action_list actlist;
	lg.warn("Installing new path: %ld: %d ->  %s\n", id, p_out,
			dl_dst.string().c_str());

	/*OpenFlow command initialization*/
	ofp_flow_mod* ofm;
	size_t size = sizeof *ofm + sizeof(ofp_action_output)
			+ sizeof(ofp_action_header);
	boost::shared_array<char> raw_of(new char[size]);
	ofm = (ofp_flow_mod*) raw_of.get();
	ofm->header.length = htons(size);
	src = datapathid::from_host(id);

	set_match(&ofm->match, dl_dst, vlan);
	set_mod_def(ofm, p_out, buf);

	/*Action*/
	ofp_action_output& action = *((ofp_action_output*) ofm->actions);
	memset(&action, 0, sizeof(ofp_action_output));

	action.type = htons(OFPAT_OUTPUT);
	action.len = htons(sizeof(ofp_action_output));
	action.max_len = htons(0);
	action.port = htons(p_out);

	ofp_action_header& action_vlan = *((ofp_action_header*) (ofm->actions
			+ sizeof(ofp_action_output)));
	memset(&action_vlan, 0, sizeof(ofp_action_header));

	action_vlan.type = htons(OFPAT_STRIP_VLAN);
	action_vlan.len = htons(sizeof(ofp_action_header));

	/*Send command*/
	send_openflow_command(src, &ofm->header, true);
	cookie++;
	return ofm->match;
}

ofp_match fns::install_rule_vlan_swap(uint64_t id, int p_out,
		vigil::ethernetaddr dl_dst, int buf, uint32_t tag_in, uint32_t tag_out) {
	datapathid src;
	ofp_action_list actlist;
	lg.warn("Installing new path: %ld: %d ->  %s\n", id, p_out,
			dl_dst.string().c_str());

	/*OpenFlow command initialization*/
	ofp_flow_mod* ofm;
	size_t size = sizeof *ofm + sizeof(ofp_action_output)
			+ sizeof(ofp_action_vlan_vid);
	boost::shared_array<char> raw_of(new char[size]);
	ofm = (ofp_flow_mod*) raw_of.get();
	ofm->header.length = htons(size);
	src = datapathid::from_host(id);

	set_match(&ofm->match, dl_dst, tag_in);
	set_mod_def(ofm, p_out, buf);

	/*Action*/
	ofp_action_output& action = *((ofp_action_output*) ofm->actions);
	memset(&action, 0, sizeof(ofp_action_output));

	action.type = htons(OFPAT_OUTPUT);
	action.len = htons(sizeof(ofp_action_output));
	action.max_len = htons(0);
	action.port = htons(p_out);

	ofp_action_vlan_vid& action_vlan = *((ofp_action_vlan_vid*) (ofm->actions
			+ sizeof(ofp_action_output)));
	memset(&action_vlan, 0, sizeof(ofp_action_vlan_vid));

	action_vlan.type = htons(OFPAT_SET_VLAN_VID);
	action_vlan.len = htons(sizeof(ofp_action_vlan_vid));
	action_vlan.vlan_vid = htons(tag_out);

	/*Send command*/
	send_openflow_command(src, &ofm->header, true);
	cookie++;
	return ofm->match;
}

int fns::remove_rule(boost::shared_ptr<FNSRule> rule) {
	datapathid src;
	ofp_action_list actlist;

	lg.warn("Removing rule from switch: %lu", rule->sw_id);
	/*OpenFlow command initialization*/
	ofp_flow_mod* ofm;
	size_t size = sizeof *ofm;
	boost::shared_array<char> raw_of(new char[size]);
	ofm = (ofp_flow_mod*) raw_of.get();

	src = datapathid::from_host(rule->sw_id);

	ofm->header.version = OFP_VERSION;
	ofm->header.type = OFPT_FLOW_MOD;

	ofm->header.length = htons(size);
	memcpy(&ofm->match, &rule->match, sizeof(rule->match));

	ofm->command = htons(OFPFC_DELETE);
	ofm->out_port = OFPP_NONE;
	ofm->hard_timeout = 0;
	ofm->priority = htons(OFP_DEFAULT_PRIORITY);
	ofm->flags = ofd_flow_mod_flags();
	/*Send command*/
	send_openflow_command(src, &ofm->header, true);
	cookie++;
	return 0;
}
#endif

#ifdef NOX_OF11
void fns::set_match(struct ofp_match* match, vigil::ethernetaddr dl_dst,
		uint16_t vlan) {
	memset(match, 0, sizeof(struct ofl_match_standard));
	match->type = OFPMT_STANDARD;
	match->wildcards = OFPFW_ALL;
	match->wildcards = OFPFW_ALL & ~OFPFW_DL_VLAN;
	memset(match->dl_src_mask, 0xff, 6);
	//   memset(match.dl_dst_mask, 0xff, 6);
	match->nw_src_mask = 0xffffffff;
	match->nw_dst_mask = 0xffffffff;
	match->metadata_mask = 0xffffffffffffffffULL;
	match->dl_vlan = vlan;
	//match.in_port = htonl(p_in);
	/* L2 dst */
	memset(match->dl_dst_mask, 0, sizeof(match->dl_dst_mask));
	memcpy(match->dl_dst, dl_dst.octet, sizeof(dl_dst.octet));
}

void fns::set_mod_def(struct ofl_msg_flow_mod *mod, int p_out, int buf) {
	mod->header.type = OFPT_FLOW_MOD;
	mod->cookie = htonl(cookie);
	mod->cookie_mask = 0x00ULL;
	mod->table_id = 0;
	mod->command = OFPFC_ADD;
	mod->out_port = htonl(p_out);
	mod->out_group = 0;
	mod->flags = 0x0000;
	mod->instructions_num = 1;
	mod->priority = htons(OFP_DEFAULT_PRIORITY);
	mod->buffer_id = buf;
	mod->hard_timeout = htonl(HARD_TIMEOUT);
	mod->idle_timeout = IDLE_TIMEOUT;
}

ofp_match fns::install_rule(uint64_t id, int p_out, vigil::ethernetaddr dl_dst,
		int buf, uint16_t vlan, uint32_t mpls) {
	struct ofp_match match;
	struct ofl_msg_flow_mod mod;

	lg.warn("Installing new path: %ld: %d ->  %s\n", id, p_out,
			dl_dst.string().c_str());

	set_match(&match, dl_dst, vlan);
	set_mod_def(&mod, p_out, buf);
	mod.match = (struct ofl_match_header *) &match;

	/* Actions */
	struct ofl_action_output output = { {/*.type = */OFPAT_OUTPUT}, /*.port = */
		p_out, /*.max_len = */0};
	struct ofl_action_header *actions[] = {
		(struct ofl_action_header *) &output};
	struct ofl_instruction_actions apply = { {/*.type = */
			OFPIT_WRITE_ACTIONS}, /*.actions_num = */1, /*.actions = */
		actions};
	struct ofl_instruction_header *insts[] = {
		(struct ofl_instruction_header *) &apply};

	mod.instructions = insts;

	if (send_openflow_msg(datapathid::from_host(id),
					(struct ofl_msg_header *) &mod, 0/*xid*/, false) == EAGAIN) {
		lg.err("Error, unable to clear flow table on startup");
	}
	return match;
}

ofp_match fns::install_rule_vlan_push(uint64_t id, int p_out,
		vigil::ethernetaddr dl_dst, int buf, uint32_t tag) {
	struct ofp_match match;
	struct ofl_msg_flow_mod mod;

	lg.warn("Installing new path : %ld PUSH %d: %d -> %s\n", id, tag, p_out,
			dl_dst.string().c_str());

	set_match(&match, dl_dst, OFPVID_NONE);
	set_mod_def(&mod, p_out, buf);
	mod.match = (struct ofl_match_header *) &match;

	/* Actions */
	struct ofl_action_output output = { {/*.type = */OFPAT_OUTPUT}, /*.port = */
		p_out, /*.max_len = */0};
	struct ofl_action_push push = { {/*.type = */OFPAT_PUSH_VLAN}, /*.ethertype = */
		ETH_TYPE_VLAN};
	struct ofl_action_vlan_vid set_vlan = { {/*.type = */OFPAT_SET_VLAN_VID}, /*.VLAN id = */
		tag};

	struct ofl_action_header *actions[] = {
		(struct ofl_action_header *) &output,
		(struct ofl_action_header *) &push,
		(struct ofl_action_header *) &set_vlan};

	struct ofl_instruction_actions apply = { {/*.type = */
			OFPIT_WRITE_ACTIONS}, /*.actions_num = */3, /*.actions = */
		actions};

	struct ofl_instruction_header *insts[] = {
		(struct ofl_instruction_header *) &apply};

	mod.instructions = insts;

	if (send_openflow_msg(datapathid::from_host(id),
					(struct ofl_msg_header *) &mod, 0/*xid*/, false) == EAGAIN) {
		lg.err("Error, unable to clear flow table on startup");
	}
	return match;
}

ofp_match fns::install_rule_vlan_pop(uint64_t id, int p_out,
		vigil::ethernetaddr dl_dst, int buf, uint32_t tag) {
	struct ofp_match match;
	struct ofl_msg_flow_mod mod;
	datapathid dpid = datapathid::from_host(id);

	lg.warn("Installing new path  %ld POP %d: %d ->%s\n", id, tag, p_out,
			dl_dst.string().c_str());
	set_match(&match, dl_dst, tag);
	set_mod_def(&mod, p_out, buf);
	mod.match = (struct ofl_match_header *) &match;

	/* Actions */
	struct ofl_action_output output = { {/*.type = */OFPAT_OUTPUT}, /*.port = */
		p_out, /*.max_len = */0};
	struct ofl_action_push pop = { {/*.type = */OFPAT_POP_VLAN}, /*.ethertype = */
		ETH_TYPE_IP};

	struct ofl_action_header *actions[] = {
		(struct ofl_action_header *) &output,
		(struct ofl_action_header *) &pop};

	struct ofl_instruction_actions apply = { {/*.type = */
			OFPIT_WRITE_ACTIONS}, /*.actions_num = */2, /*.actions = */
		actions};

	struct ofl_instruction_header *insts[] = {
		(struct ofl_instruction_header *) &apply};

	mod.instructions = insts;

	if (send_openflow_msg(dpid, (struct ofl_msg_header *) &mod, 0/*xid*/, false)
			== EAGAIN) {
		lg.err("Error, unable to clear flow table on startup");
	}
	return match;
}

ofp_match fns::install_rule_vlan_swap(uint64_t id, int p_out,
		vigil::ethernetaddr dl_dst, int buf, uint32_t tag_in, uint32_t tag_out) {
	struct ofp_match match;
	struct ofl_msg_flow_mod mod;

	lg.warn("Installing new path : %ld CHANGE TAG %d -> %d %d -> %s\n", id,
			tag_in, tag_out, p_out, dl_dst.string().c_str());

	set_match(&match, dl_dst, tag_in);
	set_mod_def(&mod, p_out, buf);
	mod.match = (struct ofl_match_header *) &match;

	/* Actions */
	struct ofl_action_output output = { {/*.type = */OFPAT_OUTPUT}, /*.port = */
		p_out, /*.max_len = */0};
	struct ofl_action_vlan_vid set_vlan = { {/*.type = */OFPAT_SET_VLAN_VID}, /*.VLAN id = */
		tag_out};

	struct ofl_action_header *actions[] = {
		(struct ofl_action_header *) &output,
		(struct ofl_action_header *) &set_vlan};

	struct ofl_instruction_actions apply = { {/*.type = */
			OFPIT_WRITE_ACTIONS}, /*.actions_num = */2, /*.actions = */
		actions};

	struct ofl_instruction_header *insts[] = {
		(struct ofl_instruction_header *) &apply};

	mod.instructions = insts;

	if (send_openflow_msg(datapathid::from_host(id),
					(struct ofl_msg_header *) &mod, 0/*xid*/, false) == EAGAIN) {
		lg.err("Error, unable to clear flow table on startup");
	}
	return match;
}

ofp_match fns::install_rule_mpls_push(uint64_t id, int p_out,
		vigil::ethernetaddr dl_dst, int buf, uint32_t tag) {
	struct ofp_match match;
	struct ofl_msg_flow_mod mod;

	lg.warn("Installing new path : %ld PUSH %d: %d -> %s\n", id, tag, p_out,
			dl_dst.string().c_str());

	set_match(&match, dl_dst, OFPVID_NONE);
	set_mod_def(&mod, p_out, buf);
	mod.match = (struct ofl_match_header *) &match;

	/* Actions */
	struct ofl_action_output output = { {/*.type = */OFPAT_OUTPUT}, /*.port = */
		p_out, /*.max_len = */0};
	struct ofl_action_push push = { {/*.type = */OFPAT_PUSH_MPLS}, /*.ethertype = */
		ETH_TYPE_MPLS};
	struct ofl_action_mpls_label set_label = { {/*.type = */
			OFPAT_SET_MPLS_LABEL}, /*.MPLS label = */
		tag};
	struct ofl_action_mpls_tc set_tc = { {/*.type = */OFPAT_SET_MPLS_TC}, /*.MPLS TC = */
		PacketUtil::TC_IPV4};
	struct ofl_action_mpls_tc set_ttl = { {/*.type = */OFPAT_SET_MPLS_TTL}, /*.MPLS TTL = */
		20};

	struct ofl_action_header *actions[] = {
		(struct ofl_action_header *) &output,
		(struct ofl_action_header *) &push,
		(struct ofl_action_header *) &set_label,
		(struct ofl_action_header *) &set_tc,
		(struct ofl_action_header *) &set_ttl};

	struct ofl_instruction_actions apply = { {/*.type = */
			OFPIT_WRITE_ACTIONS}, /*.actions_num = */5, /*.actions = */
		actions};

	struct ofl_instruction_header *insts[] = {
		(struct ofl_instruction_header *) &apply};

	mod.instructions = insts;

	if (send_openflow_msg(datapathid::from_host(id),
					(struct ofl_msg_header *) &mod, 0/*xid*/, false) == EAGAIN) {
		lg.err("Error, unable to clear flow table on startup");
	}
	return match;
}

ofp_match fns::install_rule_mpls_pop(uint64_t id, int p_out,
		vigil::ethernetaddr dl_dst, int buf, uint32_t tag) {
	struct ofp_match match;
	struct ofl_msg_flow_mod mod;
	datapathid dpid = datapathid::from_host(id);

	lg.warn("Installing new path  %ld POP %d: %d ->%s\n", id, tag, p_out,
			dl_dst.string().c_str());
	set_match(&match, dl_dst, tag);
	match.dl_type = ETH_TYPE_MPLS;
	set_mod_def(&mod, p_out, buf);
	mod.match = (struct ofl_match_header *) &match;

	/* Actions */
	struct ofl_action_output output = { {/*.type = */OFPAT_OUTPUT}, /*.port = */
		p_out, /*.max_len = */0};
	struct ofl_action_push pop = { {/*.type = */OFPAT_POP_MPLS}, /*.ethertype = */
		ETH_TYPE_IP};

	struct ofl_action_header *actions[] = {
		(struct ofl_action_header *) &output,
		(struct ofl_action_header *) &pop};

	struct ofl_instruction_actions apply = { {/*.type = */
			OFPIT_WRITE_ACTIONS}, /*.actions_num = */2, /*.actions = */
		actions};

	struct ofl_instruction_header *insts[] = {
		(struct ofl_instruction_header *) &apply};

	mod.instructions = insts;

	if (send_openflow_msg(dpid, (struct ofl_msg_header *) &mod, 0/*xid*/, false)
			== EAGAIN) {
		lg.err("Error, unable to clear flow table on startup");
	}
	return match;
}

ofp_match fns::install_rule_mpls_swap(uint64_t id, int p_out,
		vigil::ethernetaddr dl_dst, int buf, uint32_t tag_in, uint32_t tag_out) {
	struct ofp_match match;
	struct ofl_msg_flow_mod mod;

	lg.warn("Installing new path : %ld CHANGE TAG %d -> %d %d -> %s\n", id,
			tag_in, tag_out, p_out, dl_dst.string().c_str());

	set_match(&match, dl_dst, tag_in);
	set_mod_def(&mod, p_out, buf);
	mod.match = (struct ofl_match_header *) &match;

	/* Actions */
	struct ofl_action_output output = { {/*.type = */OFPAT_OUTPUT}, /*.port = */
		p_out, /*.max_len = */0};
	struct ofl_action_vlan_vid set_vlan = { {/*.type = */
			OFPAT_SET_MPLS_LABEL}, /*.VLAN id = */
		tag_out};

	struct ofl_action_header *actions[] = {
		(struct ofl_action_header *) &output,
		(struct ofl_action_header *) &set_vlan};

	struct ofl_instruction_actions apply = { {/*.type = */
			OFPIT_WRITE_ACTIONS}, /*.actions_num = */2, /*.actions = */
		actions};

	struct ofl_instruction_header *insts[] = {
		(struct ofl_instruction_header *) &apply};

	mod.instructions = insts;

	if (send_openflow_msg(datapathid::from_host(id),
					(struct ofl_msg_header *) &mod, 0/*xid*/, false) == EAGAIN) {
		lg.err("Error, unable to clear flow table on startup");
	}
	return match;
}

int fns::remove_rule(boost::shared_ptr<FNSRule> rule) {
	datapathid dpid;

	lg.dbg("Removing rule in %lu", rule->sw_id);
	/*OpenFlow command initialization*/
	dpid = datapathid::from_host(rule->sw_id);

	struct ofl_msg_flow_mod mod;
	mod.header.type = OFPT_FLOW_MOD;
	mod.cookie = 0x00ULL;
	mod.cookie_mask = 0x00ULL;
	mod.table_id = 0xff; // all tables
	mod.command = OFPFC_DELETE;
	mod.out_port = OFPP_ANY;
	mod.out_group = OFPG_ANY;
	mod.flags = 0x0000;
	mod.match = (struct ofl_match_header *) &rule->match;
	mod.instructions_num = 0;
	mod.instructions = NULL;

	/* XXX OK to do non-blocking send?  We do so with all other
	 * commands on switch join */
	if (send_openflow_msg(dpid, (struct ofl_msg_header *) &mod, 0/*xid*/, false)
			== EAGAIN) {
		lg.err("Error, unable to clear flow table on startup");
	}
	return 0;
}

#endif

void fns::forward_via_controller(uint64_t id, boost::shared_ptr<Buffer> buff,
		int port) {

	lg.warn("ATTENTION. Sending packet directly to the destination: %lu :%d",
			id, port);

#ifdef NOX_OF10
	send_openflow_packet(datapathid::from_host(id), *buff, port, 0, false);
#else
	send_openflow_pkt(datapathid::from_host(id), *buff, OFPP_CONTROLLER, port,
			false);
#endif
}
void fns::forward_via_controller(uint64_t id, const Buffer &buff, int port) {
	lg.warn("ATTENTION. Sending packet directly to the destination: %lu :%d",
			id, port);

#ifdef NOX_OF10
	send_openflow_packet(datapathid::from_host(id), buff, port, 0, false);
#else
	send_openflow_pkt(datapathid::from_host(id), buff, OFPP_CONTROLLER, port,
			false);
#endif
}

Flow* fns::getMatchFlow(uint64_t id, Flow* flow) {
	return flow;
}

int fns::mod_fns_add(fnsDesc* fns1) {
	boost::shared_ptr<FNS> fns = rules.getFNS(fns1->uuid);
	if (fns == NULL) {
		lg.warn("The FNS doesn't exists");
		return -1;
	}

	for (int i = 0; i < fns1->nEp; i++) {
		/*Save endpoints and compute path*/
		endpoint *ep = GET_ENDPOINT(fns1, i);
		uint64_t key = rules.addEPoint(ep, fns);

		lg.dbg("Endpoint: %ld : %d vlan: %d m: %d k: %lu\n", ep->swId,
				ep->port, ep->vlan, ep->mpls, key);
		if (!key)
			lg.warn("Collision. Remove endpoint before adding a new one");

	}
	return 0;
}
int fns::mod_fns_del(fnsDesc* fns1) {
	boost::shared_ptr<FNS> fns = rules.getFNS(fns1->uuid);
	if (fns == NULL) {
		lg.warn("The FNS doesn't exist");
		return -1;
	}
	lg.warn("Num of affected endpoints: %d", fns1->nEp);
	for (int i = 0; i < fns1->nEp; i++) {
		remove_endpoint(GET_ENDPOINT(fns1, i), fns);

	}
	return 0;
}

int fns::remove_endpoint(endpoint *epd, boost::shared_ptr<FNS> fns) {
	uint64_t key = EPoint::generate_key(epd->swId, epd->port, epd->vlan,
			epd->mpls);
	boost::shared_ptr<EPoint> ep = rules.getEpoint(key);
	return remove_endpoint(ep, fns);

}
int fns::remove_endpoint(boost::shared_ptr<EPoint> ep,
		boost::shared_ptr<FNS> fns) {

	if (ep == NULL) {
		lg.warn("The EndPoint doesn't exist");
		return -1;
	}
	lg.dbg("Installed rules: %d", (int) ep->num_installed());
	while (ep->num_installed() > 0) {
		boost::shared_ptr<FNSRule> rule = ep->getRuleBack();
		remove_rule(rule);
		ep->installed_pop();
	}
	lg.dbg("Removing EPoint");
	rules.removeEPoint(ep->key);
	fns->removeEPoint(ep);
	return 0;
}
int fns::save_fns(fnsDesc* fns1) {

	boost::shared_ptr<FNS> fns = rules.addFNS(fns1);

	for (int i = 0; i < fns1->nEp; i++) {
		/*Save endpoints and compute path*/
		endpoint *ep = GET_ENDPOINT(fns1, i);
		uint64_t key = rules.addEPoint(ep, fns);

		lg.warn("Endpoint: %ld : %d vlan: %d m: %d k: %lu\n", ep->swId,
				ep->port, ep->vlan, ep->mpls, key);
		if (!key)
			lg.warn("Collision. Remove endpoint before adding a new one");

	}
	return 0;
}
int fns::remove_fns(fnsDesc* fns1) {
	boost::shared_ptr<FNS> fns = rules.getFNS(fns1->uuid);

	lg.warn("Removing fns with uuid: %lu \n", fns->getUuid());
	if (fns == NULL) {
		lg.warn("The FNS doesn't exists");
		return -1;
	}

	/* Go to any end nodes and remove installed path */
	lg.warn("Num of affected endpoints: %d", fns->numEPoints());
	while (fns->numEPoints() > 0) {
		remove_endpoint(fns->getEPoint(0), fns);
	}

	/* Remove fns from the list and free memory*/
	lg.warn("removing fns");
	rules.removeFNS(fns->getUuid());

	return 0;
}

void fns::server() {

	socklen_t addrlen;
	struct sockaddr_in serv_addr, clientaddr;
	int yes = 1;
	int sockfd = 0;
	int listener;
	fd_set master; /* master file descriptor list */
	fd_set read_fds; /* temp file descriptor list for select() */
	int fdmax;
	int newfd;
	int nbytes;
	struct timeval tv;
	uint8_t* buf;
	int i;

	listener = socket(AF_INET, SOCK_STREAM, 0);
	if (listener < 0) {
		perror("ERROR opening socket");
		exit(1);
	}

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(server_port);

	if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
		perror("ERROR on setsockopt()");
		exit(1);
	}

	if (bind(listener, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		close(listener);
		perror("ERROR on binding");
		exit(1);
	}

	if (listen(listener, MAX_CONNECTIONS) == -1) {
		perror("ERROR on listen");
		exit(1);
	}

	fdmax = listener; /* maximum file descriptor number */

	/*Allocate reception buffer*/
	buf = (uint8_t*) malloc(MSG_SIZE);
	if (buf == NULL) {
		perror("ERROR in malloc");
		exit(1);
	}

	/* clear the master and temp sets */
	FD_ZERO(&master);
	FD_ZERO(&read_fds);

	/* add the listener to the master set */
	FD_SET(listener, &master);

	/*Loop forever*/
	while (1) {
		/* copy it */
		read_fds = master;

		/*Set timeout*/
		tv.tv_sec = SELECT_TIMEOUT;
		tv.tv_usec = 0;
		if (select(fdmax + 1, &read_fds, NULL, NULL, &tv) == -1) {
			perror("Server-select()");
			exit(1);
		}

		/*Check listening*/
		if (FD_ISSET(listener, &read_fds)) {
			addrlen = sizeof(clientaddr);
			if ((newfd = accept(listener, (struct sockaddr *) &clientaddr,
					(socklen_t *) &addrlen)) == -1) {
				perror("Server-accept() error lol!");
				continue;
			}
			FD_SET(newfd, &master); /* add to master set */
			/*TODO manage multiple ports*/
			sockfd = newfd;

			if (newfd > fdmax)
				fdmax = newfd;//* keep track of the maximum */

			printf("New connection in %d\n", sockfd);

		}
		int s = sockfd;
		if (FD_ISSET(s, &read_fds)) {
			/*do the job*/
			if ((nbytes = recv(s, buf, MSG_SIZE, 0)) <= 0) {
				/* got error or connection closed by client */
				if (nbytes == 0) {
					/* connection closed */
					printf("socket hung up\n");
				} else {
					perror("recv()");
				}
				/* close it... */
				close(s);
				/* remove from master set */
				FD_CLR(s, &master);
				//} else if (nbytes < sizeof(struct msg_hdr)) {
				//	lg.dbg("Too small packet");
			} else {
				/* we got some data from a client*/
				lg.dbg("New msg of size %d", nbytes);
				unsigned int offset = 0;
				do {
					struct msg_fns *msg = (struct msg_fns*) (buf + offset);
					switch (msg->type) {
					case FNS_MSG_MOD_ADD:
						mod_fns_add(&msg->fns);
						break;
					case FNS_MSG_MOD_DEL:
						mod_fns_del(&msg->fns);
						break;
					case FNS_MSG_ADD:
						save_fns(&msg->fns);
						break;
					case FNS_MSG_DEL:
						remove_fns(&msg->fns);
						break;
					case FNS_MSG_SW_IDS: {
						/**TODO return IDs of the endpoints and num of ports*/
						vector<Node*> nodeFinder = finder.getNodes();
						lg.dbg("Current nodes in the controller:");
						int size = sizeof(struct msg_ids) + nodeFinder.size()
								* sizeof(endpoint);
						struct msg_ids *msg1 = (struct msg_ids *) malloc(size);
						memset(msg1, 0, size);
						msg1->nEp = nodeFinder.size();
						msg1->type = FNS_MSG_SW_IDS;
						for (i = 0; i < nodeFinder.size(); i++) {
							lg.dbg("ID: %lu: ports: %d", nodeFinder.at(i)->id,
									nodeFinder.at(i)->ports);
							msg1->endpoints[i].swId = nodeFinder.at(i)->id;
							msg1->endpoints[i].port = nodeFinder.at(i)->ports;
						}
						if (write(s, msg1, size) < 0)
							lg.err("Error sending packet");
						break;
					}
					default:
						lg.err("Invalid message of size %d: %s\n", nbytes,
								(char*) buf);
						break;
					}
					offset += (msg->size);
					lg.dbg("msg size %d %d", (msg->size), offset);

				} while (offset < nbytes);
			}
		}
	}
	lg.dbg("Finishing server");
	free(buf);
	/*Close all sockets*/
	close(listener);

}
void fns::configure(const Configuration* c) {
	server_port = TCP_PORT;

	const hash_map<string, string> argmap = c->get_arguments_list();
	hash_map<string, string>::const_iterator i;
	i = argmap.find("tcpport");
	if (i != argmap.end())
		server_port = (uint16_t) atoi(i->second.c_str());

	lg.dbg(" Listening in port: %d", server_port);
}

void fns::install() {
	lg.dbg(" Install called ");
	this->server_thread.start(boost::bind(&fns::server, this));

	register_handler("Link_event", boost::bind(&fns::handle_link_event, this,
			_1));
	register_handler("Datapath_join_event", boost::bind(
			&fns::handle_datapath_join, this, _1));
	register_handler("Datapath_leave_event", boost::bind(
			&fns::handle_datapath_leave, this, _1));
	register_handler("Packet_in_event", boost::bind(&fns::handle_packet_in,
			this, _1));

}

void fns::getInstance(const Context* c, fns*& component) {
	component = dynamic_cast<fns*> (c->get_by_interface(
			container::Interface_description(typeid(fns).name())));
}

REGISTER_COMPONENT(Simple_component_factory<fns>,
		fns)
;
} // vigil namespace

