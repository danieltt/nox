/* Copyright 2008 (C) Nicira, Inc.
 * Copyright 2009 (C) Stanford University.
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
#ifndef fns_HH
#define fns_HH

#include "noxdetect.hh"
#include "component.hh"
#include "config.h"
#include "threads/native.hh"
#include <boost/bind.hpp>
#include "discovery/link-event.hh"
#include "datapath-join.hh"
#include "datapath-leave.hh"
#include "flow.hh"
#include <inttypes.h>
#include "netinet++/datapathid.hh"
#include "openflow-default.hh"

#include "rules.hh"
#include "libnetvirt/fns.h"
#include "PathFinder.hh"

#ifdef LOG4CXX_ENABLED
#include <boost/format.hpp>
#include "log4cxx/logger.h"
#else
#include "vlog.hh"
#endif

namespace vigil {
using namespace std;
using namespace vigil::container;

/** \brief fns
 * \ingroup noxcomponents
 *
 * @author
 * @date
 */
class fns: public Component {
public:

	static const int IDLE_TIMEOUT = 0;
	static const int HARD_TIMEOUT = 0;
	static const int VLAN_NONE = 0xffff;

	/** \brief Constructor of fns.
	 *
	 * @param c context
	 * @param node XML configuration (JSON object)
	 */
	fns(const Context* c, const json_object* node) :
		Component(c) {
	}

	Native_thread server_thread;

	/*Event handlers */
	Disposition handle_link_event(const Event&);
	Disposition handle_datapath_join(const Event& e);
	Disposition handle_datapath_leave(const Event& e);
	Disposition handle_packet_in(const Event& e);



	int remove_rule(boost::shared_ptr<FNSRule> rule);

	int save_fns(fnsDesc* fns);
	int remove_fns(fnsDesc* fns);
	int mod_fns_add(fnsDesc* fns);
	int mod_fns_del(fnsDesc* fns);
	int remove_endpoint(endpoint* epd, boost::shared_ptr<FNS> fns);
	int remove_endpoint(boost::shared_ptr<EPoint> ep,
			boost::shared_ptr<FNS> fns);

	Flow* getMatchFlow(uint64_t id, Flow* flow);

	/** \brief Configure fns.
	 *
	 * Parse the configuration, register event handlers, and
	 * resolve any dependencies.
	 *
	 * @param c configuration
	 */
	void configure(const Configuration* c);

	/** \brief Start fns.
	 *
	 * Start the component. For example, if any threads require
	 * starting, do it now.
	 */
	void install();

	/** \brief Get instance of fns.
	 * @param c context
	 * @param component reference to component
	 */
	static void getInstance(const container::Context* c, fns*& component);

private:
	int server_sock_fd;
	int sock_fd;
	int server_port;
	PathFinder finder;
	RulesDB rules;
	Locator locator;
	uint64_t cookie;

	int sock; /* The socket file descriptor for our "listening"
	 socket */
	int connectlist[MAX_CONNECTIONS]; /* Array of connected sockets so we know who
	 we are talking to */
	fd_set socks; /* Socket file descriptors we want to wake
	 up for, using select() */
	int highsock; /* Highest #'d file descriptor, needed for select() */

	//void setnonblocking(int sock);
	void build_select_list();
	void handle_new_connection();
	void read_socks();
	void server();


	void process_packet_in_l2(boost::shared_ptr<FNS> fns, boost::shared_ptr<EPoint> ep_src, const Flow& flow,
				const Buffer& buff, int buf_id);
	void process_packet_in_l3(boost::shared_ptr<FNS> fns, boost::shared_ptr<EPoint> ep_src, const Flow& flow,
					const Buffer& buff, int buf_id);

	void set_match(struct ofp_match* match, vigil::ethernetaddr dl_dst,
			vigil::ethernetaddr dl_src, uint16_t vlan);
#ifdef NOX_OF11
	void set_mod_def(struct ofl_msg_flow_mod *mod, int p_out, int buf);
#else
	void set_mod_def(struct ofp_flow_mod *mod, int p_out, int buf);
#endif

	void forward_via_controller(uint64_t id,
			const boost::shared_ptr<Buffer> buff, int port);
	void forward_via_controller(uint64_t id, const Buffer &buff, int port);
	void
	send_pkt_to_all_fns(boost::shared_ptr<FNS> fns,
			boost::shared_ptr<EPoint> ep_src, const Buffer& buff);

	ofp_match install_rule(uint64_t id, int p_out, vigil::ethernetaddr dl_dst,
			vigil::ethernetaddr dl_src, int buf, uint16_t vlan, uint32_t mpls);

	ofp_match install_rule_vlan_push(uint64_t id, int p_out,
			vigil::ethernetaddr dl_dst, vigil::ethernetaddr dl_src, int buf,
			uint32_t tag);
	ofp_match install_rule_vlan_pop(uint64_t id, int p_out,
			vigil::ethernetaddr dl_dst, vigil::ethernetaddr dl_src, int buf,
			uint32_t tag);
	ofp_match install_rule_vlan_swap(uint64_t id, int p_out,
			vigil::ethernetaddr dl_dst, vigil::ethernetaddr dl_src, int buf,
			uint32_t tag_in, uint32_t tag_out);

#ifdef NOX_OF11
#ifdef MPLS
	ofp_match install_rule_mpls_push(uint64_t id, int p_out,
			vigil::ethernetaddr dl_dst, int buf, uint32_t tag);
	ofp_match install_rule_mpls_pop(uint64_t id, int p_out,
			vigil::ethernetaddr dl_dst, int buf, uint32_t tag);
	ofp_match install_rule_mpls_swap(uint64_t id, int p_out,
			vigil::ethernetaddr dl_dst, int buf, uint32_t tag_in,
			uint32_t tag_out);
#endif
#endif
};
}
#endif
