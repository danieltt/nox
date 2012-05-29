/* Copyright 2012 Daniel Turull (KTH) <danieltt@kth.se>
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

#ifndef EPOINT_HH_
#define EPOINT_HH_

#include "libnetvirt/fns.h"
#include <boost/smart_ptr/shared_ptr.hpp>
#include "noxdetect.hh"

#include <stdio.h>
#include <cstdlib>
#include <list>

#include <stdio.h>
#include <stdint.h>
#include <iostream>
#include <vector>
#include <map>

using namespace std;

class FNSRule {
public:
	FNSRule(uint64_t sw_id, ofp_match match);
	uint64_t sw_id;
	ofp_match match;
};

class EPoint {
public:
	EPoint(uint64_t ep_id, uint32_t in_port, uint16_t vlan, uint64_t fns_uuid);
	EPoint(uint64_t ep_id, uint32_t in_port, uint16_t vlan, uint64_t fns_uuid, uint32_t mpls, uint32_t address, uint8_t mask);
	void addRule(boost::shared_ptr<FNSRule> r);
	int num_installed();
	boost::shared_ptr<FNSRule> getRuleBack();
	void installed_pop();
	static uint64_t generate_key(uint64_t sw_id, uint32_t port, uint16_t vlan, uint32_t mpls);

	uint64_t key;
	uint64_t ep_id;
	int in_port;
	uint16_t vlan;
	uint64_t fns_uuid;
	uint32_t mpls;
	/* L3 fields */
	uint32_t address;
	uint8_t mask;

private:
	vector<boost::shared_ptr<FNSRule> > installed_rules;
};

#endif /* EPOINT_HH_ */
