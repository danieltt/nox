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

#ifndef RULES_HH_
#define RULES_HH_

#include "libnetvirt/fns.h"
#include "PathFinder.hh"
#include "netinet++/ethernetaddr.hh"
#include <boost/smart_ptr/shared_ptr.hpp>

#include <stdio.h>
#include <cstdlib>

#include "noxdetect.hh"

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
	EPoint(uint64_t ep_id, uint32_t in_port, uint16_t vlan, uint64_t fns_uuid, uint32_t mpls);
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

private:
	vector<boost::shared_ptr<FNSRule> > installed_rules;
};

class FNS{
public:
	FNS(uint64_t uuid, uint8_t forwarding);
	uint64_t getUuid();
	uint8_t getForwarding();
	int numEPoints();
	void addEPoint(boost::shared_ptr<EPoint> ep);
	int removeEPoint(boost::shared_ptr<EPoint> ep);
	boost::shared_ptr<EPoint> getEPoint(int pos);

private:
	uint64_t uuid;
	uint8_t forwarding;
	vector<boost::shared_ptr<EPoint> > epoints;
};


class RulesDB {
public:

	uint64_t addEPoint(endpoint* ep, boost::shared_ptr<FNS> fns);
	boost::shared_ptr<EPoint> getEpoint(uint64_t key);
	void removeEPoint(uint64_t key);

	boost::shared_ptr<FNS> addFNS(fnsDesc* fns);
	void removeFNS(uint64_t uuid);
	boost::shared_ptr<FNS> getFNS(uint64_t uuid);


private:
	PathFinder* finder;
	/* Rules in memory
	 * To be more scalable should be stored in a distributed way*/
	map<uint64_t, boost::shared_ptr<EPoint> > endpoints;
	map<uint64_t, boost::shared_ptr<FNS> > fnsList;
};

class Locator {
public:
	bool insertClient(vigil::ethernetaddr addr, boost::shared_ptr<EPoint> ep);
	boost::shared_ptr<EPoint> getLocation(vigil::ethernetaddr);
	void printLocations();
private:
	map<vigil::ethernetaddr, boost::shared_ptr<EPoint> > clients;
	bool validateAddr(vigil::ethernetaddr addr);

};

#endif /* RULES_HH_ */
