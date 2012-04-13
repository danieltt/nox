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
#include "EPoint.hh"
#include "route.hh"

using namespace std;


class Locator {
public:
	bool insertClient(vigil::ethernetaddr addr, boost::shared_ptr<EPoint> ep);
	boost::shared_ptr<EPoint> getLocation(vigil::ethernetaddr addr);
	void printLocations();
private:
	map<vigil::ethernetaddr, boost::shared_ptr<EPoint> > clients;
	bool validateAddr(vigil::ethernetaddr addr);

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
	/* L3 lookup*/
	boost::shared_ptr<EPoint> lookup(uint32_t addr);
	/* L2 lookup*/
	bool addlocation(vigil::ethernetaddr addr, boost::shared_ptr<EPoint> ep);
	boost::shared_ptr<EPoint> getLocation(vigil::ethernetaddr addr);

	/*ARP table lookup */
	bool addMAC(uint32_t ip, vigil::ethernetaddr mac);
	vigil::ethernetaddr getMAC(uint32_t ip);

private:
	uint64_t uuid;
	uint8_t forwarding;
	vector<boost::shared_ptr<EPoint> > epoints;
	RouteTable table;
	Locator l2table;
	map<uint32_t, vigil::ethernetaddr > mactable;

};



class RulesDB {
public:

	uint64_t addEPoint(endpoint* ep, boost::shared_ptr<FNS> fns);
	boost::shared_ptr<EPoint> getEpoint(uint64_t key);
	void removeEPoint(uint64_t key);

	boost::shared_ptr<FNS> addFNS(fnsDesc* fns);
	void removeFNS(uint64_t uuid);
	boost::shared_ptr<FNS> getFNS(uint64_t uuid);

	boost::shared_ptr<EPoint> getGlobalLocation(vigil::ethernetaddr addr);


private:
	PathFinder* finder;
	/* Rules in memory
	 * To be more scalable should be stored in a distributed way*/
	map<uint64_t, boost::shared_ptr<EPoint> > endpoints;
	map<uint64_t, boost::shared_ptr<FNS> > fnsList;
};



#endif /* RULES_HH_ */
