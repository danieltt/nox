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
#ifndef ROUTE_HH_
#define ROUTE_HH_
#include <boost/smart_ptr/shared_ptr.hpp>
#include "rules.hh"
#include <list>

class Route_entry{
public:
	uint32_t prefix;
	short mask;
	boost::shared_ptr<EPoint> endpoint;
	static bool compare_entry(Route_entry first, Route_entry second);
};

const uint32_t bitmask[]={	0x00000000,	0x8000000,	0xC000000,	0xE000000,
							0xF0000000,	0xF800000,	0xFC00000,	0xFE00000,
							0xFF000000,	0xFF80000,	0xFFC0000,	0xFFE0000,
							0xFFF00000,	0xFFF8000,	0xFFFC000,	0xFFFE000,
							0xFFFF0000,	0xFFFF800,	0xFFFFC00,	0xFFFFE00,
							0xFFFFF000,	0xFFFFF80,	0xFFFFFC0,	0xFFFFFE0,
							0xFFFFFF00,	0xFFFFFF8,	0xFFFFFFC,	0xFFFFFFE,
							0xFFFFFFFF};

class RouteTable {
public:
	boost::shared_ptr<EPoint> getEndpoint(uint32_t target_addr);
	void addNet(Route_entry entry);
	void removeNet(uint32_t prefix, short mask);
	void removeEndoint(boost::shared_ptr<EPoint> epoint);


private:
	std::list<Route_entry> table;

};
#endif /* PACKET_HH_ */
