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

#include "route.hh"


bool Route_entry::compare_entry(Route_entry first, Route_entry second){
	if(first.mask < second.mask)
		return true;
	if(first.mask > second.mask)
		return false;
	if(first.prefix < second.prefix)
		return true;
	else return false;
}

boost::shared_ptr<EPoint> RouteTable::getEndpoint(uint32_t target_addr){
	list<Route_entry>::iterator it;
	for (it=table.begin(); it!=table.end(); ++it){
		if(it->prefix == (target_addr & bitmask[it->mask]))
			return it->endpoint;
	}
	return boost::shared_ptr<EPoint>();
}
void RouteTable::addNet(Route_entry entry){
	table.push_front(entry);
	table.sort(Route_entry::compare_entry);
}
void RouteTable::removeNet(uint32_t prefix, short mask){
	list<Route_entry>::iterator it;
	for (it=table.begin(); it!=table.end(); ++it){
			if(it->mask == prefix && it->prefix == mask)
				table.erase(it);
	}
}
void RouteTable::removeEndoint(boost::shared_ptr<EPoint> epoint){
	list<Route_entry>::iterator it;
		for (it=table.begin(); it!=table.end(); ++it){
				if(it->endpoint == epoint)
					table.erase(it);
		}
}
