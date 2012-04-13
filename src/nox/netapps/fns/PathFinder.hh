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

#ifndef PATHFINDER_H_
#define PATHFINDER_H_
#define MAX_DIST 10000
#include <stdio.h>
#include <stdint.h>
#include <iostream>
#include <vector>
#include <map>

using namespace std;

class LinkAtr {
public:
	LinkAtr(int distance, int sport, int dport) :
		distance(distance) {
		ports = pair<int, int> (sport, dport);
	}
	int distance;
	pair<int, int> ports;

};

class Node {
public:
	Node(uint64_t id,int ports) :
		id(id), ports(ports), previous(NULL), distanceFromStart(MAX_DIST) {
		//nodes.push_back(this);
	}
	pair<int, int> getPortTo(Node* node);

	uint64_t id;
	int ports;
	Node* previous;
	int distanceFromStart;
	vector<pair<Node*, LinkAtr*> > adjacentNodes; /*Node, Distance*/
};

class PathFinder {

public:
	PathFinder() {
	}
	Node* addNode(uint64_t id,int ports);
	void removeNode(uint64_t id);
	Node* getNode(uint64_t id);
	void addEdge(uint64_t node1, uint64_t node2, LinkAtr* atr1, LinkAtr* atr2);
	void removeEdge(uint64_t node1, uint64_t node2);
	int compute(uint64_t source);
	void clean();
	void PrintShortestRouteTo(uint64_t destination);
	vector<Node*> getPath(uint64_t destination);
	vector<Node*> getNodes();

private:
	vector<Node*>* AdjacentRemainingNodes(Node* node);
	Node* ExtractSmallest();
	int Distance(Node* node1, Node* node2);
	bool Contains(uint64_t node);

	map<uint64_t, Node*> nodes;
	map<uint64_t, Node*> nodesTmp;

};

#endif /* PATHFINDER_H_ */
