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

#define MAX_INT 100000

#include "PathFinder.hh"
pair<int, int> Node::getPortTo(Node* node) {
	//	printf("Dest %ld\n", node->id);
	for (int i = 0; i < adjacentNodes.size(); i++) {
		//		printf("ID: %ld p: %d\n",adjacentNodes.at(i).first->id, adjacentNodes.at(i).second->port);
		if (adjacentNodes.at(i).first == node)
			return adjacentNodes.at(i).second->ports;
	}
	return pair<int, int> (-1, -1);
}
Node* Node::getNodeFromPort(int port) {
	//	printf("Dest %ld\n", node->id);
	for (int i = 0; i < adjacentNodes.size(); i++) {
		//		printf("ID: %ld p: %d\n",adjacentNodes.at(i).first->id, adjacentNodes.at(i).second->port);
		if (adjacentNodes.at(i).second->ports.first == port)
			return adjacentNodes.at(i).first;
	}
	return NULL;
}
Node* PathFinder::addNode(uint64_t id, int ports) {
	pair<map<uint64_t, Node*>::iterator, bool> ret;
	Node* node = new Node(id, ports);

	ret = nodes.insert(pair<uint64_t, Node*> (id, node));
	return ret.first->second;
}
vector<Node*> PathFinder::getNodes() {
	vector<Node*> tmp;
	map<uint64_t, Node*>::iterator it;

	for (it = nodes.begin(); it != nodes.end(); it++) {
		tmp.push_back(it->second);
	}
	return tmp;
}

void PathFinder::removeNode(uint64_t id) {
	nodes.erase(id);
}
Node* PathFinder::getNode(uint64_t id){
	map<uint64_t, Node*>::iterator epr;
	if (nodes.size() == 0) {
		return NULL;
	}
	epr = nodes.find(id);
	return (nodes.end() == epr) ? NULL : epr->second;

}

void PathFinder::addEdge(uint64_t node1, uint64_t node2, LinkAtr* atr1,
		LinkAtr* atr2) {
	Node* n1;
	Node* n2;
	map<uint64_t, Node*>::iterator epr;

	if((n1 = getNode(node1)) == NULL)
		return;

	if((n2 = getNode(node2)) == NULL)
		return;

	n1->adjacentNodes.push_back(pair<Node*, LinkAtr*> (n2, atr1));
	n2->adjacentNodes.push_back(pair<Node*, LinkAtr*> (n1, atr2));
}

void PathFinder::removeEdge(uint64_t node1, uint64_t node2) {
	Node* n1;
	Node* n2;
	map<uint64_t, Node*>::iterator epr;
	vector<pair<Node*, LinkAtr*> > tmp;
	vector<pair<Node*, LinkAtr*> > tmp1;
	pair<Node*, LinkAtr*> tmppair;

	epr = nodes.find(node1);
	if((n1 = getNode(node1)) == NULL)
			return;

	if((n2 = getNode(node2)) == NULL)
			return;

	while(!n1->adjacentNodes.empty()){
		tmppair = n1->adjacentNodes.back();
		n1->adjacentNodes.pop_back();
		if(tmppair.first != n2)
			tmp.push_back(tmppair);
	}
	n1->adjacentNodes = tmp;

	while(!n2->adjacentNodes.empty()){
		tmppair = n2->adjacentNodes.back();
		n2->adjacentNodes.pop_back();
		if(tmppair.first != n1)
			tmp1.push_back(tmppair);
	}
	n2->adjacentNodes = tmp1;
}

void PathFinder::removeEdge(Node* n1, Node* n2) {
	map<uint64_t, Node*>::iterator epr;
	vector<pair<Node*, LinkAtr*> > tmp;
	vector<pair<Node*, LinkAtr*> > tmp1;
	pair<Node*, LinkAtr*> tmppair;

	while(!n1->adjacentNodes.empty()){
		tmppair = n1->adjacentNodes.back();
		n1->adjacentNodes.pop_back();
		if(tmppair.first != n2)
			tmp.push_back(tmppair);
	}
	n1->adjacentNodes = tmp;

	while(!n2->adjacentNodes.empty()){
		tmppair = n2->adjacentNodes.back();
		n2->adjacentNodes.pop_back();
		if(tmppair.first != n1)
			tmp1.push_back(tmppair);
	}
	n2->adjacentNodes = tmp1;
}

int PathFinder::compute(uint64_t source) {
	clean();
	nodesTmp = nodes;
	if (nodes.size() == 0) {
		//		printf("There are not nodes in the database\n");
		return -1;
	}

	map<uint64_t, Node*>::iterator sNode = nodesTmp.find(source);
	if (sNode->second->id != source) {
		//		printf("Source %ldnot found\n",source);
		return -2;
	}
	sNode->second->distanceFromStart = 0; // set start node

	while (nodesTmp.size() > 0) {
		//	printf("Nodes size: %d\n", (int) nodesTmp.size());
		Node* smallest = ExtractSmallest();
		vector<Node*>* adjacentNodes = AdjacentRemainingNodes(smallest);

		const int size = adjacentNodes->size();
		//		printf("Adjacent nodes size: %d\n", (int) size);
		for (int i = 0; i < size; ++i) {
			Node* adjacent = adjacentNodes->at(i);
			int distance = Distance(smallest, adjacent)
					+ smallest->distanceFromStart;
			//			printf("New Distance %d\n",distance);
			if (distance < adjacent->distanceFromStart) {
				adjacent->distanceFromStart = distance;
				adjacent->previous = smallest;
			}
		}
		delete adjacentNodes;
	}
	return 0;
}

void PathFinder::clean() {
	map<uint64_t, Node*>::iterator it;
	if (nodes.empty())
		return;
	for (it = nodes.begin(); it != nodes.end(); it++) {
		it->second->distanceFromStart = MAX_DIST;
		it->second->previous = NULL;
	}
}

// Find the node with the smallest distance,
// remove it, and return it.
Node* PathFinder::ExtractSmallest() {
	map<uint64_t, Node*>::iterator it;
	if (nodesTmp.size() == 0)
		return NULL;

	it = nodesTmp.begin();
	Node* smallest = it->second;
	for (it = nodesTmp.begin(); it != nodesTmp.end(); it++) {
		//	printf("Looking for smallest loop\n");
		Node* current = it->second;
		//				printf("current id: %lu d: %d, small id: %ld d: %d\n", current->id,
		//						current->distanceFromStart, smallest->id,
		//						smallest->distanceFromStart);
		if (current->distanceFromStart < smallest->distanceFromStart) {
			smallest = current;

		}
	}
	//	printf("To remove: %ld\n", smallest->id);
	nodesTmp.erase(smallest->id);

	return smallest;
}

// Return all nodes adjacent to 'node' which are still
// in the 'nodes' collection.
vector<Node*>* PathFinder::AdjacentRemainingNodes(Node* node) {
	vector<Node*>* adjacentNodes = new vector<Node*> ();
	const int size = node->adjacentNodes.size();
	//	printf("Adjacent nodes: %d\n",size);
	for (int i = 0; i < size; ++i) {
		Node* adjacent = node->adjacentNodes.at(i).first;
		//		printf("Adjacent id: %d\n",adjacent->id);
		if (adjacent && Contains(adjacent->id)) {
			adjacentNodes->push_back(adjacent);
		}
	}
	return adjacentNodes;
}

// Return distance between two connected nodes
int PathFinder::Distance(Node* node1, Node* node2) {

	const int size = node1->adjacentNodes.size();
	for (int i = 0; i < size; ++i) {
		Node* tmp = node1->adjacentNodes.at(i).first;
		if (tmp == node2) {
			return node1->adjacentNodes.at(i).second->distance;
		}
	}
	return -1; // should never happen
}

// Does the 'nodes' vector contain 'node'
bool PathFinder::Contains(uint64_t node) {
	if (nodesTmp.count(node))
		return true;
	else
		return false;
}

void PathFinder::PrintShortestRouteTo(uint64_t destination) {
	Node* previous = nodes.find(destination)->second;
	printf("Destination: %ld. Distance from start: %d. ", previous->id,
			previous->distanceFromStart);
	while (previous) {
		printf("%ld ", previous->id);
		previous = previous->previous;
	}
	printf("\n");
}

vector<Node*> PathFinder::getPath(uint64_t destination) {
	vector<Node*> path;
	Node* previous = nodes.find(destination)->second;
	while (previous) {
		path.push_back(previous);
		previous = previous->previous;
	}
	return path;

}
int main(int argc, char* argv[]) {
	PathFinder finder;

	finder.addNode(1, 4);
	finder.addNode(2, 4);
	finder.addNode(3, 4);
	finder.addNode(4, 4);

	LinkAtr* atr = new LinkAtr(1, 1, 1);
	finder.addEdge(1, 2, atr, atr);
	finder.addEdge(2, 3, atr, atr);
	finder.addEdge(3, 4, atr, atr);
	finder.addEdge(4, 1, atr, atr);


	printf("Computing\n");
	finder.compute(1);
	printf("Printing routes:\n");
	finder.PrintShortestRouteTo(2);
	finder.PrintShortestRouteTo(3);
	finder.PrintShortestRouteTo(4);
	finder.getPath(3);

	finder.clean();

	printf("Computing\n");
	finder.compute(2);
	printf("Printing routes:\n");
	finder.PrintShortestRouteTo(2);
	finder.PrintShortestRouteTo(3);
	finder.PrintShortestRouteTo(4);

	return 0;
}

