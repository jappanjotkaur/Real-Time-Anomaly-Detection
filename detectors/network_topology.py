"""
Network Topology Builder
Builds and analyzes network topology from packet data
"""

import time
from collections import defaultdict
from typing import Dict, List, Set, Tuple
import networkx as nx
from datetime import datetime


class NetworkTopologyBuilder:
    """Builds network topology graph and analyzes network structure"""
    
    def __init__(self):
        # Network graph
        try:
            self.graph = nx.Graph()
        except:
            self.graph = None
            print("[!] NetworkX not available. Topology visualization disabled.")
        
        # Node metadata
        self.node_metadata = defaultdict(lambda: {
            'ip': '',
            'packet_count': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'protocols': set(),
            'ports': set(),
            'first_seen': time.time(),
            'last_seen': time.time(),
            'is_internal': False,
            'threat_score': 0.0,
            'device_type': 'unknown'
        })
        
        # Edge metadata (connections)
        self.edge_metadata = defaultdict(lambda: {
            'packet_count': 0,
            'bytes_transferred': 0,
            'protocols': set(),
            'ports': set(),
            'first_seen': time.time(),
            'last_seen': time.time(),
            'is_anomalous': False
        })
        
    def add_connection(self, src_ip: str, dst_ip: str, packet_info: Dict, timestamp: float):
        """Add a connection to the topology"""
        if self.graph is None:
            return
        
        protocol = packet_info.get('protocol', 'Unknown')
        src_port = packet_info.get('src_port', 'N/A')
        dst_port = packet_info.get('dst_port', 'N/A')
        size = packet_info.get('size', 0)
        
        # Skip if IPs are unknown
        if src_ip == 'Unknown' or dst_ip == 'Unknown':
            return
        
        # Add nodes
        self.graph.add_node(src_ip)
        self.graph.add_node(dst_ip)
        
        # Update node metadata
        self._update_node_metadata(src_ip, packet_info, size, timestamp, is_source=True)
        self._update_node_metadata(dst_ip, packet_info, size, timestamp, is_source=False)
        
        # Add edge
        edge_key = (src_ip, dst_ip)
        self.graph.add_edge(src_ip, dst_ip)
        
        # Update edge metadata
        edge_meta = self.edge_metadata[edge_key]
        edge_meta['packet_count'] += 1
        edge_meta['bytes_transferred'] += size
        edge_meta['protocols'].add(protocol)
        if src_port != 'N/A':
            edge_meta['ports'].add(src_port)
        if dst_port != 'N/A':
            edge_meta['ports'].add(dst_port)
        edge_meta['last_seen'] = timestamp
        if edge_meta['first_seen'] == time.time():  # New edge
            edge_meta['first_seen'] = timestamp
    
    def _update_node_metadata(self, ip: str, packet_info: Dict, size: int, 
                             timestamp: float, is_source: bool):
        """Update metadata for a node"""
        meta = self.node_metadata[ip]
        meta['ip'] = ip
        
        if is_source:
            meta['bytes_sent'] += size
        else:
            meta['bytes_received'] += size
        
        meta['packet_count'] += 1
        meta['protocols'].add(packet_info.get('protocol', 'Unknown'))
        
        port = packet_info.get('src_port' if is_source else 'dst_port', 'N/A')
        if port != 'N/A':
            meta['ports'].add(port)
        
        meta['last_seen'] = timestamp
        if meta['first_seen'] == time.time():
            meta['first_seen'] = timestamp
        
        meta['is_internal'] = self._is_internal_ip(ip)
    
    def get_topology_summary(self) -> Dict:
        """Get summary of network topology"""
        if self.graph is None:
            return {'error': 'NetworkX not available'}
        
        # Calculate metrics
        num_nodes = self.graph.number_of_nodes()
        num_edges = self.graph.number_of_edges()
        
        # Find central nodes (high degree)
        degrees = dict(self.graph.degree())
        top_nodes = sorted(degrees.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Find communities (if possible)
        communities = []
        try:
            communities_generator = nx.community.greedy_modularity_communities(self.graph)
            communities = [list(c) for c in communities_generator]
        except:
            pass
        
        # Find isolated nodes
        isolated_nodes = list(nx.isolates(self.graph))
        
        # Find bridges (critical connections)
        bridges = []
        try:
            bridges = list(nx.bridges(self.graph))
        except:
            pass
        
        return {
            'num_nodes': num_nodes,
            'num_edges': num_edges,
            'top_connected_nodes': [{'ip': ip, 'degree': deg} for ip, deg in top_nodes],
            'communities': len(communities),
            'community_details': communities[:5],  # First 5 communities
            'isolated_nodes': len(isolated_nodes),
            'bridges': len(bridges),
            'density': nx.density(self.graph) if num_nodes > 1 else 0
        }
    
    def get_node_analysis(self, ip: str) -> Dict:
        """Get detailed analysis for a node"""
        if self.graph is None or ip not in self.graph:
            return None
        
        meta = self.node_metadata[ip]
        neighbors = list(self.graph.neighbors(ip))
        
        # Calculate centrality metrics
        try:
            degree_centrality = nx.degree_centrality(self.graph).get(ip, 0)
            betweenness_centrality = nx.betweenness_centrality(self.graph).get(ip, 0)
            closeness_centrality = nx.closeness_centrality(self.graph).get(ip, 0)
        except:
            degree_centrality = betweenness_centrality = closeness_centrality = 0
        
        return {
            'ip': ip,
            'metadata': {
                'packet_count': meta['packet_count'],
                'bytes_sent': meta['bytes_sent'],
                'bytes_received': meta['bytes_received'],
                'protocols': list(meta['protocols']),
                'ports': list(meta['ports'])[:20],  # First 20 ports
                'is_internal': meta['is_internal'],
                'device_type': meta['device_type']
            },
            'network_metrics': {
                'degree': len(neighbors),
                'degree_centrality': degree_centrality,
                'betweenness_centrality': betweenness_centrality,
                'closeness_centrality': closeness_centrality
            },
            'neighbors': neighbors[:20],  # First 20 neighbors
            'first_seen': datetime.fromtimestamp(meta['first_seen']).isoformat(),
            'last_seen': datetime.fromtimestamp(meta['last_seen']).isoformat()
        }
    
    def get_anomalous_nodes(self, threshold: float = 5.0) -> List[Dict]:
        """Get nodes with high threat scores"""
        anomalous = []
        
        for ip, meta in self.node_metadata.items():
            if meta['threat_score'] >= threshold:
                node_analysis = self.get_node_analysis(ip)
                if node_analysis:
                    node_analysis['threat_score'] = meta['threat_score']
                    anomalous.append(node_analysis)
        
        return sorted(anomalous, key=lambda x: x.get('threat_score', 0), reverse=True)
    
    def update_node_threat_score(self, ip: str, threat_score: float):
        """Update threat score for a node"""
        if ip in self.node_metadata:
            self.node_metadata[ip]['threat_score'] = max(
                self.node_metadata[ip]['threat_score'],
                threat_score
            )
    
    def get_graph_data(self) -> Dict:
        """Get graph data for visualization"""
        if self.graph is None:
            return {'error': 'NetworkX not available'}
        
        # Convert to format suitable for visualization (e.g., D3.js)
        nodes = []
        for ip, meta in self.node_metadata.items():
            if ip in self.graph:
                nodes.append({
                    'id': ip,
                    'label': ip,
                    'size': meta['packet_count'],
                    'threat_score': meta['threat_score'],
                    'is_internal': meta['is_internal'],
                    'packet_count': meta['packet_count']
                })
        
        edges = []
        for (src, dst), meta in self.edge_metadata.items():
            if self.graph.has_edge(src, dst):
                edges.append({
                    'source': src,
                    'target': dst,
                    'weight': meta['packet_count'],
                    'bytes': meta['bytes_transferred'],
                    'protocols': list(meta['protocols']),
                    'is_anomalous': meta['is_anomalous']
                })
        
        return {
            'nodes': nodes,
            'edges': edges,
            'summary': self.get_topology_summary()
        }
    
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is internal/private"""
        if ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('127.'):
            return True
        if ip.startswith('172.'):
            parts = ip.split('.')
            if len(parts) > 1:
                try:
                    second_octet = int(parts[1])
                    if 16 <= second_octet <= 31:
                        return True
                except:
                    pass
        return False

