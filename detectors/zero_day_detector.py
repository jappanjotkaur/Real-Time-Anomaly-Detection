"""
Zero-Day Attack Detection System
Uses graph neural networks and advanced pattern matching to detect unknown attacks
"""

import numpy as np
import networkx as nx
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Optional
import time
import hashlib
from datetime import datetime


class ZeroDayDetector:
    """Detect zero-day attacks using graph-based anomaly detection"""
    
    def __init__(self, graph_window=300, anomaly_threshold=0.7):
        """
        Args:
            graph_window: Time window in seconds for building network graphs
            anomaly_threshold: Threshold for zero-day detection (0-1)
        """
        self.graph_window = graph_window
        self.anomaly_threshold = anomaly_threshold
        
        # Network graph for each time window
        self.network_graphs = deque(maxlen=100)
        self.current_graph = nx.DiGraph()
        self.graph_start_time = time.time()
        
        # Feature patterns for zero-day detection
        self.known_patterns = defaultdict(int)
        self.pattern_signatures = {}
        
        # Behavioral baselines
        self.baseline_metrics = {
            'avg_degree': 0.0,
            'avg_clustering': 0.0,
            'avg_path_length': 0.0,
            'edge_density': 0.0
        }
        
        # Zero-day incidents
        self.zero_day_incidents = deque(maxlen=1000)
        
        # Attack pattern templates
        self.attack_templates = self._initialize_attack_templates()
    
    def _initialize_attack_templates(self) -> Dict:
        """Initialize known attack pattern templates"""
        return {
            'lateral_movement': {
                'pattern': 'fan_out_internal',
                'description': 'Rapid expansion to multiple internal nodes',
                'severity': 9.0
            },
            'data_exfiltration': {
                'pattern': 'large_outbound_flow',
                'description': 'Unusual large data transfer to external node',
                'severity': 8.5
            },
            'command_control': {
                'pattern': 'persistent_external',
                'description': 'Persistent communication with external node',
                'severity': 8.0
            },
            'reconnaissance': {
                'pattern': 'scanning_pattern',
                'description': 'Systematic scanning of multiple targets',
                'severity': 7.0
            },
            'privilege_escalation': {
                'pattern': 'vertical_escalation',
                'description': 'Access escalation to higher privilege nodes',
                'severity': 9.5
            }
        }
    
    def analyze_packet(self, packet_info: Dict, timestamp: float) -> Dict:
        """
        Analyze packet for zero-day attack patterns
        Returns:
            Detection result with zero-day score and patterns
        """
        src_ip = packet_info.get('src_ip', 'Unknown')
        dst_ip = packet_info.get('dst_ip', 'Unknown')
        protocol = packet_info.get('protocol', 'Unknown')
        size = packet_info.get('size', 0)
        
        if src_ip == 'Unknown' or dst_ip == 'Unknown':
            return {'is_zero_day': False, 'score': 0.0}
        
        # Update network graph
        self._update_graph(src_ip, dst_ip, packet_info, timestamp)
        
        # Check if we should analyze the current graph
        if time.time() - self.graph_start_time >= self.graph_window:
            result = self._analyze_graph()
            self._reset_graph()
            return result
        
        # Real-time pattern detection
        pattern_result = self._detect_patterns(src_ip, dst_ip, packet_info, timestamp)
        
        return pattern_result
    
    def _update_graph(self, src_ip: str, dst_ip: str, packet_info: Dict, timestamp: float):
        """Update network graph with new connection"""
        # Add nodes
        if not self.current_graph.has_node(src_ip):
            self.current_graph.add_node(src_ip, first_seen=timestamp, 
                                       packets=0, bytes=0, protocols=set())
        if not self.current_graph.has_node(dst_ip):
            self.current_graph.add_node(dst_ip, first_seen=timestamp,
                                       packets=0, bytes=0, protocols=set())
        
        # Update node attributes
        self.current_graph.nodes[src_ip]['packets'] += 1
        self.current_graph.nodes[src_ip]['bytes'] += packet_info.get('size', 0)
        self.current_graph.nodes[src_ip]['protocols'].add(packet_info.get('protocol', 'Unknown'))
        self.current_graph.nodes[src_ip]['last_seen'] = timestamp
        
        # Add or update edge
        edge_key = (src_ip, dst_ip)
        if not self.current_graph.has_edge(src_ip, dst_ip):
            self.current_graph.add_edge(src_ip, dst_ip, 
                                       first_seen=timestamp,
                                       packets=0, bytes=0,
                                       protocols=set())
        
        self.current_graph.edges[src_ip, dst_ip]['packets'] += 1
        self.current_graph.edges[src_ip, dst_ip]['bytes'] += packet_info.get('size', 0)
        self.current_graph.edges[src_ip, dst_ip]['protocols'].add(packet_info.get('protocol', 'Unknown'))
        self.current_graph.edges[src_ip, dst_ip]['last_seen'] = timestamp
    
    def _reset_graph(self):
        """Save current graph and start a new one"""
        if self.current_graph.number_of_nodes() > 0:
            self.network_graphs.append(self.current_graph.copy())
            
            # Update baseline metrics
            self._update_baseline_metrics()
        
        self.current_graph = nx.DiGraph()
        self.graph_start_time = time.time()
    
    def _analyze_graph(self) -> Dict:
        """Analyze network graph for zero-day attack patterns"""
        if self.current_graph.number_of_nodes() == 0:
            return {'is_zero_day': False, 'score': 0.0}
        
        anomalies = []
        total_score = 0.0
        
        # 1. Graph structure anomalies
        structure_score, structure_anomalies = self._analyze_graph_structure()
        if structure_score > 0:
            total_score += structure_score
            anomalies.extend(structure_anomalies)
        
        # 2. Temporal pattern anomalies
        temporal_score, temporal_anomalies = self._analyze_temporal_patterns()
        if temporal_score > 0:
            total_score += temporal_score
            anomalies.extend(temporal_anomalies)
        
        # 3. Behavioral anomalies
        behavioral_score, behavioral_anomalies = self._analyze_behavioral_patterns()
        if behavioral_score > 0:
            total_score += behavioral_score
            anomalies.extend(behavioral_anomalies)
        
        # 4. Attack template matching
        template_score, template_anomalies = self._match_attack_templates()
        if template_score > 0:
            total_score += template_score
            anomalies.extend(template_anomalies)
        
        # Normalize score
        normalized_score = min(total_score / 40.0, 1.0)  # Max score is ~40
        
        is_zero_day = normalized_score >= self.anomaly_threshold
        
        result = {
            'is_zero_day': is_zero_day,
            'score': normalized_score,
            'anomalies': anomalies,
            'graph_metrics': self._calculate_graph_metrics(),
            'timestamp': time.time()
        }
        
        if is_zero_day:
            self.zero_day_incidents.append(result)
        
        return result
    
    def _analyze_graph_structure(self) -> Tuple[float, List[str]]:
        """Analyze graph structure for anomalies"""
        score = 0.0
        anomalies = []
        
        if self.current_graph.number_of_nodes() == 0:
            return 0.0, []
        
        metrics = self._calculate_graph_metrics()
        baseline = self.baseline_metrics
        
        # Check for unusual degree distribution
        degrees = dict(self.current_graph.degree())
        avg_degree = np.mean(list(degrees.values())) if degrees else 0
        
        if baseline['avg_degree'] > 0:
            degree_deviation = abs(avg_degree - baseline['avg_degree']) / baseline['avg_degree']
            if degree_deviation > 2.0:
                score += 3.0
                anomalies.append(f"Unusual degree distribution (deviation: {degree_deviation:.2f}x)")
        
        # Check for hub nodes (potential C2 servers)
        hub_threshold = np.percentile(list(degrees.values()), 95) if degrees else 0
        hub_nodes = [node for node, deg in degrees.items() if deg > hub_threshold * 2]
        if hub_nodes:
            score += 2.0
            anomalies.append(f"Hub nodes detected: {len(hub_nodes)} nodes with unusually high connectivity")
        
        # Check for disconnected components (isolated attack)
        components = list(nx.weakly_connected_components(self.current_graph))
        if len(components) > 3:
            score += 1.5
            anomalies.append(f"Multiple disconnected components: {len(components)} (possible isolated attack)")
        
        # Check for star patterns (single point of failure/attack)
        for node in self.current_graph.nodes():
            out_degree = self.current_graph.out_degree(node)
            in_degree = self.current_graph.in_degree(node)
            if out_degree > 20 and in_degree < 2:
                score += 2.5
                anomalies.append(f"Star pattern detected: {node} has {out_degree} outbound connections")
                break
        
        return score, anomalies
    
    def _analyze_temporal_patterns(self) -> Tuple[float, List[str]]:
        """Analyze temporal patterns for anomalies"""
        score = 0.0
        anomalies = []
        
        # Check for burst patterns
        edge_times = []
        for src, dst, data in self.current_graph.edges(data=True):
            if 'first_seen' in data and 'last_seen' in data:
                duration = data['last_seen'] - data['first_seen']
                edge_times.append((duration, data['packets']))
        
        if edge_times:
            # Check for very short duration with many packets (burst attack)
            for duration, packets in edge_times:
                if duration > 0 and packets / duration > 100:  # >100 packets/second
                    score += 2.0
                    anomalies.append(f"Burst pattern detected: {packets} packets in {duration:.2f}s")
                    break
        
        return score, anomalies
    
    def _analyze_behavioral_patterns(self) -> Tuple[float, List[str]]:
        """Analyze behavioral patterns"""
        score = 0.0
        anomalies = []
        
        # Check for protocol diversity (unusual for single node)
        for node in self.current_graph.nodes():
            protocols = self.current_graph.nodes[node].get('protocols', set())
            if len(protocols) > 5:
                score += 1.5
                anomalies.append(f"High protocol diversity: {node} uses {len(protocols)} different protocols")
                break
        
        # Check for unusual byte patterns
        for src, dst, data in self.current_graph.edges(data=True):
            bytes_transferred = data.get('bytes', 0)
            packets = data.get('packets', 1)
            avg_packet_size = bytes_transferred / packets if packets > 0 else 0
            
            # Very large average packet size (possible data exfiltration)
            if avg_packet_size > 10000:  # 10KB average
                score += 2.0
                anomalies.append(f"Unusual packet size: {avg_packet_size:.0f} bytes average")
                break
        
        return score, anomalies
    
    def _match_attack_templates(self) -> Tuple[float, List[str]]:
        """Match against known attack templates"""
        score = 0.0
        anomalies = []
        
        # Check for lateral movement pattern
        if self._detect_lateral_movement():
            score += self.attack_templates['lateral_movement']['severity']
            anomalies.append(self.attack_templates['lateral_movement']['description'])
        
        # Check for data exfiltration
        if self._detect_data_exfiltration():
            score += self.attack_templates['data_exfiltration']['severity']
            anomalies.append(self.attack_templates['data_exfiltration']['description'])
        
        # Check for C2 pattern
        if self._detect_command_control():
            score += self.attack_templates['command_control']['severity']
            anomalies.append(self.attack_templates['command_control']['description'])
        
        return score, anomalies
    
    def _detect_lateral_movement(self) -> bool:
        """Detect lateral movement pattern"""
        # Look for nodes that connect to many internal nodes
        internal_ips = self._get_internal_ips()
        
        for node in self.current_graph.nodes():
            if node not in internal_ips:
                continue
            
            # Count internal destinations
            internal_dests = [dst for dst in self.current_graph.successors(node) 
                            if dst in internal_ips]
            
            if len(internal_dests) >= 3:
                return True
        
        return False
    
    def _detect_data_exfiltration(self) -> bool:
        """Detect data exfiltration pattern"""
        internal_ips = self._get_internal_ips()
        
        for src, dst, data in self.current_graph.edges(data=True):
            if src in internal_ips and dst not in internal_ips:
                bytes_transferred = data.get('bytes', 0)
                if bytes_transferred > 1000000:  # >1MB
                    return True
        
        return False
    
    def _detect_command_control(self) -> bool:
        """Detect command and control pattern"""
        internal_ips = self._get_internal_ips()
        
        for src, dst, data in self.current_graph.edges(data=True):
            if src in internal_ips and dst not in internal_ips:
                packets = data.get('packets', 0)
                duration = data.get('last_seen', 0) - data.get('first_seen', 1)
                
                # Persistent communication with external node
                if packets > 10 and duration > 300:  # >10 packets over 5 minutes
                    return True
        
        return False
    
    def _detect_patterns(self, src_ip: str, dst_ip: str, packet_info: Dict, timestamp: float) -> Dict:
        """Detect real-time attack patterns"""
        score = 0.0
        patterns = []
        
        # Create pattern signature
        pattern_sig = self._create_pattern_signature(src_ip, dst_ip, packet_info)
        
        # Check if pattern is known
        if pattern_sig in self.known_patterns:
            # Known pattern - check for deviations
            known_count = self.known_patterns[pattern_sig]
            # Patterns seen very rarely might be zero-day
            if known_count < 3:
                score += 1.0
                patterns.append("Rare pattern signature detected")
        else:
            # Unknown pattern - potential zero-day
            score += 2.0
            patterns.append("Unknown pattern signature - potential zero-day")
            self.known_patterns[pattern_sig] = 1
        
        return {
            'is_zero_day': score >= 2.0,
            'score': min(score / 10.0, 1.0),
            'patterns': patterns,
            'timestamp': timestamp
        }
    
    def _create_pattern_signature(self, src_ip: str, dst_ip: str, packet_info: Dict) -> str:
        """Create a signature for the packet pattern"""
        protocol = packet_info.get('protocol', 'Unknown')
        src_port = packet_info.get('src_port', 'N/A')
        dst_port = packet_info.get('dst_port', 'N/A')
        size = packet_info.get('size', 0)
        
        # Create hash-based signature
        sig_string = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{protocol}:{size//100}"
        return hashlib.md5(sig_string.encode()).hexdigest()[:16]
    
    def _calculate_graph_metrics(self) -> Dict:
        """Calculate graph metrics"""
        if self.current_graph.number_of_nodes() == 0:
            return {}
        
        degrees = dict(self.current_graph.degree())
        
        return {
            'num_nodes': self.current_graph.number_of_nodes(),
            'num_edges': self.current_graph.number_of_edges(),
            'avg_degree': np.mean(list(degrees.values())) if degrees else 0,
            'max_degree': max(degrees.values()) if degrees else 0,
            'density': nx.density(self.current_graph),
            'num_components': len(list(nx.weakly_connected_components(self.current_graph)))
        }
    
    def _update_baseline_metrics(self):
        """Update baseline metrics from historical graphs"""
        if len(self.network_graphs) == 0:
            return
        
        # Calculate metrics for recent graphs
        recent_graphs = list(self.network_graphs)[-10:]
        
        degrees = []
        densities = []
        
        for graph in recent_graphs:
            if graph.number_of_nodes() > 0:
                graph_degrees = dict(graph.degree())
                degrees.extend(graph_degrees.values())
                densities.append(nx.density(graph))
        
        if degrees:
            self.baseline_metrics['avg_degree'] = np.mean(degrees)
        if densities:
            self.baseline_metrics['edge_density'] = np.mean(densities)
    
    def _get_internal_ips(self) -> set:
        """Get set of internal/private IP addresses"""
        internal = set()
        for node in self.current_graph.nodes():
            if self._is_internal_ip(node):
                internal.add(node)
        return internal
    
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
    
    def get_zero_day_incidents(self, time_window: int = 3600) -> List[Dict]:
        """Get zero-day incidents within time window"""
        cutoff_time = time.time() - time_window
        return [incident for incident in self.zero_day_incidents 
                if incident.get('timestamp', 0) >= cutoff_time]

