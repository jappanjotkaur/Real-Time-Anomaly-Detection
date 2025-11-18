"""
Advanced Attack Pattern Detection
Detects port scans, DDoS, brute force, and other attack patterns
"""

import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Set, Optional
import numpy as np


class AttackPatternDetector:
    """Detects various attack patterns in network traffic"""
    
    def __init__(self):
        # Port scan detection
        self.port_scan_threshold = 10  # Distinct ports in short time
        self.port_scan_window = 60  # seconds
        self.scan_candidates = defaultdict(lambda: {
            'ports': set(),
            'timestamps': deque(maxlen=1000),
            'destinations': set()
        })
        
        # DDoS detection
        self.ddos_threshold = 100  # Packets per second
        self.ddos_window = 10  # seconds
        self.ddos_candidates = defaultdict(lambda: {
            'packet_count': deque(maxlen=1000),
            'timestamps': deque(maxlen=1000),
            'targets': set()
        })
        
        # Brute force detection
        self.brute_force_threshold = 5  # Failed connections
        self.brute_force_window = 300  # 5 minutes
        self.brute_force_attempts = defaultdict(lambda: {
            'failed_connections': deque(maxlen=100),
            'targets': set(),
            'ports': set()
        })
        
        # Horizontal scan detection (multiple targets, same port)
        self.horizontal_scan_threshold = 5  # Distinct targets
        self.horizontal_scan_window = 60  # seconds
        self.horizontal_scans = defaultdict(lambda: {
            'targets': set(),
            'timestamps': deque(maxlen=100),
            'port': None
        })
        
        # Vertical scan detection (single target, multiple ports)
        self.vertical_scan_threshold = 10  # Distinct ports
        self.vertical_scan_window = 60  # seconds
        
        # SYN flood detection
        self.syn_flood_threshold = 50  # SYN packets without ACK
        self.syn_connections = defaultdict(lambda: {
            'syn_count': 0,
            'syn_ack_count': 0,
            'timestamps': deque(maxlen=1000)
        })
        
        # ICMP flood detection
        self.icmp_flood_threshold = 100  # ICMP packets per second
        self.icmp_candidates = defaultdict(lambda: {
            'packet_count': deque(maxlen=1000),
            'timestamps': deque(maxlen=1000)
        })
        
        # Detected attacks
        self.detected_attacks = deque(maxlen=1000)
        
    def analyze_packet(self, packet_info: Dict, timestamp: float) -> Tuple[List[Dict], float]:
        """
        Analyze packet for attack patterns
        Returns: (detected_attacks, overall_threat_score)
        """
        src_ip = packet_info.get('src_ip', 'Unknown')
        dst_ip = packet_info.get('dst_ip', 'Unknown')
        protocol = packet_info.get('protocol', 'Unknown')
        src_port = packet_info.get('src_port', 'N/A')
        dst_port = packet_info.get('dst_port', 'N/A')
        details = packet_info.get('details', '')
        
        detected_attacks = []
        threat_score = 0.0
        
        if src_ip == 'Unknown':
            return detected_attacks, threat_score
        
        # Check for port scan
        if protocol in ['TCP', 'UDP'] and dst_port != 'N/A':
            scan_result = self._detect_port_scan(src_ip, dst_ip, dst_port, timestamp)
            if scan_result:
                detected_attacks.append(scan_result)
                threat_score += scan_result.get('severity', 0)
        
        # Check for DDoS
        ddos_result = self._detect_ddos(src_ip, dst_ip, timestamp)
        if ddos_result:
            detected_attacks.append(ddos_result)
            threat_score += ddos_result.get('severity', 0)
        
        # Check for brute force
        if protocol == 'TCP' and 'RST' in details:
            brute_result = self._detect_brute_force(src_ip, dst_ip, dst_port, timestamp)
            if brute_result:
                detected_attacks.append(brute_result)
                threat_score += brute_result.get('severity', 0)
        
        # Check for horizontal scan
        if protocol in ['TCP', 'UDP'] and dst_port != 'N/A':
            h_scan_result = self._detect_horizontal_scan(src_ip, dst_port, dst_ip, timestamp)
            if h_scan_result:
                detected_attacks.append(h_scan_result)
                threat_score += h_scan_result.get('severity', 0)
        
        # Check for SYN flood
        if protocol == 'TCP' and 'SYN' in details and 'ACK' not in details:
            syn_flood_result = self._detect_syn_flood(src_ip, dst_ip, timestamp)
            if syn_flood_result:
                detected_attacks.append(syn_flood_result)
                threat_score += syn_flood_result.get('severity', 0)
        
        # Check for ICMP flood
        if protocol == 'ICMP':
            icmp_flood_result = self._detect_icmp_flood(src_ip, dst_ip, timestamp)
            if icmp_flood_result:
                detected_attacks.append(icmp_flood_result)
                threat_score += icmp_flood_result.get('severity', 0)
        
        # Store detected attacks
        for attack in detected_attacks:
            self.detected_attacks.append({
                **attack,
                'timestamp': timestamp,
                'detection_time': datetime.fromtimestamp(timestamp).isoformat()
            })
        
        return detected_attacks, min(threat_score, 10.0)
    
    def _detect_port_scan(self, src_ip: str, dst_ip: str, dst_port: int, timestamp: float) -> Optional[Dict]:
        """Detect port scanning activity"""
        key = f"{src_ip}:{dst_ip}"
        candidate = self.scan_candidates[key]
        
        # Clean old timestamps
        cutoff_time = timestamp - self.port_scan_window
        while candidate['timestamps'] and candidate['timestamps'][0] < cutoff_time:
            candidate['timestamps'].popleft()
        
        candidate['ports'].add(dst_port)
        candidate['destinations'].add(dst_ip)
        candidate['timestamps'].append(timestamp)
        
        # Check threshold
        if len(candidate['ports']) >= self.port_scan_threshold:
            return {
                'attack_type': 'port_scan',
                'severity': 7.0,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'ports_scanned': len(candidate['ports']),
                'message': f"Port scan detected: {src_ip} scanned {len(candidate['ports'])} ports on {dst_ip}",
                'ports': list(candidate['ports'])[:20]  # First 20 ports
            }
        return None
    
    def _detect_ddos(self, src_ip: str, dst_ip: str, timestamp: float) -> Optional[Dict]:
        """Detect DDoS attack"""
        key = f"{src_ip}:{dst_ip}"
        candidate = self.ddos_candidates[key]
        
        candidate['packet_count'].append(timestamp)
        candidate['timestamps'].append(timestamp)
        candidate['targets'].add(dst_ip)
        
        # Calculate packet rate in recent window
        cutoff_time = timestamp - self.ddos_window
        recent_packets = [ts for ts in candidate['packet_count'] if ts >= cutoff_time]
        
        if len(recent_packets) >= self.ddos_threshold:
            packet_rate = len(recent_packets) / self.ddos_window
            return {
                'attack_type': 'ddos',
                'severity': 9.0,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'packet_rate': packet_rate,
                'message': f"DDoS attack detected: {src_ip} sending {packet_rate:.1f} packets/sec to {dst_ip}",
                'packets_in_window': len(recent_packets)
            }
        return None
    
    def _detect_brute_force(self, src_ip: str, dst_ip: str, dst_port: int, timestamp: float) -> Optional[Dict]:
        """Detect brute force attack (multiple failed connections)"""
        key = f"{src_ip}:{dst_ip}:{dst_port}"
        attempts = self.brute_force_attempts[key]
        
        attempts['failed_connections'].append(timestamp)
        attempts['targets'].add(dst_ip)
        attempts['ports'].add(dst_port)
        
        # Clean old attempts
        cutoff_time = timestamp - self.brute_force_window
        recent_failures = [ts for ts in attempts['failed_connections'] if ts >= cutoff_time]
        
        if len(recent_failures) >= self.brute_force_threshold:
            return {
                'attack_type': 'brute_force',
                'severity': 8.0,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'failed_attempts': len(recent_failures),
                'message': f"Brute force attack detected: {src_ip} attempted {len(recent_failures)} failed connections to {dst_ip}:{dst_port}",
                'time_window': self.brute_force_window
            }
        return None
    
    def _detect_horizontal_scan(self, src_ip: str, dst_port: int, dst_ip: str, timestamp: float) -> Optional[Dict]:
        """Detect horizontal scan (same port, multiple targets)"""
        key = f"{src_ip}:{dst_port}"
        scan = self.horizontal_scans[key]
        
        if scan['port'] is None:
            scan['port'] = dst_port
        
        scan['targets'].add(dst_ip)
        scan['timestamps'].append(timestamp)
        
        # Clean old timestamps
        cutoff_time = timestamp - self.horizontal_scan_window
        recent_targets = {tgt for i, tgt in enumerate(scan['targets']) 
                         if i < len(scan['timestamps']) and scan['timestamps'][i] >= cutoff_time}
        
        if len(recent_targets) >= self.horizontal_scan_threshold:
            return {
                'attack_type': 'horizontal_scan',
                'severity': 6.0,
                'src_ip': src_ip,
                'port': dst_port,
                'targets_scanned': len(recent_targets),
                'message': f"Horizontal scan detected: {src_ip} scanned port {dst_port} on {len(recent_targets)} targets",
                'targets': list(recent_targets)[:10]  # First 10 targets
            }
        return None
    
    def _detect_syn_flood(self, src_ip: str, dst_ip: str, timestamp: float) -> Optional[Dict]:
        """Detect SYN flood attack"""
        key = f"{src_ip}:{dst_ip}"
        conn = self.syn_connections[key]
        
        conn['syn_count'] += 1
        conn['timestamps'].append(timestamp)
        
        # Clean old timestamps
        cutoff_time = timestamp - 10  # 10 second window
        recent_syns = [ts for ts in conn['timestamps'] if ts >= cutoff_time]
        
        if len(recent_syns) >= self.syn_flood_threshold:
            syn_rate = len(recent_syns) / 10
            return {
                'attack_type': 'syn_flood',
                'severity': 8.5,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'syn_rate': syn_rate,
                'message': f"SYN flood detected: {src_ip} sending {syn_rate:.1f} SYN packets/sec to {dst_ip}",
                'syn_count': len(recent_syns)
            }
        return None
    
    def _detect_icmp_flood(self, src_ip: str, dst_ip: str, timestamp: float) -> Optional[Dict]:
        """Detect ICMP flood (ping flood)"""
        key = f"{src_ip}:{dst_ip}"
        candidate = self.icmp_candidates[key]
        
        candidate['packet_count'].append(timestamp)
        candidate['timestamps'].append(timestamp)
        
        # Calculate packet rate
        cutoff_time = timestamp - 10  # 10 second window
        recent_packets = [ts for ts in candidate['packet_count'] if ts >= cutoff_time]
        
        if len(recent_packets) >= self.icmp_flood_threshold:
            packet_rate = len(recent_packets) / 10
            return {
                'attack_type': 'icmp_flood',
                'severity': 7.5,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'packet_rate': packet_rate,
                'message': f"ICMP flood detected: {src_ip} sending {packet_rate:.1f} ICMP packets/sec to {dst_ip}",
                'packets_in_window': len(recent_packets)
            }
        return None
    
    def get_attack_summary(self) -> Dict:
        """Get summary of detected attacks"""
        attack_counts = defaultdict(int)
        recent_attacks = []
        
        # Get attacks from last hour
        cutoff_time = time.time() - 3600
        for attack in self.detected_attacks:
            if attack.get('timestamp', 0) >= cutoff_time:
                attack_counts[attack['attack_type']] += 1
                recent_attacks.append(attack)
        
        return {
            'total_attacks': len(recent_attacks),
            'attack_types': dict(attack_counts),
            'recent_attacks': recent_attacks[-20:]  # Last 20 attacks
        }

