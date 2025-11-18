"""
Behavioral Profiling System
Tracks and learns normal behavior patterns for devices, IPs, and flows
"""

import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
import numpy as np
from typing import Dict, List, Tuple, Optional


class BehavioralProfiler:
    """Tracks behavioral patterns and detects deviations"""
    
    def __init__(self, learning_period=300, update_interval=60):
        """
        Args:
            learning_period: Time in seconds to learn baseline behavior (default: 5 minutes)
            update_interval: How often to update behavioral profiles (seconds)
        """
        self.learning_period = learning_period
        self.update_interval = update_interval
        self.start_time = time.time()
        
        # Device/IP behavioral profiles
        self.device_profiles = defaultdict(lambda: {
            'packet_rate': deque(maxlen=1000),
            'avg_packet_size': deque(maxlen=1000),
            'protocol_distribution': defaultdict(int),
            'port_usage': defaultdict(int),
            'destinations': defaultdict(int),
            'active_hours': set(),
            'first_seen': time.time(),
            'last_seen': time.time(),
            'total_packets': 0,
            'total_bytes': 0,
            'connection_patterns': deque(maxlen=500)
        })
        
        # Flow behavioral patterns
        self.flow_patterns = defaultdict(lambda: {
            'packet_count_history': deque(maxlen=100),
            'byte_count_history': deque(maxlen=100),
            'duration_history': deque(maxlen=100),
            'frequency': 0,
            'first_seen': time.time(),
            'last_seen': time.time()
        })
        
        # Temporal patterns (time-based behavior)
        self.temporal_patterns = defaultdict(lambda: defaultdict(int))
        
    def update_device_profile(self, packet_info: Dict, timestamp: float):
        """Update behavioral profile for a device/IP"""
        src_ip = packet_info.get('src_ip', 'Unknown')
        dst_ip = packet_info.get('dst_ip', 'Unknown')
        protocol = packet_info.get('protocol', 'Unknown')
        src_port = packet_info.get('src_port', 'N/A')
        dst_port = packet_info.get('dst_port', 'N/A')
        size = packet_info.get('size', 0)
        
        # Update source IP profile
        if src_ip != 'Unknown':
            profile = self.device_profiles[src_ip]
            profile['packet_rate'].append(timestamp)
            profile['avg_packet_size'].append(size)
            profile['protocol_distribution'][protocol] += 1
            if src_port != 'N/A' and isinstance(src_port, (int, str)):
                try:
                    profile['port_usage'][int(src_port)] += 1
                except:
                    pass
            profile['destinations'][dst_ip] += 1
            profile['active_hours'].add(datetime.fromtimestamp(timestamp).hour)
            profile['last_seen'] = timestamp
            profile['total_packets'] += 1
            profile['total_bytes'] += size
            
            # Track connection pattern
            if protocol in ['TCP', 'UDP']:
                pattern = f"{dst_ip}:{dst_port}"
                profile['connection_patterns'].append(pattern)
        
        # Update destination IP profile (if it's an internal IP)
        if dst_ip != 'Unknown' and self._is_internal_ip(dst_ip):
            profile = self.device_profiles[dst_ip]
            profile['packet_rate'].append(timestamp)
            profile['avg_packet_size'].append(size)
            profile['last_seen'] = timestamp
            profile['total_packets'] += 1
            profile['total_bytes'] += size
        
        # Update temporal patterns
        hour = datetime.fromtimestamp(timestamp).hour
        day_of_week = datetime.fromtimestamp(timestamp).weekday()
        self.temporal_patterns[src_ip][(day_of_week, hour)] += 1
        
    def get_behavioral_anomaly_score(self, packet_info: Dict, timestamp: float) -> Tuple[float, List[str]]:
        """
        Calculate behavioral anomaly score (0-10) and return reasons
        Returns: (score, reasons)
        """
        src_ip = packet_info.get('src_ip', 'Unknown')
        dst_ip = packet_info.get('dst_ip', 'Unknown')
        protocol = packet_info.get('protocol', 'Unknown')
        src_port = packet_info.get('src_port', 'N/A')
        dst_port = packet_info.get('dst_port', 'N/A')
        size = packet_info.get('size', 0)
        
        if src_ip == 'Unknown':
            return 0.0, []
        
        score = 0.0
        reasons = []
        
        # Check if device has baseline yet
        profile = self.device_profiles[src_ip]
        elapsed_time = timestamp - self.start_time
        
        if elapsed_time < self.learning_period:
            # Still learning baseline
            return 0.0, ["Learning baseline behavior"]
        
        # Check packet rate anomaly
        if len(profile['packet_rate']) > 10:
            recent_rates = self._calculate_recent_rate(profile['packet_rate'], timestamp, window=60)
            historical_avg = self._calculate_historical_avg_rate(profile['packet_rate'], timestamp)
            
            if historical_avg > 0:
                rate_deviation = abs(recent_rates - historical_avg) / historical_avg
                if rate_deviation > 2.0:  # 200% deviation
                    score += 2.5
                    reasons.append(f"Unusual packet rate ({rate_deviation:.1f}x normal)")
                elif rate_deviation > 1.5:  # 150% deviation
                    score += 1.0
                    reasons.append(f"Elevated packet rate ({rate_deviation:.1f}x normal)")
        
        # Check packet size anomaly
        if len(profile['avg_packet_size']) > 10:
            avg_size = np.mean(list(profile['avg_packet_size']))
            std_size = np.std(list(profile['avg_packet_size']))
            
            if std_size > 0:
                size_zscore = abs(size - avg_size) / std_size
                if size_zscore > 3.0:
                    score += 1.5
                    reasons.append(f"Unusual packet size (z-score: {size_zscore:.2f})")
        
        # Check protocol anomaly
        total_protocol_packets = sum(profile['protocol_distribution'].values())
        if total_protocol_packets > 0:
            protocol_ratio = profile['protocol_distribution'].get(protocol, 0) / total_protocol_packets
            if protocol_ratio < 0.01 and total_protocol_packets > 100:
                # Rarely seen protocol
                score += 2.0
                reasons.append(f"Rarely used protocol: {protocol}")
        
        # Check port usage anomaly
        if src_port != 'N/A' and isinstance(src_port, (int, str)):
            try:
                port = int(src_port)
                total_port_usage = sum(profile['port_usage'].values())
                if total_port_usage > 0:
                    port_usage_count = profile['port_usage'].get(port, 0)
                    port_ratio = port_usage_count / total_port_usage
                    
                    # Check for unusual port (not in top 10 most used ports)
                    if port_ratio < 0.01 and total_port_usage > 50:
                        top_ports = sorted(profile['port_usage'].items(), key=lambda x: x[1], reverse=True)[:10]
                        if port not in [p[0] for p in top_ports]:
                            score += 1.5
                            reasons.append(f"Unusual source port: {port}")
            except:
                pass
        
        # Check destination anomaly (new or rare destination)
        total_connections = sum(profile['destinations'].values())
        if total_connections > 0:
            dst_frequency = profile['destinations'].get(dst_ip, 0)
            dst_ratio = dst_frequency / total_connections
            
            if dst_ratio < 0.01 and total_connections > 20:
                score += 1.5
                reasons.append(f"Rare destination: {dst_ip}")
            
            # Check for excessive unique destinations (possible scanning)
            unique_dests = len(profile['destinations'])
            if unique_dests > 50 and total_connections > 100:
                dest_diversity = unique_dests / total_connections
                if dest_diversity > 0.5:  # More than 50% unique destinations
                    score += 2.0
                    reasons.append(f"High destination diversity (possible scanning): {unique_dests} unique destinations")
        
        # Check temporal anomaly (unusual time of activity)
        hour = datetime.fromtimestamp(timestamp).hour
        day_of_week = datetime.fromtimestamp(timestamp).weekday()
        
        if (day_of_week, hour) in self.temporal_patterns[src_ip]:
            # Check if this is an unusual time for this device
            total_activity = sum(self.temporal_patterns[src_ip].values())
            this_time_activity = self.temporal_patterns[src_ip][(day_of_week, hour)]
            
            if total_activity > 100:
                time_ratio = this_time_activity / total_activity
                if time_ratio < 0.01:
                    score += 1.0
                    reasons.append(f"Unusual time of activity: {hour:02d}:00 on {['Mon','Tue','Wed','Thu','Fri','Sat','Sun'][day_of_week]}")
        
        # Check connection pattern anomaly
        if len(profile['connection_patterns']) > 20:
            recent_patterns = list(profile['connection_patterns'])[-20:]
            current_pattern = f"{dst_ip}:{dst_port}"
            
            if current_pattern not in recent_patterns:
                # New connection pattern
                pattern_frequency = list(profile['connection_patterns']).count(current_pattern)
                if pattern_frequency < 2:
                    score += 0.5
                    reasons.append("New connection pattern")
        
        # Check for beaconing behavior (periodic communication)
        if len(profile['packet_rate']) > 20:
            intervals = []
            for i in range(1, min(20, len(profile['packet_rate']))):
                intervals.append(profile['packet_rate'][i] - profile['packet_rate'][i-1])
            
            if len(intervals) > 10:
                interval_std = np.std(intervals)
                interval_mean = np.mean(intervals)
                
                # Low variance in intervals suggests beaconing
                if interval_mean > 0 and interval_std / interval_mean < 0.2:
                    score += 2.0
                    reasons.append("Possible beaconing behavior detected")
        
        return min(score, 10.0), reasons
    
    def get_device_behavior_summary(self, ip: str) -> Dict:
        """Get behavioral summary for a device"""
        if ip not in self.device_profiles:
            return None
        
        profile = self.device_profiles[ip]
        
        # Calculate statistics
        avg_packet_size = np.mean(list(profile['avg_packet_size'])) if profile['avg_packet_size'] else 0
        total_protocols = sum(profile['protocol_distribution'].values())
        top_protocols = sorted(profile['protocol_distribution'].items(), key=lambda x: x[1], reverse=True)[:5]
        top_ports = sorted(profile['port_usage'].items(), key=lambda x: x[1], reverse=True)[:10]
        top_destinations = sorted(profile['destinations'].items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Calculate packet rate
        if len(profile['packet_rate']) > 1:
            time_span = profile['packet_rate'][-1] - profile['packet_rate'][0]
            packet_rate = len(profile['packet_rate']) / max(time_span, 1)
        else:
            packet_rate = 0
        
        return {
            'ip': ip,
            'total_packets': profile['total_packets'],
            'total_bytes': profile['total_bytes'],
            'avg_packet_size': avg_packet_size,
            'packet_rate': packet_rate,
            'top_protocols': top_protocols,
            'top_ports': top_ports,
            'top_destinations': top_destinations,
            'unique_destinations': len(profile['destinations']),
            'active_hours': sorted(profile['active_hours']),
            'first_seen': datetime.fromtimestamp(profile['first_seen']).isoformat(),
            'last_seen': datetime.fromtimestamp(profile['last_seen']).isoformat()
        }
    
    def _calculate_recent_rate(self, timestamps: deque, current_time: float, window: int = 60) -> float:
        """Calculate packet rate in recent window (packets per second)"""
        if len(timestamps) < 2:
            return 0.0
        
        # Count packets in recent window
        window_start = current_time - window
        recent_count = sum(1 for ts in timestamps if ts >= window_start)
        
        return recent_count / window
    
    def _calculate_historical_avg_rate(self, timestamps: deque, current_time: float) -> float:
        """Calculate historical average packet rate"""
        if len(timestamps) < 2:
            return 0.0
        
        # Use all available data for historical average
        time_span = timestamps[-1] - timestamps[0]
        if time_span > 0:
            return len(timestamps) / time_span
        return 0.0
    
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
    
    def get_all_profiles(self) -> Dict:
        """Get all device profiles"""
        return {ip: self.get_device_behavior_summary(ip) 
                for ip in self.device_profiles.keys() 
                if self.get_device_behavior_summary(ip) is not None}

