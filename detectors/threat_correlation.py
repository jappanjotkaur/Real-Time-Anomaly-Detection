"""
Threat Correlation Engine
Correlates multiple threat indicators to identify complex attack patterns
"""

import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Set, Optional
import numpy as np


class ThreatCorrelationEngine:
    """Correlates multiple threat indicators to identify complex attacks"""
    
    def __init__(self, correlation_window=300):
        """
        Args:
            correlation_window: Time window in seconds for correlating events
        """
        self.correlation_window = correlation_window
        
        # Event storage
        self.events = deque(maxlen=10000)
        
        # Correlation rules
        self.correlation_rules = [
            self._correlate_multi_stage_attack,
            self._correlate_lateral_movement,
            self._correlate_data_exfiltration,
            self._correlate_command_control,
            self._correlate_privilege_escalation,
            self._correlate_reconnaissance_chain
        ]
        
        # Correlated incidents
        self.incidents = deque(maxlen=1000)
        
    def add_event(self, event_type: str, event_data: Dict, timestamp: float):
        """Add an event for correlation"""
        event = {
            'type': event_type,
            'data': event_data,
            'timestamp': timestamp,
            'src_ip': event_data.get('src_ip', 'Unknown'),
            'dst_ip': event_data.get('dst_ip', 'Unknown'),
            'severity': event_data.get('severity', 0),
            'correlated': False
        }
        self.events.append(event)
        
        # Try to correlate with existing events
        self._correlate_events(event)
    
    def _correlate_events(self, new_event: Dict):
        """Correlate new event with existing events"""
        cutoff_time = new_event['timestamp'] - self.correlation_window
        
        # Get recent events in correlation window
        recent_events = [e for e in self.events 
                        if e['timestamp'] >= cutoff_time and not e.get('correlated', False)]
        
        # Apply correlation rules
        for rule in self.correlation_rules:
            incident = rule(new_event, recent_events)
            if incident:
                self.incidents.append(incident)
                # Mark events as correlated
                for event in recent_events + [new_event]:
                    event['correlated'] = True
                break
    
    def _correlate_multi_stage_attack(self, new_event: Dict, recent_events: List[Dict]) -> Optional[Dict]:
        """Detect multi-stage attacks (recon -> exploit -> C2 -> exfiltration)"""
        event_types = [e['type'] for e in recent_events] + [new_event['type']]
        
        stages_detected = {
            'reconnaissance': any('scan' in t or 'recon' in t for t in event_types),
            'exploitation': any('exploit' in t or 'brute_force' in t for t in event_types),
            'command_control': any('c2' in t or 'beacon' in t for t in event_types),
            'exfiltration': any('exfiltration' in t or 'data_transfer' in t for t in event_types)
        }
        
        stages_count = sum(1 for detected in stages_detected.values() if detected)
        
        if stages_count >= 3:
            # Multiple attack stages detected
            return {
                'incident_type': 'multi_stage_attack',
                'severity': 9.5,
                'stages': stages_detected,
                'events': recent_events + [new_event],
                'src_ip': new_event['src_ip'],
                'description': f"Multi-stage attack detected: {stages_count} attack stages identified",
                'timestamp': new_event['timestamp']
            }
        return None
    
    def _correlate_lateral_movement(self, new_event: Dict, recent_events: List[Dict]) -> Optional[Dict]:
        """Detect lateral movement (accessing multiple internal systems)"""
        src_ip = new_event['src_ip']
        
        # Get all events from same source IP
        src_events = [e for e in recent_events if e['src_ip'] == src_ip] + [new_event]
        
        # Check if accessing multiple internal IPs
        internal_destinations = set()
        for event in src_events:
            dst_ip = event['dst_ip']
            if self._is_internal_ip(dst_ip):
                internal_destinations.add(dst_ip)
        
        if len(internal_destinations) >= 3:
            return {
                'incident_type': 'lateral_movement',
                'severity': 8.5,
                'src_ip': src_ip,
                'internal_targets': list(internal_destinations),
                'target_count': len(internal_destinations),
                'events': src_events,
                'description': f"Lateral movement detected: {src_ip} accessed {len(internal_destinations)} internal systems",
                'timestamp': new_event['timestamp']
            }
        return None
    
    def _correlate_data_exfiltration(self, new_event: Dict, recent_events: List[Dict]) -> Optional[Dict]:
        """Detect data exfiltration patterns"""
        src_ip = new_event['src_ip']
        
        # Get events from same source
        src_events = [e for e in recent_events if e['src_ip'] == src_ip] + [new_event]
        
        # Check for large data transfers to external IPs
        external_transfers = []
        for event in src_events:
            dst_ip = event.get('dst_ip', 'Unknown')
            size = event.get('data', {}).get('size', 0)
            
            if not self._is_internal_ip(dst_ip) and size > 10000:  # >10KB
                external_transfers.append({
                    'dst_ip': dst_ip,
                    'size': size,
                    'timestamp': event['timestamp']
                })
        
        total_size = sum(t['size'] for t in external_transfers)
        
        if len(external_transfers) >= 5 or total_size > 1000000:  # 5 transfers or >1MB
            return {
                'incident_type': 'data_exfiltration',
                'severity': 9.0,
                'src_ip': src_ip,
                'transfer_count': len(external_transfers),
                'total_size': total_size,
                'transfers': external_transfers,
                'description': f"Data exfiltration suspected: {src_ip} transferred {total_size} bytes to external systems",
                'timestamp': new_event['timestamp']
            }
        return None
    
    def _correlate_command_control(self, new_event: Dict, recent_events: List[Dict]) -> Optional[Dict]:
        """Detect command and control (C2) communication"""
        src_ip = new_event['src_ip']
        
        # Get events from same source
        src_events = [e for e in recent_events if e['src_ip'] == src_ip] + [new_event]
        
        # Check for beaconing pattern (periodic communication)
        if len(src_events) >= 10:
            timestamps = [e['timestamp'] for e in src_events]
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            
            if intervals:
                avg_interval = np.mean(intervals)
                std_interval = np.std(intervals)
                
                # Low variance suggests beaconing
                if avg_interval > 0 and std_interval / avg_interval < 0.3:
                    return {
                        'incident_type': 'command_control',
                        'severity': 8.0,
                        'src_ip': src_ip,
                        'beacon_interval': avg_interval,
                        'event_count': len(src_events),
                        'events': src_events,
                        'description': f"C2 communication detected: {src_ip} shows beaconing pattern (interval: {avg_interval:.1f}s)",
                        'timestamp': new_event['timestamp']
                    }
        return None
    
    def _correlate_privilege_escalation(self, new_event: Dict, recent_events: List[Dict]) -> Optional[Dict]:
        """Detect privilege escalation attempts"""
        src_ip = new_event['src_ip']
        
        # Look for sequence: normal user activity -> admin port access -> system modification
        event_sequence = [e['type'] for e in recent_events if e['src_ip'] == src_ip] + [new_event['type']]
        
        admin_ports = {22, 23, 3389, 5985, 5986, 445, 135, 139}  # SSH, Telnet, RDP, WinRM, SMB
        new_event_port = new_event.get('data', {}).get('dst_port', 0)
        
        # Check for admin port access after normal activity
        if new_event_port in admin_ports:
            # Check if there was recent normal activity
            has_normal_activity = any('normal' in t or 'http' in t for t in event_sequence[:-1])
            
            if has_normal_activity:
                return {
                    'incident_type': 'privilege_escalation',
                    'severity': 8.5,
                    'src_ip': src_ip,
                    'target_port': new_event_port,
                    'events': [e for e in recent_events if e['src_ip'] == src_ip] + [new_event],
                    'description': f"Privilege escalation attempt: {src_ip} accessed admin port {new_event_port} after normal activity",
                    'timestamp': new_event['timestamp']
                }
        return None
    
    def _correlate_reconnaissance_chain(self, new_event: Dict, recent_events: List[Dict]) -> Optional[Dict]:
        """Detect reconnaissance chain (port scan -> service identification -> vulnerability scan)"""
        src_ip = new_event['src_ip']
        
        # Get events from same source
        src_events = [e for e in recent_events if e['src_ip'] == src_ip] + [new_event]
        
        recon_indicators = {
            'port_scan': any('port_scan' in e['type'] or 'scan' in e['type'] for e in src_events),
            'service_identification': any('service' in e['type'] or 'banner' in e['type'] for e in src_events),
            'vulnerability_scan': any('vuln' in e['type'] or 'exploit' in e['type'] for e in src_events)
        }
        
        recon_count = sum(1 for detected in recon_indicators.values() if detected)
        
        if recon_count >= 2:
            return {
                'incident_type': 'reconnaissance_chain',
                'severity': 7.0,
                'src_ip': src_ip,
                'indicators': recon_indicators,
                'events': src_events,
                'description': f"Reconnaissance chain detected: {src_ip} performed {recon_count} reconnaissance activities",
                'timestamp': new_event['timestamp']
            }
        return None
    
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is internal/private"""
        if ip == 'Unknown':
            return False
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
    
    def get_correlated_incidents(self, time_window: int = 3600) -> List[Dict]:
        """Get correlated incidents within time window"""
        cutoff_time = time.time() - time_window
        return [incident for incident in self.incidents 
                if incident['timestamp'] >= cutoff_time]
    
    def get_threat_timeline(self, src_ip: str = None, time_window: int = 3600) -> List[Dict]:
        """Get timeline of threat events"""
        cutoff_time = time.time() - time_window
        
        events = [e for e in self.events if e['timestamp'] >= cutoff_time]
        if src_ip:
            events = [e for e in events if e['src_ip'] == src_ip]
        
        return sorted(events, key=lambda x: x['timestamp'])

