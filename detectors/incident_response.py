"""
Automated Incident Response System
Automatically responds to detected threats by blocking, throttling, or alerting
"""

import time
import subprocess
import platform
from typing import Dict, List, Optional, Tuple
from collections import defaultdict, deque
from datetime import datetime
import json
import os


class IncidentResponseEngine:
    """Automated incident response system"""
    
    def __init__(self, response_config: Dict = None):
        """
        Args:
            response_config: Configuration for response actions
                - auto_block: Enable automatic IP blocking (default: False)
                - auto_throttle: Enable automatic rate limiting (default: True)
                - block_duration: Duration to block IPs in seconds (default: 3600)
                - throttle_threshold: Packets per second threshold (default: 100)
                - whitelist_ips: List of IPs to never block
        """
        self.config = response_config or {}
        self.auto_block = self.config.get('auto_block', False)
        self.auto_throttle = self.config.get('auto_throttle', True)
        self.block_duration = self.config.get('block_duration', 3600)
        self.throttle_threshold = self.config.get('throttle_threshold', 100)
        self.whitelist_ips = set(self.config.get('whitelist_ips', []))
        
        # Track blocked and throttled IPs
        self.blocked_ips = {}  # {ip: (block_time, duration, reason)}
        self.throttled_ips = {}  # {ip: (throttle_time, rate_limit)}
        self.response_history = deque(maxlen=1000)
        
        # Rate tracking
        self.ip_rate_tracker = defaultdict(lambda: deque(maxlen=100))
        
        # Platform detection
        self.is_windows = platform.system() == 'Windows'
        self.is_linux = platform.system() == 'Linux'
        
        # Response actions log
        self.response_log_path = 'logs/incident_response.log'
        os.makedirs(os.path.dirname(self.response_log_path), exist_ok=True)
    
    def process_threat(self, threat_data: Dict) -> Dict:
        """
        Process a threat and determine appropriate response
        Args:
            threat_data: Dictionary containing threat information
                - src_ip: Source IP address
                - dst_ip: Destination IP address
                - severity: Threat severity (0-10)
                - threat_type: Type of threat
                - anomaly_score: Anomaly detection score
        Returns:
            Response action taken
        """
        src_ip = threat_data.get('src_ip', 'Unknown')
        severity = threat_data.get('severity', 0)
        threat_type = threat_data.get('threat_type', 'unknown')
        anomaly_score = threat_data.get('anomaly_score', 0)
        
        if src_ip == 'Unknown' or src_ip in self.whitelist_ips:
            return {'action': 'none', 'reason': 'Whitelisted or unknown IP'}
        
        response = {
            'action': 'none',
            'timestamp': time.time(),
            'ip': src_ip,
            'severity': severity,
            'threat_type': threat_type
        }
        
        # Check if IP is already blocked
        if src_ip in self.blocked_ips:
            block_time, duration, reason = self.blocked_ips[src_ip]
            if time.time() - block_time < duration:
                return {'action': 'already_blocked', 'reason': reason}
            else:
                # Block expired, remove it
                self.unblock_ip(src_ip)
        
        # Determine response based on severity
        if severity >= 9.0 or (severity >= 7.0 and self.auto_block):
            # Critical threat - block immediately
            if self.auto_block:
                result = self.block_ip(src_ip, reason=f"Critical threat: {threat_type}")
                response.update(result)
            else:
                response['action'] = 'alert_only'
                response['recommendation'] = f"Recommend blocking {src_ip} - Critical threat detected"
        
        elif severity >= 6.0:
            # High severity - throttle or block based on config
            if self.auto_throttle:
                result = self.throttle_ip(src_ip, rate_limit=self.throttle_threshold * 0.5)
                response.update(result)
            elif self.auto_block:
                result = self.block_ip(src_ip, reason=f"High severity threat: {threat_type}")
                response.update(result)
            else:
                response['action'] = 'alert_only'
                response['recommendation'] = f"Monitor {src_ip} closely - High severity threat"
        
        elif severity >= 4.0 and anomaly_score > 5.0:
            # Medium severity with high anomaly score - throttle
            if self.auto_throttle:
                result = self.throttle_ip(src_ip, rate_limit=self.throttle_threshold)
                response.update(result)
            else:
                response['action'] = 'monitor'
                response['recommendation'] = f"Monitor {src_ip} - Suspicious activity detected"
        
        # Log response
        self._log_response(response)
        self.response_history.append(response)
        
        return response
    
    def block_ip(self, ip: str, reason: str = "Threat detected", duration: int = None) -> Dict:
        """Block an IP address"""
        if ip in self.whitelist_ips:
            return {'action': 'block_failed', 'reason': 'IP is whitelisted'}
        
        duration = duration or self.block_duration
        block_time = time.time()
        
        # Try to block using platform-specific methods
        success = False
        error = None
        
        if self.is_linux:
            success, error = self._block_ip_linux(ip)
        elif self.is_windows:
            success, error = self._block_ip_windows(ip)
        
        if success or not (self.is_linux or self.is_windows):
            # Track block even if platform method fails (for logging)
            self.blocked_ips[ip] = (block_time, duration, reason)
        
        result = {
            'action': 'blocked' if success else 'block_attempted',
            'ip': ip,
            'duration': duration,
            'reason': reason,
            'timestamp': block_time
        }
        
        if error:
            result['error'] = error
        
        return result
    
    def _block_ip_linux(self, ip: str) -> Tuple[bool, Optional[str]]:
        """Block IP on Linux using iptables"""
        try:
            # Check if iptables is available
            result = subprocess.run(['which', 'iptables'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                return False, "iptables not found"
            
            # Add blocking rule
            rule = ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP']
            result = subprocess.run(rule, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                return True, None
            else:
                return False, result.stderr
        except Exception as e:
            return False, str(e)
    
    def _block_ip_windows(self, ip: str) -> Tuple[bool, Optional[str]]:
        """Block IP on Windows using netsh or Windows Firewall"""
        try:
            # Try using netsh advfirewall (requires admin)
            rule_name = f"NetSniff_Block_{ip.replace('.', '_')}"
            
            # Add firewall rule
            command = [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}',
                'dir=in',
                'action=block',
                f'remoteip={ip}',
                'enable=yes'
            ]
            
            result = subprocess.run(command, capture_output=True, text=True, 
                                  timeout=10, shell=True)
            
            if result.returncode == 0:
                return True, None
            else:
                # Fallback: Just log the attempt
                return False, "Windows firewall rule creation failed (may need admin)"
        except Exception as e:
            return False, str(e)
    
    def unblock_ip(self, ip: str) -> Dict:
        """Unblock an IP address"""
        if ip not in self.blocked_ips:
            return {'action': 'not_blocked', 'ip': ip}
        
        success = False
        error = None
        
        if self.is_linux:
            success, error = self._unblock_ip_linux(ip)
        elif self.is_windows:
            success, error = self._unblock_ip_windows(ip)
        
        # Remove from tracking
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
        
        result = {
            'action': 'unblocked' if success else 'unblock_attempted',
            'ip': ip,
            'timestamp': time.time()
        }
        
        if error:
            result['error'] = error
        
        return result
    
    def _unblock_ip_linux(self, ip: str) -> Tuple[bool, Optional[str]]:
        """Unblock IP on Linux"""
        try:
            rule = ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP']
            result = subprocess.run(rule, capture_output=True, text=True, timeout=5)
            return result.returncode == 0, result.stderr if result.returncode != 0 else None
        except Exception as e:
            return False, str(e)
    
    def _unblock_ip_windows(self, ip: str) -> Tuple[bool, Optional[str]]:
        """Unblock IP on Windows"""
        try:
            rule_name = f"NetSniff_Block_{ip.replace('.', '_')}"
            command = ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}']
            result = subprocess.run(command, capture_output=True, text=True, 
                                  timeout=10, shell=True)
            return result.returncode == 0, result.stderr if result.returncode != 0 else None
        except Exception as e:
            return False, str(e)
    
    def throttle_ip(self, ip: str, rate_limit: int = None) -> Dict:
        """Throttle traffic from an IP address"""
        rate_limit = rate_limit or self.throttle_threshold
        
        # Track throttling
        self.throttled_ips[ip] = (time.time(), rate_limit)
        
        # Update rate tracking
        self.ip_rate_tracker[ip].append(time.time())
        
        # Note: Actual throttling requires traffic shaping tools (tc on Linux, QoS on Windows)
        # This is a placeholder that logs the action
        
        result = {
            'action': 'throttled',
            'ip': ip,
            'rate_limit': rate_limit,
            'timestamp': time.time(),
            'note': 'Rate limiting requires traffic shaping configuration'
        }
        
        return result
    
    def track_packet_rate(self, ip: str, timestamp: float):
        """Track packet rate for an IP"""
        self.ip_rate_tracker[ip].append(timestamp)
    
    def get_ip_rate(self, ip: str, window: int = 60) -> float:
        """Get current packet rate for an IP (packets per second)"""
        if ip not in self.ip_rate_tracker:
            return 0.0
        
        current_time = time.time()
        window_start = current_time - window
        
        # Count packets in window
        recent_packets = [ts for ts in self.ip_rate_tracker[ip] if ts >= window_start]
        
        if len(recent_packets) < 2:
            return 0.0
        
        time_span = recent_packets[-1] - recent_packets[0]
        if time_span > 0:
            return len(recent_packets) / time_span
        return 0.0
    
    def check_rate_limit(self, ip: str) -> bool:
        """Check if IP exceeds rate limit"""
        if ip not in self.throttled_ips:
            return False
        
        current_rate = self.get_ip_rate(ip)
        _, rate_limit = self.throttled_ips[ip]
        
        return current_rate > rate_limit
    
    def _log_response(self, response: Dict):
        """Log response action to file"""
        try:
            log_entry = {
                'timestamp': datetime.fromtimestamp(response['timestamp']).isoformat(),
                'action': response['action'],
                'ip': response.get('ip', 'Unknown'),
                'severity': response.get('severity', 0),
                'threat_type': response.get('threat_type', 'unknown'),
                'reason': response.get('reason', '')
            }
            
            with open(self.response_log_path, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            print(f"[!] Error logging response: {e}")
    
    def get_response_summary(self) -> Dict:
        """Get summary of incident response actions"""
        current_time = time.time()
        
        # Count active blocks
        active_blocks = sum(1 for ip, (block_time, duration, _) in self.blocked_ips.items()
                          if current_time - block_time < duration)
        
        # Count active throttles
        active_throttles = len(self.throttled_ips)
        
        return {
            'total_responses': len(self.response_history),
            'active_blocks': active_blocks,
            'active_throttles': active_throttles,
            'total_blocked_ips': len(self.blocked_ips),
            'recent_responses': list(self.response_history)[-10:]
        }
    
    def cleanup_expired_blocks(self):
        """Remove expired IP blocks"""
        current_time = time.time()
        expired_ips = []
        
        for ip, (block_time, duration, _) in self.blocked_ips.items():
            if current_time - block_time >= duration:
                expired_ips.append(ip)
        
        for ip in expired_ips:
            self.unblock_ip(ip)
        
        return len(expired_ips)

