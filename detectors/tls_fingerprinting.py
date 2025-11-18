"""
TLS/SSL Fingerprinting System
Analyzes encrypted traffic without decryption using TLS handshake fingerprinting
"""

import dpkt
import struct
import hashlib
from typing import Dict, Optional, List, Tuple
from collections import defaultdict


class TLSFingerprinter:
    """TLS/SSL fingerprinting for encrypted traffic analysis"""
    
    def __init__(self):
        # Known TLS fingerprints (JA3-like)
        self.known_fingerprints = {
            # Common browser fingerprints
            'chrome': set(),
            'firefox': set(),
            'safari': set(),
            'edge': set(),
            
            # Malware/Tool fingerprints
            'metasploit': set(),
            'nmap': set(),
            'masscan': set(),
            'cobalt_strike': set(),
        }
        
        # Track fingerprint usage
        self.fingerprint_stats = defaultdict(lambda: {
            'count': 0,
            'first_seen': None,
            'last_seen': None,
            'source_ips': set(),
            'destinations': set()
        })
        
        # Suspicious fingerprint patterns
        self.suspicious_patterns = []
        
    def extract_tls_fingerprint(self, packet_data: bytes, src_ip: str, dst_ip: str, 
                                src_port: int, dst_port: int) -> Optional[Dict]:
        """
        Extract TLS fingerprint from packet
        Returns fingerprint information or None if not TLS
        """
        try:
            # Check if this is a TLS handshake (ClientHello)
            if len(packet_data) < 5:
                return None
            
            # TLS handshake starts with 0x16 (22 in decimal)
            if packet_data[0] != 0x16:
                return None
            
            # Parse TLS record
            tls_content_type = packet_data[0]
            tls_version = struct.unpack('>H', packet_data[1:3])[0]
            
            # TLS handshake message type (0x01 = ClientHello)
            if len(packet_data) < 5 or packet_data[5] != 0x01:
                return None
            
            # Extract TLS ClientHello data
            try:
                fingerprint = self._parse_client_hello(packet_data, src_ip, dst_ip, src_port, dst_port)
                if fingerprint:
                    # Update statistics
                    fp_hash = fingerprint['fingerprint_hash']
                    stats = self.fingerprint_stats[fp_hash]
                    stats['count'] += 1
                    stats['source_ips'].add(src_ip)
                    stats['destinations'].add(dst_ip)
                    if not stats['first_seen']:
                        stats['first_seen'] = fingerprint['timestamp']
                    stats['last_seen'] = fingerprint['timestamp']
                    
                return fingerprint
            except Exception as e:
                return None
                
        except Exception as e:
            return None
    
    def _parse_client_hello(self, data: bytes, src_ip: str, dst_ip: str, 
                           src_port: int, dst_port: int) -> Optional[Dict]:
        """Parse TLS ClientHello message"""
        try:
            offset = 5  # Skip record header and handshake header
            
            # TLS version (2 bytes)
            if offset + 2 > len(data):
                return None
            version = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2
            
            # Random (32 bytes)
            if offset + 32 > len(data):
                return None
            random = data[offset:offset+32]
            offset += 32
            
            # Session ID length
            if offset >= len(data):
                return None
            session_id_len = data[offset]
            offset += 1 + session_id_len
            
            # Cipher suites length
            if offset + 2 > len(data):
                return None
            cipher_suites_len = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2
            
            if offset + cipher_suites_len > len(data):
                return None
            
            # Extract cipher suites
            cipher_suites = []
            for i in range(0, cipher_suites_len, 2):
                if offset + i + 2 <= len(data):
                    cipher_suite = struct.unpack('>H', data[offset+i:offset+i+2])[0]
                    cipher_suites.append(cipher_suite)
            
            offset += cipher_suites_len
            
            # Compression methods length
            if offset >= len(data):
                return None
            compression_len = data[offset]
            offset += 1
            
            if offset + compression_len > len(data):
                return None
            
            # Compression methods
            compression_methods = list(data[offset:offset+compression_len])
            offset += compression_len
            
            # Extensions length
            extensions = []
            extensions_data = {}
            if offset + 2 <= len(data):
                extensions_len = struct.unpack('>H', data[offset:offset+2])[0]
                offset += 2
                
                ext_offset = offset
                while ext_offset < offset + extensions_len and ext_offset + 4 <= len(data):
                    ext_type = struct.unpack('>H', data[ext_offset:ext_offset+2])[0]
                    ext_len = struct.unpack('>H', data[ext_offset+2:ext_offset+4])[0]
                    extensions.append(ext_type)
                    
                    # Parse Server Name Indication (SNI) extension
                    if ext_type == 0:  # server_name
                        if ext_offset + 4 + ext_len <= len(data):
                            sni_data = data[ext_offset+4:ext_offset+4+ext_len]
                            try:
                                # Parse SNI
                                if len(sni_data) > 5:
                                    sni_len = struct.unpack('>H', sni_data[3:5])[0]
                                    if len(sni_data) >= 5 + sni_len:
                                        server_name = sni_data[5:5+sni_len].decode('utf-8', errors='ignore')
                                        extensions_data['sni'] = server_name
                            except:
                                pass
                    
                    # Parse Supported Groups extension
                    if ext_type == 10:  # supported_groups
                        if ext_offset + 6 + ext_len <= len(data):
                            groups_data = data[ext_offset+6:ext_offset+6+ext_len]
                            groups = []
                            for g in range(0, len(groups_data), 2):
                                if g + 2 <= len(groups_data):
                                    group = struct.unpack('>H', groups_data[g:g+2])[0]
                                    groups.append(group)
                            extensions_data['supported_groups'] = groups
                    
                    ext_offset += 4 + ext_len
            
            # Create JA3-like fingerprint
            fingerprint_string = f"{version},{','.join(map(str, cipher_suites[:10]))}," \
                                f"{','.join(map(str, extensions[:10]))}"
            fingerprint_hash = hashlib.md5(fingerprint_string.encode()).hexdigest()
            
            return {
                'fingerprint_hash': fingerprint_hash,
                'fingerprint_string': fingerprint_string,
                'tls_version': version,
                'cipher_suites': cipher_suites[:10],  # First 10 for fingerprint
                'extensions': extensions[:10],  # First 10 for fingerprint
                'compression_methods': compression_methods,
                'sni': extensions_data.get('sni'),
                'supported_groups': extensions_data.get('supported_groups', [])[:5],
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'timestamp': None  # Will be set by caller
            }
            
        except Exception as e:
            return None
    
    def analyze_tls_anomaly(self, fingerprint: Dict) -> Tuple[float, List[str]]:
        """
        Analyze TLS fingerprint for anomalies
        Returns: (anomaly_score, reasons)
        """
        score = 0.0
        reasons = []
        
        fp_hash = fingerprint['fingerprint_hash']
        stats = self.fingerprint_stats[fp_hash]
        
        # Check for rare/unusual fingerprints
        total_fingerprints = sum(s['count'] for s in self.fingerprint_stats.values())
        if total_fingerprints > 0:
            fp_frequency = stats['count'] / total_fingerprints
            if fp_frequency < 0.01 and total_fingerprints > 100:
                score += 2.0
                reasons.append("Rare TLS fingerprint detected")
        
        # Check for unusual cipher suites (weak or outdated)
        cipher_suites = fingerprint.get('cipher_suites', [])
        weak_ciphers = [0x0000, 0x0002, 0x0003, 0x0004, 0x0005]  # NULL, RC4, etc.
        for cipher in cipher_suites:
            if cipher in weak_ciphers:
                score += 3.0
                reasons.append(f"Weak cipher suite detected: {hex(cipher)}")
                break
        
        # Check for unusual TLS version (too old)
        tls_version = fingerprint.get('tls_version', 0)
        if tls_version < 0x0301:  # SSL 3.0 or older
            score += 2.5
            reasons.append(f"Outdated TLS/SSL version: {hex(tls_version)}")
        elif tls_version == 0x0300:  # SSL 3.0
            score += 2.0
            reasons.append("SSL 3.0 detected (vulnerable)")
        
        # Check for missing SNI (unusual for modern clients)
        if not fingerprint.get('sni') and fingerprint.get('dst_port') == 443:
            score += 1.0
            reasons.append("Missing SNI (Server Name Indication)")
        
        # Check for fingerprint diversity (multiple clients using same fingerprint = botnet?)
        unique_sources = len(stats['source_ips'])
        if stats['count'] > 10 and unique_sources > 5:
            # Multiple sources using same fingerprint
            if unique_sources / stats['count'] > 0.8:
                score += 1.5
                reasons.append("Multiple sources using identical TLS fingerprint (possible botnet)")
        
        # Check for unusual extensions
        extensions = fingerprint.get('extensions', [])
        uncommon_extensions = [13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23]
        unusual_count = sum(1 for ext in extensions if ext in uncommon_extensions)
        if unusual_count > 3:
            score += 1.0
            reasons.append(f"Unusual TLS extensions detected: {unusual_count}")
        
        return min(score, 10.0), reasons
    
    def get_fingerprint_stats(self) -> Dict:
        """Get statistics about TLS fingerprints"""
        return {
            'total_fingerprints': len(self.fingerprint_stats),
            'top_fingerprints': sorted(
                [(fp, stats['count']) for fp, stats in self.fingerprint_stats.items()],
                key=lambda x: x[1],
                reverse=True
            )[:10],
            'unique_ips': len(set(
                ip for stats in self.fingerprint_stats.values() 
                for ip in stats['source_ips']
            ))
        }

