"""
Threat Intelligence Integration
IP reputation, GeoIP, threat feeds, and domain analysis
"""

import requests
import socket
import json
import time
import os
from collections import defaultdict
from datetime import datetime, timedelta
import hashlib

class ThreatIntelligence:
    """Threat intelligence and reputation checking"""
    
    def __init__(self, cache_ttl=3600):
        self.cache_ttl = cache_ttl  # Cache results for 1 hour
        self.ip_cache = {}
        self.domain_cache = {}
        self.threat_feeds = []
        self.suspicious_ips = set()
        self.suspicious_domains = set()
        
        # Load known threat indicators
        self._load_threat_indicators()
        
    def _load_threat_indicators(self):
        """Load known threat indicators (malware IPs, C2 domains, etc.)"""
        # Common suspicious ports
        self.suspicious_ports = {
            4444,  # Metasploit
            31337, # Back Orifice
            6667,  # IRC (often used for C2)
            12345, # NetBus
            5555,  # Android ADB (can be abused)
            9999,  # Custom malware ports
            8080,  # HTTP alternate (can be used for C2)
            4433,  # Alternative HTTPS
        }
        
        # Known malicious TLDs (often used by malware)
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.gq'  # Free TLDs often abused
        }
        
        # Load from local threat lists if available
        try:
            if os.path.exists('threat_lists/suspicious_ips.txt'):
                with open('threat_lists/suspicious_ips.txt', 'r') as f:
                    self.suspicious_ips.update(line.strip() for line in f)
        except:
            pass
    
    def check_ip_reputation(self, ip_address, timeout=2):
        """Check IP reputation using multiple sources"""
        # Check cache first
        if ip_address in self.ip_cache:
            cached_result = self.ip_cache[ip_address]
            if time.time() - cached_result['timestamp'] < self.cache_ttl:
                return cached_result['data']
        
        result = {
            'ip': ip_address,
            'reputation': 'unknown',
            'threat_level': 0,
            'sources': [],
            'country': None,
            'asn': None,
            'is_malicious': False,
            'is_suspicious': False,
            'reasons': []
        }
        
        # Check local threat lists
        if ip_address in self.suspicious_ips:
            result['is_malicious'] = True
            result['threat_level'] = 9
            result['reputation'] = 'malicious'
            result['reasons'].append('Known malicious IP in threat list')
        
        # Check if IP is private/local
        try:
            ip_obj = socket.inet_aton(ip_address)
            # Private IP ranges
            if ip_address.startswith('10.') or ip_address.startswith('192.168.') or \
               ip_address.startswith('172.16.') or ip_address.startswith('172.17.') or \
               ip_address.startswith('172.18.') or ip_address.startswith('172.19.') or \
               (ip_address.startswith('172.2') and int(ip_address.split('.')[1]) <= 31) or \
               ip_address.startswith('127.') or ip_address.startswith('169.254.'):
                result['reputation'] = 'private'
                result['reasons'].append('Private/local IP address')
        except:
            pass
        
        # Get GeoIP information (free service)
        try:
            geoip_response = requests.get(
                f'http://ip-api.com/json/{ip_address}',
                timeout=timeout
            )
            if geoip_response.status_code == 200:
                geoip_data = geoip_response.json()
                result['country'] = geoip_data.get('country', 'Unknown')
                result['asn'] = geoip_data.get('as', 'Unknown')
                
                # Check for suspicious countries (can be configured)
                suspicious_countries = {'CN', 'RU', 'KP', 'IR'}  # Example list
                if geoip_data.get('countryCode') in suspicious_countries:
                    result['threat_level'] += 1
                    result['is_suspicious'] = True
                    result['reasons'].append(f'Origin country: {result["country"]}')
        except:
            pass
        
        # Check AbuseIPDB (requires API key - optional)
        # Uncomment if you have an API key
        # try:
        #     abuseipdb_response = requests.get(
        #         f'https://api.abuseipdb.com/api/v2/check',
        #         headers={'Key': 'YOUR_API_KEY'},
        #         params={'ipAddress': ip_address, 'maxAgeInDays': 90},
        #         timeout=timeout
        #     )
        #     if abuseipdb_response.status_code == 200:
        #         abuse_data = abuseipdb_response.json()
        #         if abuse_data.get('data', {}).get('abuseConfidenceScore', 0) > 50:
        #             result['is_malicious'] = True
        #             result['threat_level'] = max(result['threat_level'], 
        #                                        abuse_data['data']['abuseConfidenceScore'] / 10)
        #             result['reasons'].append('High abuse confidence score')
        # except:
        #     pass
        
        # Cache result
        self.ip_cache[ip_address] = {
            'data': result,
            'timestamp': time.time()
        }
        
        return result
    
    def check_domain_reputation(self, domain, timeout=2):
        """Check domain reputation"""
        # Check cache
        if domain in self.domain_cache:
            cached_result = self.domain_cache[domain]
            if time.time() - cached_result['timestamp'] < self.cache_ttl:
                return cached_result['data']
        
        result = {
            'domain': domain,
            'reputation': 'unknown',
            'threat_level': 0,
            'is_malicious': False,
            'is_suspicious': False,
            'reasons': [],
            'dga_probability': 0.0
        }
        
        # Check local threat lists
        if domain in self.suspicious_domains:
            result['is_malicious'] = True
            result['threat_level'] = 9
            result['reputation'] = 'malicious'
            result['reasons'].append('Known malicious domain')
        
        # Check for suspicious TLDs
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                result['threat_level'] += 2
                result['is_suspicious'] = True
                result['reasons'].append(f'Suspicious TLD: {tld}')
        
        # DGA (Domain Generation Algorithm) detection
        dga_score = self._detect_dga(domain)
        result['dga_probability'] = dga_score
        if dga_score > 0.7:
            result['threat_level'] += 3
            result['is_suspicious'] = True
            result['reasons'].append('High DGA probability')
        
        # Check domain length (very long domains are often suspicious)
        if len(domain) > 50:
            result['threat_level'] += 1
            result['is_suspicious'] = True
            result['reasons'].append('Unusually long domain name')
        
        # Check for random-looking patterns
        if self._has_random_pattern(domain):
            result['threat_level'] += 1
            result['is_suspicious'] = True
            result['reasons'].append('Random-looking domain pattern')
        
        # Cache result
        self.domain_cache[domain] = {
            'data': result,
            'timestamp': time.time()
        }
        
        return result
    
    def _detect_dga(self, domain):
        """Detect Domain Generation Algorithm (DGA) domains"""
        # Remove TLD
        domain_parts = domain.split('.')
        if len(domain_parts) < 2:
            return 0.0
        
        domain_name = domain_parts[-2]  # Second-level domain
        
        # Features for DGA detection
        features = {
            'length': len(domain_name),
            'vowel_ratio': sum(1 for c in domain_name if c in 'aeiouAEIOU') / max(len(domain_name), 1),
            'consonant_ratio': sum(1 for c in domain_name if c.isalpha() and c not in 'aeiouAEIOU') / max(len(domain_name), 1),
            'digit_ratio': sum(1 for c in domain_name if c.isdigit()) / max(len(domain_name), 1),
            'entropy': self._calculate_entropy(domain_name),
            'has_common_words': self._has_common_words(domain_name)
        }
        
        # Simple heuristic scoring
        score = 0.0
        
        # High entropy = more random = likely DGA
        if features['entropy'] > 3.5:
            score += 0.3
        if features['entropy'] > 4.0:
            score += 0.2
        
        # Low vowel ratio (random domains have fewer vowels)
        if features['vowel_ratio'] < 0.2:
            score += 0.2
        if features['vowel_ratio'] < 0.15:
            score += 0.1
        
        # High digit ratio
        if features['digit_ratio'] > 0.3:
            score += 0.2
        
        # No common words
        if not features['has_common_words']:
            score += 0.1
        
        # Very long domains
        if features['length'] > 15:
            score += 0.1
        
        return min(score, 1.0)
    
    def _calculate_entropy(self, string):
        """Calculate Shannon entropy of a string"""
        if not string:
            return 0
        entropy = 0
        for char in set(string):
            p = string.count(char) / len(string)
            entropy -= p * (p and (p.bit_length() - 1) or 0)
        return entropy
    
    def _has_common_words(self, domain):
        """Check if domain contains common English words"""
        common_words = ['the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'her',
                       'was', 'one', 'our', 'out', 'day', 'get', 'has', 'him', 'his', 'how',
                       'its', 'may', 'new', 'now', 'old', 'see', 'two', 'way', 'who', 'boy',
                       'did', 'has', 'let', 'put', 'say', 'she', 'too', 'use']
        
        domain_lower = domain.lower()
        for word in common_words:
            if word in domain_lower:
                return True
        return False
    
    def _has_random_pattern(self, domain):
        """Check for random-looking patterns"""
        # Check for repeated characters
        if any(domain.count(c) > len(domain) * 0.3 for c in set(domain)):
            return True
        
        # Check for alternating pattern
        if len(domain) > 4:
            alternating = all(domain[i] != domain[i+1] for i in range(len(domain)-1))
            if alternating and len(domain) > 8:
                return True
        
        return False
    
    def check_port_suspicious(self, port):
        """Check if port is suspicious"""
        return port in self.suspicious_ports
    
    def get_threat_score(self, ip_info=None, domain_info=None, port=None):
        """Calculate overall threat score (0-10)"""
        score = 0.0
        
        if ip_info:
            score += ip_info.get('threat_level', 0) * 0.6
            if ip_info.get('is_malicious'):
                score = max(score, 8.0)
        
        if domain_info:
            score += domain_info.get('threat_level', 0) * 0.4
            if domain_info.get('is_malicious'):
                score = max(score, 8.0)
        
        if port and self.check_port_suspicious(port):
            score += 2.0
        
        return min(score, 10.0)

