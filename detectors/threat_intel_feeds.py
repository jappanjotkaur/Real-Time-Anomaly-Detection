"""
Threat Intelligence Feed Aggregator
Aggregates IOCs from multiple threat intelligence sources
"""

import requests
import time
import json
import hashlib
from typing import Dict, List, Set, Optional
from collections import defaultdict, deque
from datetime import datetime, timedelta
import os


class ThreatIntelFeedAggregator:
    """Aggregate threat intelligence from multiple sources"""
    
    def __init__(self, cache_dir='threat_intel_cache'):
        """
        Args:
            cache_dir: Directory to cache threat intelligence data
        """
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)
        
        # Threat intelligence sources
        self.feeds = {
            'abuse_ch': {
                'url': 'https://feeds.abuse.ch/urlhausbot/v1',
                'enabled': True,
                'type': 'malware_urls',
                'update_interval': 3600  # 1 hour
            },
            'alienvault_otx': {
                'url': 'https://otx.alienvault.com/api/v1/pulses/subscribed',
                'enabled': False,  # Requires API key
                'type': 'pulses',
                'update_interval': 1800  # 30 minutes
            },
            'emerging_threats': {
                'url': 'https://rules.emergingthreats.net/open/suricata/rules/emerging-compromised.rules',
                'enabled': True,
                'type': 'compromised_ips',
                'update_interval': 3600
            },
            'malware_domains': {
                'url': 'http://mirror1.malwaredomains.com/files/domains.txt',
                'enabled': True,
                'type': 'malware_domains',
                'update_interval': 86400  # 24 hours
            }
        }
        
        # Cached threat data
        self.malicious_ips = set()
        self.malicious_domains = set()
        self.malicious_urls = set()
        self.suspicious_hashes = set()
        
        # Feed update timestamps
        self.feed_updates = {}
        
        # Statistics
        self.stats = {
            'total_ips': 0,
            'total_domains': 0,
            'total_urls': 0,
            'last_update': None
        }
        
        # Load cached data
        self._load_cache()
    
    def update_feeds(self, force: bool = False) -> Dict:
        """
        Update threat intelligence feeds
        Args:
            force: Force update even if not due
        Returns:
            Update results
        """
        results = {}
        
        for feed_name, feed_config in self.feeds.items():
            if not feed_config.get('enabled'):
                continue
            
            # Check if update is needed
            last_update = self.feed_updates.get(feed_name, 0)
            update_interval = feed_config.get('update_interval', 3600)
            
            if not force and time.time() - last_update < update_interval:
                results[feed_name] = {'status': 'skipped', 'reason': 'not_due'}
                continue
            
            try:
                result = self._update_feed(feed_name, feed_config)
                results[feed_name] = result
                self.feed_updates[feed_name] = time.time()
            except Exception as e:
                results[feed_name] = {'status': 'error', 'error': str(e)}
        
        # Save cache
        self._save_cache()
        
        # Update statistics
        self.stats['total_ips'] = len(self.malicious_ips)
        self.stats['total_domains'] = len(self.malicious_domains)
        self.stats['total_urls'] = len(self.malicious_urls)
        self.stats['last_update'] = time.time()
        
        return results
    
    def _update_feed(self, feed_name: str, feed_config: Dict) -> Dict:
        """Update a specific threat intelligence feed"""
        url = feed_config['url']
        feed_type = feed_config['type']
        
        try:
            response = requests.get(url, timeout=30, headers={
                'User-Agent': 'NetSniff-Guard/1.0'
            })
            response.raise_for_status()
            
            if feed_type == 'malware_urls':
                return self._parse_urlhaus_feed(response.text)
            elif feed_type == 'compromised_ips':
                return self._parse_emerging_threats_feed(response.text)
            elif feed_type == 'malware_domains':
                return self._parse_malware_domains_feed(response.text)
            elif feed_type == 'pulses':
                return self._parse_otx_pulses(response.json())
            else:
                return {'status': 'error', 'error': f'Unknown feed type: {feed_type}'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def _parse_urlhaus_feed(self, content: str) -> Dict:
        """Parse URLhaus feed"""
        added = 0
        try:
            # URLhaus provides JSON or CSV format
            if content.strip().startswith('{'):
                data = json.loads(content)
                if 'urls' in data:
                    for entry in data['urls']:
                        url = entry.get('url', '')
                        if url:
                            self.malicious_urls.add(url)
                            added += 1
            else:
                # CSV format
                lines = content.strip().split('\n')
                for line in lines:
                    if line and not line.startswith('#'):
                        parts = line.split(',')
                        if len(parts) > 0:
                            url = parts[0].strip()
                            if url:
                                self.malicious_urls.add(url)
                                added += 1
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
        
        return {'status': 'success', 'added': added}
    
    def _parse_emerging_threats_feed(self, content: str) -> Dict:
        """Parse Emerging Threats feed"""
        added = 0
        try:
            lines = content.strip().split('\n')
            for line in lines:
                if 'alert' in line.lower() and 'ip' in line.lower():
                    # Extract IP addresses from Suricata rules
                    import re
                    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                    for ip in ips:
                        if ip and not ip.startswith('127.'):
                            self.malicious_ips.add(ip)
                            added += 1
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
        
        return {'status': 'success', 'added': added}
    
    def _parse_malware_domains_feed(self, content: str) -> Dict:
        """Parse Malware Domains feed"""
        added = 0
        try:
            lines = content.strip().split('\n')
            for line in lines:
                if line and not line.startswith('#'):
                    parts = line.split('\t')
                    if len(parts) > 0:
                        domain = parts[0].strip()
                        if domain and '.' in domain:
                            self.malicious_domains.add(domain)
                            added += 1
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
        
        return {'status': 'success', 'added': added}
    
    def _parse_otx_pulses(self, data: Dict) -> Dict:
        """Parse AlienVault OTX pulses (requires API key)"""
        added = 0
        try:
            if 'results' in data:
                for pulse in data['results']:
                    # Extract IOCs
                    if 'indicators' in pulse:
                        for indicator in pulse['indicators']:
                            indicator_type = indicator.get('type', '')
                            indicator_value = indicator.get('indicator', '')
                            
                            if indicator_type == 'IPv4':
                                self.malicious_ips.add(indicator_value)
                                added += 1
                            elif indicator_type == 'domain':
                                self.malicious_domains.add(indicator_value)
                                added += 1
                            elif indicator_type == 'URL':
                                self.malicious_urls.add(indicator_value)
                                added += 1
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
        
        return {'status': 'success', 'added': added}
    
    def check_ip(self, ip: str) -> Dict:
        """Check if IP is in threat intelligence feeds"""
        is_malicious = ip in self.malicious_ips
        return {
            'ip': ip,
            'is_malicious': is_malicious,
            'threat_level': 9.0 if is_malicious else 0.0,
            'sources': ['threat_intel_feeds'] if is_malicious else []
        }
    
    def check_domain(self, domain: str) -> Dict:
        """Check if domain is in threat intelligence feeds"""
        is_malicious = domain in self.malicious_domains
        return {
            'domain': domain,
            'is_malicious': is_malicious,
            'threat_level': 9.0 if is_malicious else 0.0,
            'sources': ['threat_intel_feeds'] if is_malicious else []
        }
    
    def check_url(self, url: str) -> Dict:
        """Check if URL is in threat intelligence feeds"""
        is_malicious = url in self.malicious_urls
        return {
            'url': url,
            'is_malicious': is_malicious,
            'threat_level': 9.0 if is_malicious else 0.0,
            'sources': ['threat_intel_feeds'] if is_malicious else []
        }
    
    def add_custom_ioc(self, ioc_type: str, ioc_value: str, source: str = 'custom'):
        """Add custom IOC to threat intelligence"""
        if ioc_type == 'ip':
            self.malicious_ips.add(ioc_value)
        elif ioc_type == 'domain':
            self.malicious_domains.add(ioc_value)
        elif ioc_type == 'url':
            self.malicious_urls.add(url)
        elif ioc_type == 'hash':
            self.suspicious_hashes.add(ioc_value)
        
        self._save_cache()
    
    def _load_cache(self):
        """Load cached threat intelligence data"""
        cache_file = os.path.join(self.cache_dir, 'threat_intel_cache.json')
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                    self.malicious_ips = set(data.get('malicious_ips', []))
                    self.malicious_domains = set(data.get('malicious_domains', []))
                    self.malicious_urls = set(data.get('malicious_urls', []))
                    self.suspicious_hashes = set(data.get('suspicious_hashes', []))
                    self.feed_updates = data.get('feed_updates', {})
                    self.stats = data.get('stats', self.stats)
            except Exception as e:
                print(f"[!] Error loading threat intel cache: {e}")
    
    def _save_cache(self):
        """Save threat intelligence data to cache"""
        cache_file = os.path.join(self.cache_dir, 'threat_intel_cache.json')
        try:
            data = {
                'malicious_ips': list(self.malicious_ips),
                'malicious_domains': list(self.malicious_domains),
                'malicious_urls': list(self.malicious_urls),
                'suspicious_hashes': list(self.suspicious_hashes),
                'feed_updates': self.feed_updates,
                'stats': self.stats,
                'last_saved': time.time()
            }
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"[!] Error saving threat intel cache: {e}")
    
    def get_statistics(self) -> Dict:
        """Get threat intelligence statistics"""
        return {
            **self.stats,
            'malicious_ips': len(self.malicious_ips),
            'malicious_domains': len(self.malicious_domains),
            'malicious_urls': len(self.malicious_urls),
            'suspicious_hashes': len(self.suspicious_hashes),
            'feeds': {name: {
                'enabled': config.get('enabled', False),
                'last_update': self.feed_updates.get(name, 0)
            } for name, config in self.feeds.items()}
        }

