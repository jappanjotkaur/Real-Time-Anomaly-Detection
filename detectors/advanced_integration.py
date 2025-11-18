"""
Advanced Features Integration Module
Integrates all advanced detection and response capabilities
"""

import time
from typing import Dict, Optional
from detectors.incident_response import IncidentResponseEngine
from detectors.zero_day_detector import ZeroDayDetector
from detectors.alerting_system import AlertingSystem
from detectors.threat_intel_feeds import ThreatIntelFeedAggregator
from detectors.explainable_ai import ExplainableAI
from models.continuous_learning import ContinuousLearningPipeline


class AdvancedDetectionEngine:
    """Main integration engine for all advanced features"""
    
    def __init__(self, config: Dict = None):
        """
        Args:
            config: Configuration dictionary for all components
        """
        self.config = config or {}
        
        # Initialize components
        print("[+] Initializing Advanced Detection Engine...")
        
        # Incident Response
        response_config = self.config.get('incident_response', {})
        self.incident_response = IncidentResponseEngine(response_config)
        print("  [✓] Incident Response Engine initialized")
        
        # Zero-Day Detection
        zero_day_config = self.config.get('zero_day_detector', {})
        self.zero_day_detector = ZeroDayDetector(
            graph_window=zero_day_config.get('graph_window', 300),
            anomaly_threshold=zero_day_config.get('anomaly_threshold', 0.7)
        )
        print("  [✓] Zero-Day Detector initialized")
        
        # Alerting System
        alerting_config = self.config.get('alerting', {})
        self.alerting_system = AlertingSystem(alerting_config)
        print("  [✓] Alerting System initialized")
        
        # Threat Intelligence Feeds
        intel_config = self.config.get('threat_intel', {})
        self.threat_intel_feeds = ThreatIntelFeedAggregator(
            cache_dir=intel_config.get('cache_dir', 'threat_intel_cache')
        )
        print("  [✓] Threat Intelligence Feeds initialized")
        
        # Explainable AI
        self.explainable_ai = ExplainableAI()
        print("  [✓] Explainable AI initialized")
        
        # Continuous Learning
        learning_config = self.config.get('continuous_learning', {})
        self.continuous_learning = ContinuousLearningPipeline(
            model_path=learning_config.get('model_path', './model/continuous_model.pkl'),
            retrain_interval=learning_config.get('retrain_interval', 3600),
            min_samples=learning_config.get('min_samples', 1000)
        )
        print("  [✓] Continuous Learning Pipeline initialized")
        
        # Update threat intel feeds on startup
        if intel_config.get('update_on_startup', True):
            print("[+] Updating threat intelligence feeds...")
            self.threat_intel_feeds.update_feeds(force=True)
        
        print("[+] Advanced Detection Engine ready!")
    
    def analyze_packet(self, packet_info: Dict, timestamp: float, 
                      ml_anomaly_score: float = 0.0) -> Dict:
        """
        Comprehensive packet analysis using all advanced detectors
        Args:
            packet_info: Packet information dictionary
            timestamp: Packet timestamp
            ml_anomaly_score: ML-based anomaly score (from base detector)
        Returns:
            Comprehensive analysis result
        """
        src_ip = packet_info.get('src_ip', 'Unknown')
        dst_ip = packet_info.get('dst_ip', 'Unknown')
        
        analysis_result = {
            'timestamp': timestamp,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'packet_info': packet_info,
            'scores': {},
            'threats': [],
            'actions_taken': [],
            'explanations': []
        }
        
        anomaly_scores = {}
        explanations = []
        
        # 1. Threat Intelligence Check
        threat_intel_result = self._check_threat_intelligence(src_ip, dst_ip, packet_info)
        if threat_intel_result['threat_level'] > 0:
            anomaly_scores['threat_intel'] = threat_intel_result['threat_level']
            explanations.append(f"Threat intelligence match: {threat_intel_result.get('reason', '')}")
            analysis_result['threats'].append({
                'type': 'threat_intelligence',
                'severity': threat_intel_result['threat_level'],
                'details': threat_intel_result
            })
        
        # 2. Zero-Day Detection
        zero_day_result = self.zero_day_detector.analyze_packet(packet_info, timestamp)
        if zero_day_result.get('is_zero_day', False):
            anomaly_scores['zero_day'] = zero_day_result.get('score', 0) * 10
            explanations.extend(zero_day_result.get('patterns', []))
            analysis_result['threats'].append({
                'type': 'zero_day',
                'severity': zero_day_result.get('score', 0) * 10,
                'details': zero_day_result
            })
        
        # 3. ML Anomaly Score
        if ml_anomaly_score > 0:
            anomaly_scores['ml'] = ml_anomaly_score
        
        # 4. Explainable AI
        explainable_result = self.explainable_ai.explain_anomaly(
            packet_info, anomaly_scores, explanations
        )
        analysis_result['explanations'] = explainable_result
        
        # 5. Calculate overall threat severity
        overall_severity = self._calculate_overall_severity(anomaly_scores, explainable_result)
        analysis_result['overall_severity'] = overall_severity
        analysis_result['scores'] = anomaly_scores
        
        # 6. Incident Response
        if overall_severity >= 4.0:
            threat_data = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'severity': overall_severity,
                'threat_type': self._determine_threat_type(analysis_result),
                'anomaly_score': max(anomaly_scores.values()) if anomaly_scores else 0
            }
            
            response = self.incident_response.process_threat(threat_data)
            analysis_result['actions_taken'].append(response)
            
            # 7. Send Alerts
            if overall_severity >= 6.0:
                alert_data = {
                    'severity': self._severity_to_string(overall_severity),
                    'title': f"Network Threat Detected: {self._determine_threat_type(analysis_result)}",
                    'message': explainable_result.get('summary', 'Threat detected'),
                    'threat_type': self._determine_threat_type(analysis_result),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'timestamp': timestamp,
                    'details': {
                        'scores': anomaly_scores,
                        'explanations': explainable_result
                    }
                }
                
                alert_result = self.alerting_system.send_alert(alert_data)
                analysis_result['alert_sent'] = alert_result
        
        # 8. Continuous Learning
        if self.config.get('continuous_learning', {}).get('enabled', True):
            # Extract features for continuous learning
            features = self._extract_features_for_learning(packet_info, timestamp)
            label = -1 if overall_severity >= 4.0 else 1
            self.continuous_learning.add_sample(features, label, timestamp)
        
        return analysis_result
    
    def _check_threat_intelligence(self, src_ip: str, dst_ip: str, 
                                   packet_info: Dict) -> Dict:
        """Check threat intelligence for IPs and domains"""
        threat_level = 0.0
        reasons = []
        
        # Check source IP
        if src_ip != 'Unknown':
            ip_result = self.threat_intel_feeds.check_ip(src_ip)
            if ip_result['is_malicious']:
                threat_level = max(threat_level, ip_result['threat_level'])
                reasons.append(f"Malicious source IP: {src_ip}")
        
        # Check destination IP
        if dst_ip != 'Unknown':
            ip_result = self.threat_intel_feeds.check_ip(dst_ip)
            if ip_result['is_malicious']:
                threat_level = max(threat_level, ip_result['threat_level'])
                reasons.append(f"Malicious destination IP: {dst_ip}")
        
        # Check domain if available
        domain = packet_info.get('dst_hostname', '')
        if domain:
            domain_result = self.threat_intel_feeds.check_domain(domain)
            if domain_result['is_malicious']:
                threat_level = max(threat_level, domain_result['threat_level'])
                reasons.append(f"Malicious domain: {domain}")
        
        return {
            'threat_level': threat_level,
            'reason': '; '.join(reasons) if reasons else '',
            'sources': ['threat_intel_feeds']
        }
    
    def _calculate_overall_severity(self, anomaly_scores: Dict, 
                                    explainable_result: Dict) -> float:
        """Calculate overall threat severity (0-10)"""
        if not anomaly_scores:
            return 0.0
        
        # Get maximum score
        max_score = max(anomaly_scores.values()) if anomaly_scores else 0.0
        
        # Adjust based on explainable AI confidence
        confidence = explainable_result.get('confidence', 0) / 100.0
        adjusted_score = max_score * (0.7 + 0.3 * confidence)
        
        # Cap at 10
        return min(adjusted_score, 10.0)
    
    def _determine_threat_type(self, analysis_result: Dict) -> str:
        """Determine threat type from analysis"""
        threats = analysis_result.get('threats', [])
        if not threats:
            return 'anomaly'
        
        # Get highest severity threat
        highest_threat = max(threats, key=lambda x: x.get('severity', 0))
        return highest_threat.get('type', 'anomaly')
    
    def _severity_to_string(self, severity: float) -> str:
        """Convert severity score to string"""
        if severity >= 8.0:
            return 'critical'
        elif severity >= 6.0:
            return 'high'
        elif severity >= 4.0:
            return 'medium'
        else:
            return 'low'
    
    def _extract_features_for_learning(self, packet_info: Dict, 
                                      timestamp: float) -> list:
        """Extract features for continuous learning"""
        # Basic features similar to anomaly detector
        features = [
            packet_info.get('size', 0),
            hash(packet_info.get('protocol', 'Unknown')) % 100,
            packet_info.get('src_port', 0) if isinstance(packet_info.get('src_port'), int) else 0,
            packet_info.get('dst_port', 0) if isinstance(packet_info.get('dst_port'), int) else 0,
            timestamp % 86400,  # Time of day
            (timestamp % 604800) / 86400,  # Day of week
            0,  # Placeholder for flow metrics
            0   # Placeholder for rate metrics
        ]
        return features
    
    def get_statistics(self) -> Dict:
        """Get statistics from all components"""
        return {
            'incident_response': self.incident_response.get_response_summary(),
            'zero_day_incidents': len(self.zero_day_detector.zero_day_incidents),
            'threat_intel': self.threat_intel_feeds.get_statistics(),
            'continuous_learning': self.continuous_learning.get_statistics(),
            'alerts_sent': len(self.alerting_system.alert_history)
        }
    
    def update_threat_intel(self):
        """Update threat intelligence feeds"""
        return self.threat_intel_feeds.update_feeds()
    
    def cleanup(self):
        """Cleanup resources"""
        # Cleanup expired blocks
        self.incident_response.cleanup_expired_blocks()
        
        # Stop continuous learning
        self.continuous_learning.stop_continuous_retraining()

