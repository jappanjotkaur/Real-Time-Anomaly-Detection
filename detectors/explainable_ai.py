"""
Explainable AI Module
Provides human-readable explanations for anomaly detections
"""

from typing import Dict, List, Tuple
from collections import defaultdict


class ExplainableAI:
    """Generates explanations for anomaly detections"""
    
    def __init__(self):
        self.explanation_templates = {
            'packet_size': "Packet size is {deviation:.1f}% {direction} the normal range",
            'packet_rate': "Packet rate is {rate:.1f}x {direction} the baseline",
            'protocol': "Unusual protocol usage: {protocol} is rarely used by this device",
            'port': "Unusual port activity: port {port} is not typically used",
            'destination': "New or rare destination: {destination}",
            'temporal': "Activity at unusual time: {time}",
            'behavioral': "Behavioral deviation detected: {reason}",
            'attack': "Attack pattern detected: {attack_type}",
            'threat_intel': "Threat intelligence match: {reason}",
            'tls': "TLS/SSL anomaly: {reason}"
        }
    
    def explain_anomaly(self, packet_info: Dict, anomaly_scores: Dict, 
                       explanations: List[str] = None) -> Dict:
        """
        Generate comprehensive explanation for an anomaly
        Args:
            packet_info: Packet information
            anomaly_scores: Dictionary of scores from different detectors
            explanations: List of explanation strings from detectors
        Returns:
            Explanation dictionary with human-readable text and technical details
        """
        explanation = {
            'is_anomalous': False,
            'overall_score': 0.0,
            'confidence': 0.0,
            'primary_reasons': [],
            'detailed_explanations': [],
            'recommendations': [],
            'severity': 'low'
        }
        
        # Calculate overall score
        scores = [score for score in anomaly_scores.values() if isinstance(score, (int, float))]
        if scores:
            explanation['overall_score'] = max(scores)
            explanation['is_anomalous'] = explanation['overall_score'] > 3.0
        
        # Determine severity
        if explanation['overall_score'] >= 8.0:
            explanation['severity'] = 'critical'
        elif explanation['overall_score'] >= 6.0:
            explanation['severity'] = 'high'
        elif explanation['overall_score'] >= 4.0:
            explanation['severity'] = 'medium'
        else:
            explanation['severity'] = 'low'
        
        # Calculate confidence based on number of detectors agreeing
        agreeing_detectors = sum(1 for score in scores if score > 3.0)
        total_detectors = len(scores)
        if total_detectors > 0:
            explanation['confidence'] = (agreeing_detectors / total_detectors) * 100
        
        # Collect explanations
        if explanations:
            explanation['primary_reasons'] = explanations[:5]  # Top 5 reasons
            explanation['detailed_explanations'] = explanations
        
        # Generate human-readable summary
        summary_parts = []
        if explanation['is_anomalous']:
            summary_parts.append(f"Anomaly detected with {explanation['severity']} severity")
            summary_parts.append(f"(Score: {explanation['overall_score']:.1f}/10, Confidence: {explanation['confidence']:.0f}%)")
            
            if explanations:
                summary_parts.append("\nKey indicators:")
                for i, reason in enumerate(explanations[:3], 1):
                    summary_parts.append(f"  {i}. {reason}")
        else:
            summary_parts.append("No significant anomalies detected")
        
        explanation['summary'] = "\n".join(summary_parts)
        
        # Generate recommendations
        explanation['recommendations'] = self._generate_recommendations(
            packet_info, anomaly_scores, explanation['severity']
        )
        
        # Add packet context
        explanation['packet_context'] = {
            'src_ip': packet_info.get('src_ip', 'Unknown'),
            'dst_ip': packet_info.get('dst_ip', 'Unknown'),
            'protocol': packet_info.get('protocol', 'Unknown'),
            'src_port': packet_info.get('src_port', 'N/A'),
            'dst_port': packet_info.get('dst_port', 'N/A'),
            'size': packet_info.get('size', 0)
        }
        
        return explanation
    
    def _generate_recommendations(self, packet_info: Dict, 
                                 anomaly_scores: Dict, severity: str) -> List[str]:
        """Generate actionable recommendations based on anomaly"""
        recommendations = []
        
        src_ip = packet_info.get('src_ip', 'Unknown')
        dst_ip = packet_info.get('dst_ip', 'Unknown')
        protocol = packet_info.get('protocol', 'Unknown')
        
        if severity == 'critical':
            recommendations.append(f"Immediate action required: Block {src_ip} if not authorized")
            recommendations.append("Review firewall rules and network segmentation")
            recommendations.append("Check for data exfiltration or unauthorized access")
        elif severity == 'high':
            recommendations.append(f"Investigate {src_ip} for suspicious activity")
            recommendations.append("Review recent logs for related events")
            recommendations.append("Consider temporarily blocking the source IP")
        elif severity == 'medium':
            recommendations.append(f"Monitor {src_ip} for continued suspicious activity")
            recommendations.append("Review device behavior profile")
            recommendations.append("Check if this is expected behavior for this device")
        else:
            recommendations.append("Continue monitoring for pattern changes")
            recommendations.append("Review if this is expected network activity")
        
        # Protocol-specific recommendations
        if protocol in ['TCP', 'UDP']:
            if anomaly_scores.get('attack_pattern', 0) > 5:
                recommendations.append("Investigate for potential network scanning or attack")
        
        if protocol == 'ICMP' and anomaly_scores.get('attack_pattern', 0) > 5:
            recommendations.append("Check for ICMP flood or ping sweep attack")
        
        # TLS-specific recommendations
        if protocol == 'HTTPS' and anomaly_scores.get('tls', 0) > 3:
            recommendations.append("Review TLS/SSL configuration and certificate validity")
            recommendations.append("Check for man-in-the-middle attacks or malicious certificates")
        
        return recommendations
    
    def format_explanation_for_display(self, explanation: Dict) -> str:
        """Format explanation for display in UI"""
        lines = []
        
        lines.append("=" * 60)
        lines.append("ANOMALY EXPLANATION")
        lines.append("=" * 60)
        lines.append("")
        
        # Severity indicator
        severity_icons = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢'
        }
        icon = severity_icons.get(explanation['severity'], '⚪')
        lines.append(f"Severity: {icon} {explanation['severity'].upper()}")
        lines.append(f"Score: {explanation['overall_score']:.1f}/10")
        lines.append(f"Confidence: {explanation['confidence']:.0f}%")
        lines.append("")
        
        # Packet context
        ctx = explanation['packet_context']
        lines.append("Packet Information:")
        lines.append(f"  Source: {ctx['src_ip']}:{ctx['src_port']}")
        lines.append(f"  Destination: {ctx['dst_ip']}:{ctx['dst_port']}")
        lines.append(f"  Protocol: {ctx['protocol']}")
        lines.append(f"  Size: {ctx['size']} bytes")
        lines.append("")
        
        # Primary reasons
        if explanation['primary_reasons']:
            lines.append("Key Indicators:")
            for i, reason in enumerate(explanation['primary_reasons'], 1):
                lines.append(f"  {i}. {reason}")
            lines.append("")
        
        # Recommendations
        if explanation['recommendations']:
            lines.append("Recommendations:")
            for i, rec in enumerate(explanation['recommendations'], 1):
                lines.append(f"  {i}. {rec}")
            lines.append("")
        
        lines.append("=" * 60)
        
        return "\n".join(lines)

