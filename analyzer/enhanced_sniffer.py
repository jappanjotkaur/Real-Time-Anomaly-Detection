"""
Enhanced Packet Sniffer with Advanced Detection Capabilities
Integrates all advanced detectors: behavioral profiling, TLS fingerprinting,
attack pattern detection, threat correlation, explainable AI, and topology building
"""

import time
import sys
from collections import defaultdict
from utils.packet_parser import PacketParser
from utils.pcap_handler import PCAPHandler
from models.anomaly_detector import EnhancedAnomalyDetection
from analyzer.visualizer import PacketVisualizer
from config import *

# Advanced detectors
from detectors.behavioral_profiler import BehavioralProfiler
from detectors.tls_fingerprinting import TLSFingerprinter
from detectors.attack_pattern_detector import AttackPatternDetector
from detectors.threat_correlation import ThreatCorrelationEngine
from detectors.explainable_ai import ExplainableAI
from detectors.network_topology import NetworkTopologyBuilder
from detectors.threat_intelligence import ThreatIntelligence

# Import Scapy for packet capture
try:
    from scapy.all import sniff, get_if_list
except ImportError:
    print("[!] Scapy is not installed. Please install it with: pip install scapy")
    sys.exit(1)


class EnhancedPacketSniffer:
    """Enhanced packet sniffer with advanced detection capabilities"""
    
    def __init__(self, interface=DEFAULT_INTERFACE, output_dir=DEFAULT_OUTPUT_DIR, 
                 model_path=DEFAULT_MODEL_PATH, filter_exp=None, use_web=False, 
                 web_callback=None, alert_callback=None):
        # Initialize components
        self.interface = interface
        self.packet_id = 0
        self.filter_exp = filter_exp
        self.stop_sniffing = False
        self.use_web = use_web
        self.web_callback = web_callback
        self.alert_callback = alert_callback
        
        # Initialize PCAP file handler
        self.pcap_handler = PCAPHandler(output_dir=output_dir)
        
        # Initialize packet parser
        self.packet_parser = PacketParser()
        
        # Initialize visualizer
        self.visualizer = PacketVisualizer()
        
        # Initialize anomaly detection model
        self.anomaly_detector = EnhancedAnomalyDetection(model_path=model_path)
        
        # Initialize advanced detectors
        print("[+] Initializing advanced detection systems...")
        self.behavioral_profiler = BehavioralProfiler()
        print("  [✓] Behavioral Profiler initialized")
        
        self.tls_fingerprinter = TLSFingerprinter()
        print("  [✓] TLS Fingerprinter initialized")
        
        self.attack_detector = AttackPatternDetector()
        print("  [✓] Attack Pattern Detector initialized")
        
        self.threat_correlator = ThreatCorrelationEngine()
        print("  [✓] Threat Correlation Engine initialized")
        
        self.explainable_ai = ExplainableAI()
        print("  [✓] Explainable AI initialized")
        
        self.topology_builder = NetworkTopologyBuilder()
        print("  [✓] Network Topology Builder initialized")
        
        self.threat_intel = ThreatIntelligence()
        print("  [✓] Threat Intelligence initialized")
        
        # Store packet data for training
        self.feature_vectors = []
        self.flow_anomalies = defaultdict(int)
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'anomaly_packets': 0,
            'attack_patterns': 0,
            'correlated_incidents': 0,
            'tls_fingerprints': 0
        }
        
        print("[+] Enhanced detection system ready!")
    
    def detect_anomaly(self, packet_info, timestamp):
        """Enhanced anomaly detection using multiple detectors"""
        anomaly_scores = {}
        explanations = []
        
        # 1. ML-based anomaly detection
        try:
            features, flow_key = self.anomaly_detector.extract_features(packet_info, timestamp)
            self.feature_vectors.append(features)
            
            is_anomaly, ml_score = self.anomaly_detector.predict(features)
            if is_anomaly == -1:
                anomaly_scores['ml'] = abs(ml_score)
                explanations.append(f"ML anomaly score: {abs(ml_score):.2f}")
        except Exception as e:
            anomaly_scores['ml'] = 0.0
        
        # 2. Behavioral profiling
        try:
            self.behavioral_profiler.update_device_profile(packet_info, timestamp)
            behavioral_score, behavioral_reasons = self.behavioral_profiler.get_behavioral_anomaly_score(
                packet_info, timestamp
            )
            if behavioral_score > 0:
                anomaly_scores['behavioral'] = behavioral_score
                explanations.extend(behavioral_reasons)
        except Exception as e:
            anomaly_scores['behavioral'] = 0.0
        
        # 3. TLS fingerprinting (for HTTPS/TLS traffic)
        try:
            if packet_info.get('protocol') == 'TCP' and packet_info.get('app_proto') in ['HTTPS', 'TLS']:
                raw_packet = bytes(packet_info.get('raw_data', b''))
                if len(raw_packet) > 0:
                    src_ip = packet_info.get('src_ip', 'Unknown')
                    dst_ip = packet_info.get('dst_ip', 'Unknown')
                    src_port = int(packet_info.get('src_port', 0)) if packet_info.get('src_port') != 'N/A' else 0
                    dst_port = int(packet_info.get('dst_port', 0)) if packet_info.get('dst_port') != 'N/A' else 0
                    
                    tls_fingerprint = self.tls_fingerprinter.extract_tls_fingerprint(
                        raw_packet, src_ip, dst_ip, src_port, dst_port
                    )
                    if tls_fingerprint:
                        tls_fingerprint['timestamp'] = timestamp
                        tls_score, tls_reasons = self.tls_fingerprinter.analyze_tls_anomaly(tls_fingerprint)
                        if tls_score > 0:
                            anomaly_scores['tls'] = tls_score
                            explanations.extend(tls_reasons)
                            self.stats['tls_fingerprints'] += 1
        except Exception as e:
            pass
        
        # 4. Attack pattern detection
        try:
            attacks, attack_score = self.attack_detector.analyze_packet(packet_info, timestamp)
            if attack_score > 0:
                anomaly_scores['attack_pattern'] = attack_score
                for attack in attacks:
                    explanations.append(attack.get('message', ''))
                    self.stats['attack_patterns'] += 1
                    
                    # Add to threat correlator
                    self.threat_correlator.add_event(attack['attack_type'], {
                        'src_ip': packet_info.get('src_ip'),
                        'dst_ip': packet_info.get('dst_ip'),
                        'severity': attack.get('severity', 0),
                        **attack
                    }, timestamp)
        except Exception as e:
            anomaly_scores['attack_pattern'] = 0.0
        
        # 5. Threat intelligence
        try:
            src_ip = packet_info.get('src_ip', 'Unknown')
            dst_ip = packet_info.get('dst_ip', 'Unknown')
            dst_port = packet_info.get('dst_port', 'N/A')
            
            if src_ip != 'Unknown':
                ip_info = self.threat_intel.check_ip_reputation(src_ip)
                if ip_info.get('is_malicious') or ip_info.get('is_suspicious'):
                    threat_score = self.threat_intel.get_threat_score(ip_info=ip_info)
                    anomaly_scores['threat_intel'] = threat_score
                    explanations.extend(ip_info.get('reasons', []))
            
            # Check domain if available
            if packet_info.get('app_proto') == 'DNS':
                domain = packet_info.get('details', '').replace('Query: ', '').replace('Response: ', '')
                if domain:
                    domain_info = self.threat_intel.check_domain_reputation(domain)
                    if domain_info.get('is_malicious') or domain_info.get('is_suspicious'):
                        threat_score = self.threat_intel.get_threat_score(domain_info=domain_info)
                        anomaly_scores['threat_intel'] = max(anomaly_scores.get('threat_intel', 0), threat_score)
                        explanations.extend(domain_info.get('reasons', []))
        except Exception as e:
            pass
        
        # 6. Calculate overall anomaly score
        overall_score = max(anomaly_scores.values()) if anomaly_scores else 0.0
        
        # 7. Generate explainable AI explanation
        explanation = self.explainable_ai.explain_anomaly(
            packet_info, anomaly_scores, explanations
        )
        
        # 8. Update flow anomalies
        flow_score = 0
        if 'flow_key' in locals():
            if overall_score > 3.0:
                self.flow_anomalies[flow_key] += 1
            flow_score = self.flow_anomalies.get(flow_key, 0)
        
        # 9. Update network topology
        try:
            self.topology_builder.add_connection(
                packet_info.get('src_ip', 'Unknown'),
                packet_info.get('dst_ip', 'Unknown'),
                packet_info,
                timestamp
            )
            
            # Update node threat scores
            if overall_score > 0:
                self.topology_builder.update_node_threat_score(
                    packet_info.get('src_ip', 'Unknown'),
                    overall_score
                )
        except Exception as e:
            pass
        
        return {
            'is_anomaly': overall_score > 3.0,
            'score': overall_score,
            'flow_score': flow_score,
            'anomaly_scores': anomaly_scores,
            'explanation': explanation,
            'attacks': attacks if 'attacks' in locals() else []
        }
    
    def packet_handler(self, packet):
        """Handle each captured packet"""
        try:
            self.packet_id += 1
            timestamp = time.time()
            
            # Convert Scapy packet to raw bytes
            raw_packet = bytes(packet)
            
            # Save packet to PCAP file
            self.pcap_handler.save_packet_to_pcap(timestamp, raw_packet)
            
            # Parse packet
            packet_info = self.packet_parser.parse_packet(raw_packet)
            
            # Store raw data for TLS fingerprinting
            packet_info['raw_data'] = raw_packet
            
            if not packet_info:
                return
            
            # Skip if packet has no IP info
            if packet_info.get('src_ip') == 'Unknown' and packet_info.get('dst_ip') == 'Unknown':
                return
            
            # Enhanced anomaly detection
            detection_result = self.detect_anomaly(packet_info, timestamp)
            
            is_anomaly = detection_result['is_anomaly']
            overall_score = detection_result['score']
            flow_score = detection_result['flow_score']
            explanation = detection_result['explanation']
            attacks = detection_result.get('attacks', [])
            
            # Update statistics
            self.stats['total_packets'] += 1
            if is_anomaly:
                self.stats['anomaly_packets'] += 1
            
            # Add packet to visualizer
            self.visualizer.add_packet(
                packet_info, 
                (-1 if is_anomaly else 1, -overall_score, flow_score)
            )
            
            # Send to web dashboard if enabled
            if self.use_web and self.web_callback:
                try:
                    # Enhanced packet data for web dashboard
                    enhanced_packet_info = {
                        **packet_info,
                        'anomaly_scores': detection_result['anomaly_scores'],
                        'explanation': explanation,
                        'attacks': attacks,
                        'overall_score': overall_score
                    }
                    self.web_callback(enhanced_packet_info, (
                        -1 if is_anomaly else 1, 
                        -overall_score, 
                        flow_score
                    ))
                except Exception as e:
                    pass
            
            # Update display
            if self.packet_id % 5 == 0:
                self.visualizer.update_display()
            
            # Show alerts for high-severity anomalies
            if overall_score >= 6.0:
                severity = explanation.get('severity', 'medium')
                alert_msg = (f"[{severity.upper()}] Anomaly detected: "
                           f"{packet_info.get('src_ip', 'N/A')} -> "
                           f"{packet_info.get('dst_ip', 'N/A')} "
                           f"(Score: {overall_score:.1f}/10)")
                self.visualizer.print_alert(alert_msg)
                
                # Send alert to web dashboard
                if self.use_web and self.alert_callback:
                    try:
                        self.alert_callback(alert_msg)
                    except:
                        pass
            
            # Show attack alerts
            for attack in attacks:
                alert_msg = f"[ATTACK] {attack.get('message', 'Attack detected')}"
                self.visualizer.print_alert(alert_msg)
                
                if self.use_web and self.alert_callback:
                    try:
                        self.alert_callback(alert_msg)
                    except:
                        pass
            
            # Update model periodically
            if self.packet_id % 100 == 0 and len(self.feature_vectors) >= 100:
                try:
                    if self.anomaly_detector.fit(self.feature_vectors[-1000:]):
                        print(f"[+] Updated anomaly detection model with {len(self.feature_vectors[-1000:])} samples")
                        self.anomaly_detector.save_model()
                except Exception as e:
                    pass
            
        except Exception as e:
            pass
    
    def start_sniffing(self, max_packets=None):
        """Start packet capture and analysis"""
        self.visualizer.update_display()
        print(f"[+] Starting enhanced packet capture... Press Ctrl+C to stop")
        print(f"[+] Advanced detection systems active:")
        print(f"    - Behavioral Profiling")
        print(f"    - TLS Fingerprinting")
        print(f"    - Attack Pattern Detection")
        print(f"    - Threat Correlation")
        print(f"    - Explainable AI")
        print(f"    - Network Topology Analysis")
        print(f"    - Threat Intelligence")
        
        try:
            sniff_params = {
                'prn': self.packet_handler,
                'store': False,
                'timeout': 5,
                'stop_filter': lambda x: self.stop_sniffing,
            }
            
            if self.interface:
                sniff_params['iface'] = self.interface
            
            if self.filter_exp:
                sniff_params['filter'] = self.filter_exp
            
            while not self.stop_sniffing:
                try:
                    if max_packets:
                        remaining = max_packets - self.packet_id
                        if remaining <= 0:
                            break
                        sniff_params['count'] = min(10, remaining)
                    else:
                        sniff_params['count'] = 10
                    
                    sniff(**sniff_params)
                    time.sleep(0.1)
                    
                except KeyboardInterrupt:
                    self.stop_sniffing = True
                    break
                except Exception as e:
                    time.sleep(1)
                    
        except KeyboardInterrupt:
            print("\n[!] Packet capture stopped by user")
        except Exception as e:
            print(f"\n[!] Error during packet capture: {e}")
        finally:
            self.stop_capture()
    
    def stop_capture(self):
        """Clean up and save data when stopping"""
        self.stop_sniffing = True
        
        try:
            # Save model
            if self.feature_vectors and len(self.feature_vectors) > 100:
                self.anomaly_detector.save_model()
                print("[+] Anomaly detection model saved")
            
            # Close PCAP file
            pcap_file = self.pcap_handler.close()
            if pcap_file:
                print(f"[+] Closed PCAP file: {pcap_file}")
            
            # Show summary
            self.visualizer.show_summary()
            
            # Show advanced statistics
            print("\n[+] Advanced Detection Statistics:")
            print(f"    Total packets: {self.stats['total_packets']}")
            print(f"    Anomaly packets: {self.stats['anomaly_packets']}")
            print(f"    Attack patterns detected: {self.stats['attack_patterns']}")
            print(f"    TLS fingerprints analyzed: {self.stats['tls_fingerprints']}")
            
            # Show correlated incidents
            incidents = self.threat_correlator.get_correlated_incidents()
            if incidents:
                print(f"    Correlated incidents: {len(incidents)}")
                for incident in incidents[:5]:
                    print(f"      - {incident['incident_type']}: {incident['description']}")
            
            # Show topology summary
            topology_summary = self.topology_builder.get_topology_summary()
            if 'error' not in topology_summary:
                print(f"\n[+] Network Topology:")
                print(f"    Nodes: {topology_summary['num_nodes']}")
                print(f"    Edges: {topology_summary['num_edges']}")
                print(f"    Top connected nodes: {len(topology_summary['top_connected_nodes'])}")
            
            print(f"[+] Total packets captured: {self.packet_id}")
            
        except Exception as e:
            print(f"[!] Error during cleanup: {e}")
    
    def get_advanced_stats(self):
        """Get advanced statistics"""
        return {
            'basic_stats': self.stats,
            'topology': self.topology_builder.get_topology_summary(),
            'correlated_incidents': self.threat_correlator.get_correlated_incidents(),
            'attack_summary': self.attack_detector.get_attack_summary(),
            'behavioral_profiles': list(self.behavioral_profiler.get_all_profiles().values())[:10],
            'tls_stats': self.tls_fingerprinter.get_fingerprint_stats()
        }

