import time
import sys
from collections import defaultdict
from utils.packet_parser import PacketParser
from utils.pcap_handler import PCAPHandler
from models.anomaly_detector import EnhancedAnomalyDetection
from analyzer.visualizer import PacketVisualizer
from config import *

# Import Scapy for Windows compatibility
try:
    from scapy.all import sniff, AsyncSniffer, get_if_list
    import threading
except ImportError:
    print("[!] Scapy is not installed. Please install it with: pip install scapy")
    sys.exit(1)

class PacketSniffer:
    def __init__(self, interface=DEFAULT_INTERFACE, output_dir=DEFAULT_OUTPUT_DIR, model_path=DEFAULT_MODEL_PATH, filter_exp=None, use_web=False, web_callback=None, alert_callback=None):
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
        
        # Test interface availability - only if interface is provided
        if interface:
            try:
                available_interfaces = get_if_list()
                if interface not in available_interfaces:
                    print(f"[!] Interface '{interface}' not found in available interfaces:")
                    for i, iface in enumerate(available_interfaces):
                        print(f"    {i}: {iface}")
                    print(f"[!] Using first available interface: {available_interfaces[0]}")
                    self.interface = available_interfaces[0]
                
                print(f"[+] Using interface: {self.interface}")
                
                # Print filter information
                if self.filter_exp:
                    print(f"[+] Filter applied: {self.filter_exp}")
                else:
                    print(f"[+] No filter applied (capturing all traffic)")
                    
            except Exception as e:
                print(f"[!] Error initializing interface: {e}")
                sys.exit(1)
        else:
            print(f"[+] Using default interface (auto-detected by Scapy)")

        # Initialize visualizer
        self.visualizer = PacketVisualizer()

        # Initialize anomaly detection model
        self.anomaly_detector = EnhancedAnomalyDetection(model_path=model_path)    

        # Store packet data for training
        self.feature_vectors = []
        self.flow_anomalies = defaultdict(int)
        
        # Threading for packet capture
        self.capture_thread = None
            
    def detect_anomaly(self, packet_info, timestamp):
        """Detect anomalies in packets"""
        try:
            # Extract features from packet
            features, flow_key = self.anomaly_detector.extract_features(packet_info, timestamp)
            self.feature_vectors.append(features)

            # Predict anomaly
            is_anomaly, score = self.anomaly_detector.predict(features)

            # Update flow anomaly statistics
            if is_anomaly == -1:
                self.flow_anomalies[flow_key] += 1

            # Determine flow danger level
            flow_score = 0
            if flow_key in self.flow_anomalies:
                flow_score = self.flow_anomalies[flow_key]
            
            return is_anomaly, score, flow_score
        except Exception as e:
            print(f"[!] Error in anomaly detection: {e}")
            return 0, 0.0, 0

    def packet_handler(self, packet):
        """Handle each captured packet"""
        try:
            self.packet_id += 1
            timestamp = time.time()
            
            # Debug: Print that we received a packet
            if self.packet_id <= 10:  # Increased from 5 to 10
                print(f"[DEBUG] Received packet {self.packet_id}")
            
            # Convert Scapy packet to raw bytes for compatibility with existing parser
            raw_packet = bytes(packet)
            
            # Save packet to PCAP file
            self.pcap_handler.save_packet_to_pcap(timestamp, raw_packet)
            
            # Parse packet
            packet_info = self.packet_parser.parse_packet(raw_packet)
            
            # Skip if packet parsing failed
            if not packet_info:
                if self.packet_id <= 10:
                    print(f"[DEBUG] Packet {self.packet_id} parsing failed - returned None")
                return
            
            # Process all packets - don't skip non-IP packets
            # They might still be useful for analysis (ARP, etc.)
            if packet_info.get('src_ip') == 'Unknown' and packet_info.get('dst_ip') == 'Unknown':
                if self.packet_id <= 10:
                    print(f"[DEBUG] Packet {self.packet_id} is non-IP: {packet_info.get('protocol', 'Unknown')}")
                # Continue processing - don't skip
            
            # Debug: Print packet info for first few packets
            if self.packet_id <= 10:  # Increased from 3 to 10
                print(f"[DEBUG] Packet {self.packet_id} parsed: {packet_info.get('protocol', 'Unknown')} "
                      f"{packet_info.get('src_ip', 'N/A')} -> {packet_info.get('dst_ip', 'N/A')} "
                      f"(Size: {packet_info.get('size', 0)} bytes)")
            
            # Detect anomalies
            is_anomaly, anomaly_score, flow_score = self.detect_anomaly(packet_info, timestamp)
            
            # Add packet to visualizer
            self.visualizer.add_packet(packet_info, (is_anomaly, anomaly_score, flow_score))
            
            # Send to web dashboard if enabled
            if self.use_web and self.web_callback:
                try:
                    self.web_callback(packet_info, (is_anomaly, anomaly_score, flow_score))
                    if self.packet_id <= 3:
                        print(f"[DEBUG] Sent packet {self.packet_id} to web dashboard")
                except Exception as e:
                    print(f"[!] Error sending packet to web dashboard: {e}")
                    if self.packet_id <= 3:
                        import traceback
                        traceback.print_exc()
            
            # Update display every 5 packets to reduce flickering
            if self.packet_id % 5 == 0:
                self.visualizer.update_display()
            
            # Show alerts for dangerous flows
            if flow_score >= 5:
                alert_msg = (f"Extended anomalous flow detected! "
                        f"({packet_info.get('src_ip', 'N/A')}:{packet_info.get('src_port', 'N/A')} -> "
                        f"{packet_info.get('dst_ip', 'N/A')}:{packet_info.get('dst_port', 'N/A')} "
                        f"[{packet_info.get('protocol', 'N/A')}])")
                self.visualizer.print_alert(alert_msg)
                
                # Send alert to web dashboard if enabled
                if self.use_web and self.alert_callback:
                    try:
                        self.alert_callback(alert_msg)
                    except Exception as e:
                        pass  # Silently fail if alert callback has issues
            
            # Update model periodically
            if self.packet_id % 100 == 0 and len(self.feature_vectors) >= 100:
                try:
                    if self.anomaly_detector.fit(self.feature_vectors[-1000:]):
                        print(f"[+] Updated anomaly detection model with {len(self.feature_vectors[-1000:])} samples")
                        # Save model
                        self.anomaly_detector.save_model()
                except Exception as e:
                    print(f"[!] Error updating model: {e}")
            
        except Exception as e:
            print(f"[!] Error processing packet {self.packet_id}: {e}")
            import traceback
            traceback.print_exc()

    def start_sniffing(self, max_packets=None):
        """Start packet capture and analysis"""
        self.visualizer.update_display()
        print(f"[+] Starting packet capture... Press Ctrl+C to stop")
        
        try:
            # Prepare sniff parameters
            sniff_params = {
                'prn': self.packet_handler,
                'store': False,  # Don't store packets in memory
                'timeout': 5,    # 5 second timeout for better responsiveness
                'stop_filter': lambda x: self.stop_sniffing,  # Stop condition
            }
            
            # Only specify interface if provided
            if self.interface:
                sniff_params['iface'] = self.interface
                print(f"[+] Capturing on interface: {self.interface}")
            else:
                print(f"[+] Capturing on default interface (auto-detected)")
            
            # Add filter if specified
            if self.filter_exp:
                sniff_params['filter'] = self.filter_exp
            
            # Add packet count if specified
            if max_packets:
                print(f"[+] Will capture maximum {max_packets} packets")
            
            # Start packet capture
            packets_captured = 0
            start_time = time.time()
            
            while not self.stop_sniffing:
                try:
                    # Calculate remaining packets
                    if max_packets:
                        remaining = max_packets - packets_captured
                        if remaining <= 0:
                            print(f"[+] Reached maximum packet count ({max_packets}). Stopping capture.")
                            break
                        
                        # Capture in smaller batches
                        batch_size = min(10, remaining)
                        temp_params = sniff_params.copy()
                        temp_params['count'] = batch_size
                    else:
                        # Capture in batches of 10 for unlimited mode
                        temp_params = sniff_params.copy()
                        temp_params['count'] = 10
                    
                    # Capture packets
                    old_packet_count = self.packet_id
                    sniff(**temp_params)
                    new_packets = self.packet_id - old_packet_count
                    packets_captured += new_packets
                    
                    # Check if we're actually capturing packets
                    current_time = time.time()
                    elapsed = current_time - start_time
                    if elapsed > 10 and self.packet_id == 0:
                        print(f"\n[!] WARNING: No packets captured after {int(elapsed)} seconds!")
                        print(f"[!] This might indicate:")
                        print(f"    1. Wrong network interface selected")
                        print(f"    2. No network traffic on this interface") 
                        print(f"    3. Firewall blocking packet capture")
                        print(f"    4. Need to install/update Npcap (Windows)")
                        print(f"    5. Need administrator/root privileges")
                        print(f"\n[!] Troubleshooting:")
                        print(f"    - Run as Administrator (Windows) or with sudo (Linux)")
                        print(f"    - Try: python test_packet_capture.py")
                        print(f"    - Generate network traffic (browse web, ping 8.8.8.8)")
                        print(f"    - Select a different network interface")
                        print(f"    - Check if Npcap is installed: https://nmap.org/npcap/\n")
                    elif elapsed > 5 and self.packet_id < 5:
                        print(f"[!] Very few packets ({self.packet_id}) captured. Generate more network traffic.")
                        
                    # Small delay to prevent high CPU usage
                    time.sleep(0.1)
                        
                except KeyboardInterrupt:
                    self.stop_sniffing = True
                    break
                except Exception as e:
                    print(f"[!] Error in packet capture batch: {e}")
                    time.sleep(1)  # Brief pause before retrying
            
        except KeyboardInterrupt:
            print("\n[!] Packet capture stopped by user")
        except Exception as e:
            print(f"\n[!] Error during packet capture: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.stop_capture()

    def stop_capture(self):
        """Clean up and save data when stopping"""
        self.stop_sniffing = True
        
        try:
            # Save model before exiting
            if self.feature_vectors and len(self.feature_vectors) > 100:
                try:
                    self.anomaly_detector.save_model()
                    print("[+] Anomaly detection model saved")
                except Exception as e:
                    print(f"[!] Error saving model: {e}")
            
            # Close PCAP file
            try:
                pcap_file = self.pcap_handler.close()
                if pcap_file:
                    print(f"[+] Closed PCAP file: {pcap_file}")
            except Exception as e:
                print(f"[!] Error closing PCAP file: {e}")
            
            # Show summary
            try:
                self.visualizer.show_summary()
            except Exception as e:
                print(f"[!] Error showing summary: {e}")
            
            print(f"[+] Total packets captured: {self.packet_id}")
            
        except Exception as e:
            print(f"[!] Error during cleanup: {e}")

    def start_async_sniffing(self, max_packets=None):
        """Start asynchronous packet capture (alternative method)"""
        try:
            # Create async sniffer
            sniffer_params = {
                'prn': self.packet_handler,
                'store': False,
            }
            
            if self.interface:
                sniffer_params['iface'] = self.interface
            
            if self.filter_exp:
                sniffer_params['filter'] = self.filter_exp
            
            if max_packets:
                sniffer_params['count'] = max_packets
            
            self.async_sniffer = AsyncSniffer(**sniffer_params)
            
            # Start capture
            self.async_sniffer.start()
            
            print(f"[+] Async packet capture started")
            print("[+] Press Ctrl+C to stop...")
            
            # Keep main thread alive
            try:
                start_time = time.time()
                while True:
                    time.sleep(1)
                    
                    # Check progress
                    current_time = time.time()
                    if current_time - start_time > 10 and self.packet_id == 0:
                        print(f"[!] No packets captured in 10 seconds using async method")
                        print(f"[!] Try the regular sniffing method or check network activity")
                    
                    if max_packets and self.packet_id >= max_packets:
                        break
            except KeyboardInterrupt:
                print("\n[!] Stopping async capture...")
            
            # Stop async sniffer
            self.async_sniffer.stop()
            
        except Exception as e:
            print(f"[!] Error in async sniffing: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.stop_capture()