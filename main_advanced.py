"""
NetSniff Guard - Advanced Edition
Main entry point with all advanced features enabled
"""

import os
import sys
import threading
import time
from colorama import init, Fore
from analyzer.packet_sniffer import PacketSniffer
from config_advanced import ADVANCED_CONFIG
from detectors.advanced_integration import AdvancedDetectionEngine

# Import Scapy for Windows compatibility
try:
    from scapy.all import get_if_list
except ImportError:
    print(Fore.RED + "[!] Scapy is not installed. Please install it with: pip install scapy")
    sys.exit(1)

# Import web app
try:
    from web_app import add_packet, add_alert, run_web_server
    WEB_ENABLED = True
except ImportError:
    WEB_ENABLED = False
    print(Fore.YELLOW + "[!] Web dashboard dependencies not installed. Running in terminal mode only.")

init(autoreset=True)


def get_network_interfaces():
    """Get available network interfaces using Scapy"""
    try:
        interfaces = get_if_list()
        return interfaces
    except Exception as e:
        print(Fore.RED + f"[!] Error getting network interfaces: {e}")
        return []


def select_best_interface(devices):
    """Try to automatically select the best network interface"""
    if not devices:
        return None
    
    from scapy.all import get_if_addr, conf
    
    # First try Scapy's default interface
    try:
        default_iface = conf.iface
        if default_iface in devices:
            ip = get_if_addr(default_iface)
            if ip and ip != '0.0.0.0' and "Loopback" not in default_iface:
                print(Fore.GREEN + f"[+] Auto-selected default interface: {default_iface} (IP: {ip})")
                return default_iface
    except:
        pass
    
    # Helper function to check if IP is private
    def is_private_ip(ip):
        if not ip or ip == '0.0.0.0':
            return False
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            first = int(parts[0])
            second = int(parts[1])
            # 10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12
            return (first == 10) or (first == 192 and second == 168) or (first == 172 and 16 <= second <= 31)
        except:
            return False
    
    # Priority 1: Try to find interface with private IP (most likely to have traffic)
    for i, device in enumerate(devices):
        if "Loopback" not in device:
            try:
                ip = get_if_addr(device)
                if ip and is_private_ip(ip):
                    print(Fore.GREEN + f"[+] Auto-selected interface {i}: {device} (IP: {ip}) - Private network")
                    return device
            except:
                pass
    
    # Priority 2: Try to find interface with valid IP (not link-local, not loopback)
    for i, device in enumerate(devices):
        if "Loopback" not in device:
            try:
                ip = get_if_addr(device)
                if ip and ip != '0.0.0.0' and not ip.startswith('169.254') and not ip.startswith('127.'):
                    print(Fore.GREEN + f"[+] Auto-selected interface {i}: {device} (IP: {ip})")
                    return device
            except:
                pass
    
    # Fallback
    for device in devices:
        if "Loopback" not in device:
            print(Fore.YELLOW + f"[+] Auto-selected first non-loopback interface: {device}")
            return device
    
    return devices[0] if devices else None


class AdvancedPacketSniffer(PacketSniffer):
    """Enhanced packet sniffer with advanced detection"""
    
    def __init__(self, interface, output_dir, model_path, filter_exp=None, 
                 use_web=False, web_callback=None, alert_callback=None):
        # Initialize base sniffer
        super().__init__(interface, output_dir, model_path, filter_exp, 
                        use_web, web_callback, alert_callback)
        
        # Initialize advanced detection engine
        print(Fore.CYAN + "\n[+] Initializing Advanced Detection Engine...")
        self.advanced_engine = AdvancedDetectionEngine(ADVANCED_CONFIG)
        
        # Override detect_anomaly to use advanced engine
        self.original_detect_anomaly = super().detect_anomaly
    
    def detect_anomaly(self, packet_info, timestamp):
        """Enhanced anomaly detection with advanced features"""
        # Get base ML anomaly detection
        is_anomaly, ml_score, flow_score = self.original_detect_anomaly(packet_info, timestamp)
        
        # Run advanced analysis
        try:
            advanced_result = self.advanced_engine.analyze_packet(
                packet_info, timestamp, abs(ml_score) if ml_score else 0.0
            )
            
            # Update flow score based on advanced analysis
            if advanced_result.get('overall_severity', 0) > flow_score:
                flow_score = advanced_result['overall_severity']
            
            # Update anomaly flag based on advanced analysis
            if advanced_result.get('overall_severity', 0) >= 4.0:
                is_anomaly = -1
            
            # Send alerts if configured
            if self.alert_callback and advanced_result.get('alert_sent'):
                alert_msg = f"⚠️  {advanced_result.get('explanations', {}).get('summary', 'Threat detected')}"
                self.alert_callback(alert_msg)
            
            # Enhanced packet info for web dashboard
            if self.web_callback:
                enhanced_info = packet_info.copy()
                enhanced_info['advanced_analysis'] = {
                    'severity': advanced_result.get('overall_severity', 0),
                    'threat_types': [t.get('type') for t in advanced_result.get('threats', [])],
                    'zero_day': any(t.get('type') == 'zero_day' for t in advanced_result.get('threats', [])),
                    'actions_taken': [a.get('action') for a in advanced_result.get('actions_taken', [])]
                }
                
                # Use enhanced info with advanced scores
                anomaly_info = (is_anomaly, advanced_result.get('overall_severity', ml_score), flow_score)
                self.web_callback(enhanced_info, anomaly_info)
                return is_anomaly, advanced_result.get('overall_severity', ml_score), flow_score
        
        except Exception as e:
            print(Fore.RED + f"[!] Error in advanced detection: {e}")
            import traceback
            traceback.print_exc()
        
        return is_anomaly, ml_score, flow_score


def main():
    print(Fore.CYAN + "=" * 70)
    print(Fore.CYAN + "     NETSNIFF GUARD - ADVANCED EDITION")
    print(Fore.CYAN + "     Network Traffic Anomaly Detection with AI")
    print(Fore.CYAN + "=" * 70)
    
    # Show advanced features
    print(Fore.GREEN + "\n[+] Advanced Features Enabled:")
    print(Fore.GREEN + "  • Zero-Day Attack Detection")
    print(Fore.GREEN + "  • Automated Incident Response")
    print(Fore.GREEN + "  • Threat Intelligence Integration")
    print(Fore.GREEN + "  • Multi-Channel Alerting")
    print(Fore.GREEN + "  • Continuous Learning Pipeline")
    print(Fore.GREEN + "  • Explainable AI")
    
    # Ask if user wants to use web interface
    use_web = False
    if WEB_ENABLED:
        web_choice = input(Fore.YELLOW + "\nDo you want to use the web dashboard? (y/n): ").lower()
        use_web = (web_choice == 'y')
        
        if use_web:
            # Start web server in background thread
            web_thread = threading.Thread(target=run_web_server, 
                                        kwargs={'host': '127.0.0.1', 'port': 5000}, 
                                        daemon=True)
            web_thread.start()
            print(Fore.GREEN + "[+] Web dashboard starting...")
            print(Fore.GREEN + "[+] Open your browser to: http://127.0.0.1:5000")
            time.sleep(2)
    
    # Get network interfaces
    try:
        devices = get_network_interfaces()
        if not devices:
            print(Fore.RED + "[!] No network interfaces found.")
            print(Fore.YELLOW + "[!] Make sure Npcap is installed and you're running as Administrator.")
            sys.exit(1)
        
        # Auto-select interface
        auto_choice = input(Fore.YELLOW + "\nUse automatic interface detection? (recommended) (y/n): ").lower()
        
        if auto_choice == 'y':
            interface = select_best_interface(devices)
            if not interface:
                print(Fore.RED + "[!] Could not auto-select interface. Falling back to manual selection.")
                auto_choice = 'n'
            else:
                print(Fore.GREEN + "[+] Using automatic interface detection")
        
        if auto_choice == 'n':
            # Manual selection
            from scapy.all import get_if_addr
            print(Fore.CYAN + "\nAvailable network interfaces:")
            for i, device in enumerate(devices):
                try:
                    ip = get_if_addr(device)
                    if ip and ip != '0.0.0.0':
                        print(Fore.GREEN + f"{i}: {device} (IP: {ip})")
                    else:
                        print(Fore.YELLOW + f"{i}: {device} (No IP)")
                except:
                    print(Fore.YELLOW + f"{i}: {device}")
            
            while True:
                try:
                    choice = input(Fore.YELLOW + "\nSelect interface number for packet capture: ")
                    device_index = int(choice)
                    if 0 <= device_index < len(devices):
                        interface = devices[device_index]
                        print(Fore.GREEN + f"[+] Selected interface: {interface}")
                        break
                    else:
                        print(Fore.RED + f"[!] Invalid number. Please choose from 0 to {len(devices)-1}.")
                except ValueError:
                    print(Fore.RED + "[!] Please enter a number.")
        
        # Configuration
        from config import DEFAULT_OUTPUT_DIR, DEFAULT_MODEL_PATH
        
        filter_exp = input(Fore.YELLOW + "\nEnter BPF filter (leave empty if not needed): ")
        
        count_input = input(Fore.YELLOW + "\nEnter maximum number of packets to capture (Enter for unlimited): ")
        count = int(count_input) if count_input.strip() else None
        
        output_dir = input(Fore.YELLOW + f"\nEnter directory to save PCAP files (Enter for default {DEFAULT_OUTPUT_DIR}): ")
        if not output_dir:
            output_dir = DEFAULT_OUTPUT_DIR
        
        model_path = input(Fore.YELLOW + f"\nEnter path to model file (Enter for default {DEFAULT_MODEL_PATH}): ")
        if not model_path:
            model_path = DEFAULT_MODEL_PATH
        
        print(Fore.CYAN + "\n" + "=" * 70)
        print(Fore.CYAN + f"[+] Using interface: {interface}")
        if filter_exp:
            print(Fore.CYAN + f"[+] Applying filter: {filter_exp}")
        if count:
            print(Fore.CYAN + f"[+] Maximum packets: {count}")
        print(Fore.CYAN + f"[+] PCAP output directory: {output_dir}")
        print(Fore.CYAN + f"[+] Model file: {model_path}")
        if use_web:
            print(Fore.GREEN + f"[+] Web dashboard: http://127.0.0.1:5000")
        print(Fore.CYAN + "=" * 70)
        
        # Confirm before starting
        confirm = input(Fore.YELLOW + "\nStart advanced packet capture? (y/n): ").lower()
        if confirm != 'y':
            print(Fore.RED + "[!] Packet capture cancelled.")
            sys.exit(0)
        
        # Initialize Advanced Packet Sniffer
        sniffer = AdvancedPacketSniffer(
            interface=interface,
            output_dir=output_dir,
            model_path=model_path,
            filter_exp=filter_exp,
            use_web=use_web,
            web_callback=add_packet if use_web else None,
            alert_callback=add_alert if use_web else None
        )
        
        print(Fore.GREEN + "\n[+] Starting advanced packet capture... Press Ctrl+C to stop")
        if use_web:
            print(Fore.GREEN + "[+] View real-time dashboard at: http://127.0.0.1:5000")
        
        sniffer.start_sniffing(max_packets=count)
        
        # Print statistics
        if hasattr(sniffer, 'advanced_engine'):
            stats = sniffer.advanced_engine.get_statistics()
            print(Fore.CYAN + "\n[+] Advanced Detection Statistics:")
            print(f"    Zero-day incidents: {stats.get('zero_day_incidents', 0)}")
            print(f"    Threat intel IOCs: {stats.get('threat_intel', {}).get('malicious_ips', 0)} IPs, "
                  f"{stats.get('threat_intel', {}).get('malicious_domains', 0)} domains")
            print(f"    Alerts sent: {stats.get('alerts_sent', 0)}")
            print(f"    Response actions: {stats.get('incident_response', {}).get('total_responses', 0)}")
        
        # If using web dashboard, keep it running
        if use_web:
            print(Fore.GREEN + "\n[+] Packet capture complete!")
            print(Fore.GREEN + "[+] Web dashboard is still running at: http://127.0.0.1:5000")
            print(Fore.YELLOW + "[+] Press Ctrl+C to stop the web server and exit")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print(Fore.YELLOW + "\n[!] Shutting down...")
                if hasattr(sniffer, 'advanced_engine'):
                    sniffer.advanced_engine.cleanup()
    
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Packet capture stopped by user request.")
    except Exception as e:
        print(Fore.RED + f"\n[!] Unhandled error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()

