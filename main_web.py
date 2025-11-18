import os
import sys
import threading
from colorama import init, Fore
from analyzer.packet_sniffer import PacketSniffer
from analyzer.pcap_analyzer import analyze_pcap_file
from config import DEFAULT_INTERFACE, DEFAULT_OUTPUT_DIR, DEFAULT_MODEL_PATH

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
    
    # Try to find an interface with a valid IP address
    for i, device in enumerate(devices):
        if "Loopback" not in device:
            try:
                ip = get_if_addr(device)
                # Prefer non-link-local addresses (not 169.254.x.x)
                if ip and ip != '0.0.0.0' and not ip.startswith('169.254'):
                    print(Fore.GREEN + f"[+] Auto-selected interface {i}: {device} (IP: {ip})")
                    return device
            except:
                pass
    
    # Fallback: try to find any interface with an IP (including link-local)
    for i, device in enumerate(devices):
        if "Loopback" not in device:
            try:
                ip = get_if_addr(device)
                if ip and ip != '0.0.0.0':
                    print(Fore.YELLOW + f"[+] Auto-selected interface {i}: {device} (IP: {ip})")
                    return device
            except:
                pass
    
    # Last resort - return first non-loopback interface
    for device in devices:
        if "Loopback" not in device:
            print(Fore.YELLOW + f"[+] Auto-selected first non-loopback interface: {device}")
            return device
    
    return devices[0] if devices else None

def main():
    print(Fore.CYAN + "=" * 60)
    print(Fore.CYAN + "     PACKET SNIFFER WITH ADVANCED ANOMALY DETECTION")
    print(Fore.CYAN + "=" * 60)
    
    # Ask if user wants to use web interface
    use_web = False
    if WEB_ENABLED:
        web_choice = input(Fore.YELLOW + "Do you want to use the web dashboard? (y/n): ").lower()
        use_web = (web_choice == 'y')
        
        if use_web:
            # Start web server in background thread
            web_thread = threading.Thread(target=run_web_server, kwargs={'host': '127.0.0.1', 'port': 5004}, daemon=True)
            web_thread.start()
            print(Fore.GREEN + "[+] Web dashboard starting...")
            print(Fore.GREEN + "[+] Open your browser to: http://127.0.0.1:5004")
            import time
            time.sleep(2)  # Give server time to start
    
    # Ask if user wants to analyze existing PCAP file
    analyze_choice = input(Fore.YELLOW + "\nDo you want to analyze an existing PCAP file? (y/n): ").lower()
    
    if analyze_choice == 'y':
        # Analyze existing PCAP file
        pcap_file = input(Fore.YELLOW + "Enter path to PCAP file: ")
        if not os.path.exists(pcap_file):
            print(Fore.RED + f"[!] PCAP file does not exist: {pcap_file}")
            sys.exit(1)
            
        model_path = input(Fore.YELLOW + f"Enter path to model file (Enter for default {DEFAULT_MODEL_PATH}): ")
        if not model_path:
            model_path = DEFAULT_MODEL_PATH
            
        print(Fore.CYAN + f"[+] Starting analysis of file: {pcap_file}")
        analyze_pcap_file(pcap_file, model_path=model_path)
        sys.exit(0)
    
    # Capture new packets
    try:
        # Get available interfaces first
        devices = get_network_interfaces()
        if not devices:
            print(Fore.RED + "[!] No network interfaces found.")
            print(Fore.YELLOW + "[!] Make sure Npcap is installed and you're running as Administrator.")
            sys.exit(1)
        
        # Ask user if they want to use automatic interface detection
        auto_choice = input(Fore.YELLOW + "\nUse automatic interface detection? (recommended) (y/n): ").lower()
        
        if auto_choice == 'y':
            # Use improved automatic selection
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
                
            # Select interface
            while True:
                try:
                    choice = input(Fore.YELLOW + "\nSelect interface number for packet capture: ")
                    device_index = int(choice)
                    if 0 <= device_index < len(devices):
                        interface = devices[device_index]
                        try:
                            ip = get_if_addr(interface)
                            if ip and ip != '0.0.0.0':
                                print(Fore.GREEN + f"[+] Selected interface: {interface} (IP: {ip})")
                            else:
                                print(Fore.YELLOW + f"[+] Selected interface: {interface} (Warning: No IP assigned)")
                        except:
                            print(Fore.GREEN + f"[+] Selected interface: {interface}")
                        break
                    else:
                        print(Fore.RED + f"[!] Invalid number. Please choose from 0 to {len(devices)-1}.")
                except ValueError:
                    print(Fore.RED + "[!] Please enter a number.")
        
        # Enter filter
        filter_exp = input(Fore.YELLOW + "\nEnter BPF filter (leave empty if not needed): ")
        
        # Enter maximum packet count
        count_input = input(Fore.YELLOW + "\nEnter maximum number of packets to capture (Enter for unlimited): ")
        count = int(count_input) if count_input.strip() else None
        
        # Enter output directory
        output_dir = input(Fore.YELLOW + f"\nEnter directory to save PCAP files (Enter for default {DEFAULT_OUTPUT_DIR}): ")
        if not output_dir:
            output_dir = DEFAULT_OUTPUT_DIR
            
        # Enter model file
        model_path = input(Fore.YELLOW + f"\nEnter path to model file (Enter for default {DEFAULT_MODEL_PATH}): ")
        if not model_path:
            model_path = DEFAULT_MODEL_PATH
        
        print(Fore.CYAN + "\n" + "=" * 60)
        print(Fore.CYAN + f"[+] Using interface: {interface}")
        if filter_exp:
            print(Fore.CYAN + f"[+] Applying filter: {filter_exp}")
        if count:
            print(Fore.CYAN + f"[+] Maximum packets: {count}")
        print(Fore.CYAN + f"[+] PCAP output directory: {output_dir}")
        print(Fore.CYAN + f"[+] Model file: {model_path}")
        if use_web:
            print(Fore.GREEN + f"[+] Web dashboard: http://127.0.0.1:5004")
        print(Fore.CYAN + "=" * 60)
        
        # Confirm before starting
        confirm = input(Fore.YELLOW + "\nStart packet capture? (y/n): ").lower()
        if confirm != 'y':
            print(Fore.RED + "[!] Packet capture cancelled.")
            sys.exit(0)
        
        # Initialize PacketSniffer and start capturing
        sniffer = PacketSniffer(
            interface=interface,
            output_dir=output_dir,
            model_path=model_path,
            filter_exp=filter_exp,
            use_web=use_web,
            web_callback=add_packet if use_web else None,
            alert_callback=add_alert if use_web else None
        )
        
        print(Fore.GREEN + "\n[+] Starting packet capture... Press Ctrl+C to stop")
        if use_web:
            print(Fore.GREEN + "[+] View real-time dashboard at: http://127.0.0.1:5004")
        sniffer.start_sniffing(max_packets=count)
        
        # If using web dashboard, keep it running after capture completes
        if use_web:
            print(Fore.GREEN + "\n[+] Packet capture complete!")
            print(Fore.GREEN + "[+] Web dashboard is still running at: http://127.0.0.1:5004")
            print(Fore.YELLOW + "[+] Press Ctrl+C to stop the web server and exit")
            try:
                # Keep the main thread alive so web server continues running
                import time
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print(Fore.YELLOW + "\n[!] Shutting down web dashboard...")
    
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Packet capture stopped by user request.")
    except Exception as e:
        print(Fore.RED + f"\n[!] Unhandled error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
