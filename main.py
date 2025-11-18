import os
import sys
import ctypes
from colorama import init, Fore
from analyzer.packet_sniffer import PacketSniffer
from analyzer.pcap_analyzer import analyze_pcap_file
from config import DEFAULT_INTERFACE, DEFAULT_OUTPUT_DIR, DEFAULT_MODEL_PATH

# Import Scapy instead of pcap for Windows compatibility
try:
    from scapy.all import get_if_list
except ImportError:
    print(Fore.RED + "[!] Scapy is not installed. Please install it with: pip install scapy")
    sys.exit(1)

init(autoreset=True)

def is_admin():
    """Check if running with administrator privileges on Windows"""
    try:
        import os
        # Alternative method - check if we can write to a system directory
        test_path = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'temp', 'admin_test.tmp')
        try:
            with open(test_path, 'w') as f:
                f.write('test')
            os.remove(test_path)
            return True
        except:
            # Try the original method as fallback
            return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        # If all else fails, assume we have admin rights and let the OS handle it
        return True

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
    
    # Check for administrator privileges on Windows
    # if not is_admin():
    #     print(Fore.RED + "[!] This script must be run as Administrator for packet capture.")
    #     print(Fore.YELLOW + "[!] Please right-click Command Prompt/PowerShell and select 'Run as administrator'")
    #     sys.exit(1)
    
    # Ask if user wants to analyze existing PCAP file
    analyze_choice = input(Fore.YELLOW + "Do you want to analyze an existing PCAP file? (y/n): ").lower()
    
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
            filter_exp=filter_exp
        )
        
        print(Fore.GREEN + "\n[+] Starting packet capture... Press Ctrl+C to stop")
        sniffer.start_sniffing(max_packets=count)
    
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Packet capture stopped by user request.")
    except Exception as e:
        print(Fore.RED + f"\n[!] Unhandled error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()