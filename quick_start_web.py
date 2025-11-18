"""
Quick Start Web Dashboard
Automatically starts packet capture with web dashboard - minimal user input required
"""
import os
import sys
import threading
import webbrowser
import time
from colorama import init, Fore
from analyzer.packet_sniffer import PacketSniffer
from config import DEFAULT_OUTPUT_DIR, DEFAULT_MODEL_PATH

# Import Scapy for Windows compatibility
try:
    from scapy.all import get_if_list, get_if_addr, conf
except ImportError:
    print(Fore.RED + "[!] Scapy is not installed. Please install it with: pip install scapy")
    sys.exit(1)

# Import web app
try:
    from web_app import add_packet, add_alert, run_web_server
    WEB_ENABLED = True
except ImportError:
    WEB_ENABLED = False
    print(Fore.RED + "[!] Web dashboard dependencies not installed.")
    sys.exit(1)

init(autoreset=True)

def select_best_interface():
    """Automatically select the best network interface"""
    devices = get_if_list()
    
    if not devices:
        return None
    
    # Try Scapy's default interface first
    try:
        default_iface = conf.iface
        if default_iface in devices:
            ip = get_if_addr(default_iface)
            if ip and ip != '0.0.0.0' and "Loopback" not in default_iface:
                return default_iface, ip
    except:
        pass
    
    # Find interface with valid non-link-local IP
    for device in devices:
        if "Loopback" not in device:
            try:
                ip = get_if_addr(device)
                if ip and ip != '0.0.0.0' and not ip.startswith('169.254'):
                    return device, ip
            except:
                pass
    
    # Fallback: any interface with IP
    for device in devices:
        if "Loopback" not in device:
            try:
                ip = get_if_addr(device)
                if ip and ip != '0.0.0.0':
                    return device, ip
            except:
                pass
    
    # Last resort
    for device in devices:
        if "Loopback" not in device:
            return device, "Unknown"
    
    return devices[0] if devices else None, "Unknown"

def open_browser_delayed(url, delay=3):
    """Open browser after a short delay"""
    time.sleep(delay)
    try:
        print(Fore.GREEN + f"\n[+] Opening browser to {url}...")
        webbrowser.open(url)
    except Exception as e:
        print(Fore.YELLOW + f"[!] Could not auto-open browser: {e}")
        print(Fore.YELLOW + f"[!] Please manually open: {url}")

def main():
    print(Fore.CYAN + "\n" + "="*70)
    print(Fore.CYAN + "     NETSNIFF GUARD - QUICK START WEB DASHBOARD")
    print(Fore.CYAN + "="*70)
    
    # Auto-select network interface
    print(Fore.YELLOW + "\n[*] Auto-detecting network interface...")
    interface_info = select_best_interface()
    
    if not interface_info or interface_info[0] is None:
        print(Fore.RED + "[!] No network interfaces found.")
        print(Fore.YELLOW + "[!] Make sure Npcap is installed and you're running as Administrator.")
        sys.exit(1)
    
    interface, ip = interface_info
    print(Fore.GREEN + f"[+] Selected interface: {interface}")
    print(Fore.GREEN + f"[+] IP Address: {ip}")
    
    # Get user preferences with defaults
    print(Fore.YELLOW + f"\n[*] Quick Configuration:")
    
    # Packet count
    count_input = input(Fore.CYAN + "Number of packets to capture (default: 100, 0 = unlimited): ").strip()
    if count_input == '0':
        count = None
    elif count_input:
        try:
            count = int(count_input)
        except ValueError:
            count = 100
    else:
        count = 100
    
    # BPF filter (optional)
    filter_exp = input(Fore.CYAN + "BPF filter (press Enter to skip): ").strip()
    if not filter_exp:
        filter_exp = None
    
    # Configuration summary
    print(Fore.CYAN + "\n" + "="*70)
    print(Fore.CYAN + f"[+] Interface: {interface} ({ip})")
    print(Fore.CYAN + f"[+] Packets: {'Unlimited' if count is None else count}")
    print(Fore.CYAN + f"[+] Filter: {filter_exp if filter_exp else 'None (all traffic)'}")
    print(Fore.CYAN + f"[+] Dashboard: http://127.0.0.1:5004")
    print(Fore.CYAN + f"[+] Output: {DEFAULT_OUTPUT_DIR}")
    print(Fore.CYAN + "="*70)
    
    # Confirm
    confirm = input(Fore.YELLOW + "\nStart capture? (Y/n): ").lower()
    if confirm and confirm != 'y':
        print(Fore.RED + "[!] Cancelled.")
        sys.exit(0)
    
    # Start web server in background
    print(Fore.GREEN + "\n[+] Starting web dashboard...")
    web_thread = threading.Thread(
        target=run_web_server, 
        kwargs={'host': '127.0.0.1', 'port': 5004}, 
        daemon=True
    )
    web_thread.start()
    time.sleep(2)  # Wait for server to start
    
    # Open browser automatically
    browser_thread = threading.Thread(
        target=open_browser_delayed,
        args=('http://127.0.0.1:5004', 2),
        daemon=True
    )
    browser_thread.start()
    
    # Initialize packet sniffer
    print(Fore.GREEN + "[+] Initializing packet sniffer...")
    try:
        sniffer = PacketSniffer(
            interface=interface,
            output_dir=DEFAULT_OUTPUT_DIR,
            model_path=DEFAULT_MODEL_PATH,
            filter_exp=filter_exp,
            use_web=True,
            web_callback=add_packet,
            alert_callback=add_alert
        )
        
        print(Fore.GREEN + "\n[+] Starting packet capture...")
        print(Fore.GREEN + "[+] Web dashboard: http://127.0.0.1:5004")
        print(Fore.YELLOW + "[+] Press Ctrl+C to stop\n")
        
        # Start capture
        sniffer.start_sniffing(max_packets=count)
        
        # Keep web server running after capture
        print(Fore.GREEN + "\n" + "="*70)
        print(Fore.GREEN + "[+] Packet capture complete!")
        print(Fore.GREEN + "[+] Web dashboard is still running at: http://127.0.0.1:5004")
        print(Fore.YELLOW + "[+] Press Ctrl+C to stop the web server and exit")
        print(Fore.GREEN + "="*70 + "\n")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n[!] Shutting down...")
            
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Capture stopped by user")
    except Exception as e:
        print(Fore.RED + f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print(Fore.CYAN + "\n[+] Goodbye!")

if __name__ == "__main__":
    main()
