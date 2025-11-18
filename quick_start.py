"""
Quick Start - Real Packet Capture with Web Dashboard
Automatically configured for immediate use
"""

import os
import sys
import threading
import time
from colorama import init, Fore

init(autoreset=True)

print(Fore.CYAN + "=" * 60)
print(Fore.CYAN + "   NetSniff Guard - Quick Start (Real Traffic)")
print(Fore.CYAN + "=" * 60)

# Import web app
from web_app import add_packet, add_alert, run_web_server

# Start web server
print(Fore.GREEN + "\n[+] Starting web dashboard...")
web_thread = threading.Thread(target=run_web_server, kwargs={'host': '127.0.0.1', 'port': 5000}, daemon=True)
web_thread.start()
time.sleep(2)

# Import after web server starts
from analyzer.packet_sniffer import PacketSniffer
from scapy.all import get_if_list, get_if_addr, conf

# Auto-select interface
print(Fore.YELLOW + "[+] Auto-detecting network interface...")
interface = conf.iface
ip = get_if_addr(interface)
print(Fore.GREEN + f"[+] Selected: {interface} (IP: {ip})")

# Configuration
output_dir = "./captures"
model_path = "./model/anomaly_model.pkl"

print(Fore.CYAN + "\n" + "=" * 60)
print(Fore.CYAN + f"[+] Interface: {interface}")
print(Fore.CYAN + f"[+] Output: {output_dir}")
print(Fore.CYAN + f"[+] Model: {model_path}")
print(Fore.GREEN + f"[+] Web Dashboard: http://127.0.0.1:5000 (or 5001)")
print(Fore.CYAN + "=" * 60)

print(Fore.GREEN + "\n[+] Open your browser to: http://127.0.0.1:5000")
print(Fore.YELLOW + "[+] Generate traffic: Open websites, ping, download files")
print(Fore.YELLOW + "[+] Press Ctrl+C to stop\n")

try:
    # Initialize sniffer with web callbacks
    sniffer = PacketSniffer(
        interface=interface,
        output_dir=output_dir,
        model_path=model_path,
        filter_exp=None,
        use_web=True,
        web_callback=add_packet,
        alert_callback=add_alert
    )
    
    print(Fore.GREEN + "[+] Starting packet capture...")
    print(Fore.GREEN + "[+] Dashboard will update in real-time!\n")
    
    sniffer.start_sniffing(max_packets=None)  # Unlimited
    
except KeyboardInterrupt:
    print(Fore.YELLOW + "\n[!] Packet capture stopped by user")
except Exception as e:
    print(Fore.RED + f"\n[!] Error: {e}")
    import traceback
    traceback.print_exc()
