"""
Diagnostic script to test packet capture
"""

import sys
from colorama import init, Fore
from scapy.all import sniff, get_if_list, get_if_addr

init(autoreset=True)

def test_packet_capture():
    print(Fore.CYAN + "=" * 60)
    print(Fore.CYAN + "Packet Capture Diagnostic Test")
    print(Fore.CYAN + "=" * 60)
    print()
    
    # List available interfaces
    print(Fore.YELLOW + "[*] Available network interfaces:")
    interfaces = get_if_list()
    for i, iface in enumerate(interfaces):
        try:
            ip = get_if_addr(iface)
            if ip and ip != '0.0.0.0':
                print(Fore.GREEN + f"  {i}: {iface} (IP: {ip})")
            else:
                print(Fore.YELLOW + f"  {i}: {iface} (No IP)")
        except:
            print(Fore.YELLOW + f"  {i}: {iface}")
    print()
    
    # Test packet capture on default interface
    print(Fore.YELLOW + "[*] Testing packet capture (10 seconds)...")
    print(Fore.YELLOW + "[*] Please generate some network traffic (browse web, ping, etc.)")
    print()
    
    packet_count = 0
    ip_packets = 0
    tcp_packets = 0
    udp_packets = 0
    other_packets = 0
    
    def packet_handler(packet):
        nonlocal packet_count, ip_packets, tcp_packets, udp_packets, other_packets
        packet_count += 1
        
        if packet.haslayer('IP'):
            ip_packets += 1
            if packet.haslayer('TCP'):
                tcp_packets += 1
            elif packet.haslayer('UDP'):
                udp_packets += 1
        else:
            other_packets += 1
        
        if packet_count <= 5:
            print(Fore.GREEN + f"  [+] Packet {packet_count}: {packet.summary()}")
    
    try:
        sniff(timeout=10, prn=packet_handler, store=False)
    except Exception as e:
        print(Fore.RED + f"[!] Error during packet capture: {e}")
        return
    
    print()
    print(Fore.CYAN + "=" * 60)
    print(Fore.CYAN + "Results:")
    print(Fore.CYAN + "=" * 60)
    print(Fore.GREEN + f"  Total packets captured: {packet_count}")
    print(Fore.GREEN + f"  IP packets: {ip_packets}")
    print(Fore.GREEN + f"  TCP packets: {tcp_packets}")
    print(Fore.GREEN + f"  UDP packets: {udp_packets}")
    print(Fore.GREEN + f"  Other packets: {other_packets}")
    print()
    
    # Try with specific interface that has IP
    if packet_count == 0:
        print(Fore.YELLOW + "[*] Trying with interface that has IP address...")
        active_interfaces = [iface for iface in interfaces if get_if_addr(iface) and get_if_addr(iface) != '0.0.0.0' and not get_if_addr(iface).startswith('169.254') and not get_if_addr(iface).startswith('127.')]
        
        if active_interfaces:
            print(Fore.YELLOW + f"[*] Testing with active interface: {active_interfaces[0]}")
            try:
                packet_count = 0
                sniff(timeout=10, iface=active_interfaces[0], prn=packet_handler, store=False)
                if packet_count > 0:
                    print(Fore.GREEN + f"[+] Successfully captured {packet_count} packets on {active_interfaces[0]}")
                    print(Fore.YELLOW + f"[*] Use this interface when running the main application!")
            except Exception as e:
                print(Fore.RED + f"[!] Error: {e}")
    
    if packet_count == 0:
        print(Fore.RED + "[!] No packets captured!")
        print(Fore.YELLOW + "[*] Possible issues:")
        print(Fore.YELLOW + "  1. No network traffic on this interface")
        print(Fore.YELLOW + "  2. Npcap not installed or not working")
        print(Fore.YELLOW + "  3. Need administrator privileges")
        print(Fore.YELLOW + "  4. Wrong interface selected")
        print()
        print(Fore.YELLOW + "[*] Solutions:")
        print(Fore.YELLOW + "  - Install/update Npcap: https://nmap.org/npcap/")
        print(Fore.YELLOW + "  - Run as Administrator")
        print(Fore.YELLOW + "  - Try a different interface")
    elif packet_count < 10:
        print(Fore.YELLOW + "[!] Very few packets captured. Try generating more traffic.")
    else:
        print(Fore.GREEN + "[+] Packet capture is working correctly!")
    
    print()

if __name__ == "__main__":
    test_packet_capture()

