"""
Simple packet capture test - captures packets and displays them in real-time
"""
from scapy.all import sniff, conf, get_if_addr
from colorama import init, Fore
import datetime

init(autoreset=True)

print(Fore.CYAN + "=" * 70)
print(Fore.CYAN + "NetSniff Guard - Simple Packet Capture Demo")
print(Fore.CYAN + "=" * 70)

# Use the default interface
interface = conf.iface
ip = get_if_addr(interface)

print(Fore.GREEN + f"\nInterface: {interface}")
print(Fore.GREEN + f"IP Address: {ip}")
print(Fore.YELLOW + f"\nCapturing 15 packets...")
print(Fore.YELLOW + f"Please browse the web or ping something!")
print(Fore.CYAN + "=" * 70 + "\n")

packet_count = 0

def packet_handler(pkt):
    global packet_count
    packet_count += 1
    
    timestamp = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
    
    # Extract basic info
    try:
        if pkt.haslayer('IP'):
            src = pkt['IP'].src
            dst = pkt['IP'].dst
            proto = pkt['IP'].proto
            size = len(pkt)
            
            proto_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(proto, f'Proto-{proto}')
            
            # Get ports if TCP/UDP
            ports = ""
            if pkt.haslayer('TCP'):
                ports = f":{pkt['TCP'].sport} → :{pkt['TCP'].dport}"
            elif pkt.haslayer('UDP'):
                ports = f":{pkt['UDP'].sport} → :{pkt['UDP'].dport}"
            
            print(Fore.GREEN + f"[{packet_count:3d}] {timestamp} | " +
                  Fore.WHITE + f"{src:15s}{ports:20s} → {dst:15s} | " +
                  Fore.CYAN + f"{proto_name:6s} | " +
                  Fore.YELLOW + f"{size:5d} bytes")
        else:
            print(Fore.YELLOW + f"[{packet_count:3d}] {timestamp} | Non-IP packet")
    except Exception as e:
        print(Fore.RED + f"[{packet_count:3d}] Error parsing packet: {e}")

try:
    # Capture packets
    sniff(iface=interface, count=15, timeout=60, prn=packet_handler)
    
    print(Fore.CYAN + "\n" + "=" * 70)
    print(Fore.GREEN + f"✓ Captured {packet_count} packets successfully!")
    print(Fore.CYAN + "=" * 70)
    
except KeyboardInterrupt:
    print(Fore.YELLOW + "\n\nCapture stopped by user")
except Exception as e:
    print(Fore.RED + f"\n\nError: {e}")
    import traceback
    traceback.print_exc()
