from scapy.all import sniff, conf, get_if_addr
from colorama import init, Fore

init(autoreset=True)

# Get the default interface
interface = conf.iface
ip = get_if_addr(interface)

print(Fore.CYAN + "=" * 70)
print(Fore.CYAN + "Scapy Packet Capture Test")
print(Fore.CYAN + "=" * 70)
print(Fore.GREEN + f"\nUsing interface: {interface}")
print(Fore.GREEN + f"IP Address: {ip}")
print(Fore.YELLOW + f"\nAttempting to capture 3 packets...")
print(Fore.YELLOW + f"Please generate some network traffic (browse web, ping, etc.)")
print(Fore.CYAN + "=" * 70)

packet_count = [0]

def packet_callback(pkt):
    packet_count[0] += 1
    print(Fore.GREEN + f"[{packet_count[0]}] Captured packet: {pkt.summary()}")

try:
    # Capture 3 packets with 30 second timeout
    packets = sniff(iface=interface, count=3, timeout=30, prn=packet_callback)
    
    if len(packets) > 0:
        print(Fore.GREEN + f"\n✓ SUCCESS! Captured {len(packets)} packet(s)")
        print(Fore.CYAN + "\nThe packet capture is working correctly!")
    else:
        print(Fore.RED + f"\n✗ FAILED - No packets captured")
        print(Fore.YELLOW + "\nPossible issues:")
        print(Fore.YELLOW + "1. Npcap not installed or not working properly")
        print(Fore.YELLOW + "2. Not running with administrator privileges")
        print(Fore.YELLOW + "3. Firewall blocking packet capture")
        print(Fore.YELLOW + "4. No traffic on this network interface")
        
except Exception as e:
    print(Fore.RED + f"\n✗ ERROR: {e}")
    import traceback
    traceback.print_exc()
