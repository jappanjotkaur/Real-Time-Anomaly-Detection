from scapy.all import conf, get_if_list, get_if_addr
from colorama import Fore, init

init(autoreset=True)

print(Fore.CYAN + "=" * 70)
print(Fore.CYAN + "Network Interface Diagnostics")
print(Fore.CYAN + "=" * 70)

print(Fore.YELLOW + f"\nDefault Scapy Interface: {conf.iface}")

print(Fore.CYAN + "\n" + "=" * 70)
print(Fore.CYAN + "Available Network Interfaces:")
print(Fore.CYAN + "=" * 70)

try:
    ifaces = get_if_list()
    for i, iface in enumerate(ifaces):
        print(Fore.GREEN + f"\n[{i}] {iface}")
        try:
            ip = get_if_addr(iface)
            if ip and ip != '0.0.0.0':
                print(Fore.WHITE + f"    IP: {ip}")
            else:
                print(Fore.RED + "    No IP assigned")
        except:
            print(Fore.RED + "    Could not get IP")
            
except Exception as e:
    print(Fore.RED + f"Error getting interface details: {e}")

print(Fore.CYAN + "\n" + "=" * 70)
print(Fore.YELLOW + "Tip: Look for an interface with an IP address that matches")
print(Fore.YELLOW + "      your local network (e.g., 192.168.x.x or 10.x.x.x)")
print(Fore.CYAN + "=" * 70)
