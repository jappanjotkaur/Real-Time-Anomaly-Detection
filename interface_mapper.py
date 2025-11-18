import psutil
from scapy.all import get_if_list
import socket

def find_wifi_interface():
    """Find the correct Scapy interface that corresponds to Wi-Fi"""
    
    print("=== Windows Network Adapters (psutil) ===")
    wifi_addresses = []
    
    for interface_name, addresses in psutil.net_if_addrs().items():
        for addr in addresses:
            if addr.family == socket.AF_INET:  # IPv4
                print(f"{interface_name}: {addr.address}")
                if "Wi-Fi" in interface_name or "Wireless" in interface_name:
                    wifi_addresses.append(addr.address)
                if addr.address == "192.168.107.211":  # Your Wi-Fi IP
                    print(f"*** FOUND YOUR Wi-Fi: {interface_name} ***")
    
    print(f"\n=== Scapy Interfaces ===")
    scapy_interfaces = get_if_list()
    for i, iface in enumerate(scapy_interfaces):
        print(f"{i}: {iface}")
    
    print(f"\n=== Interface Statistics ===")
    stats = psutil.net_if_stats()
    for name, stat in stats.items():
        if stat.isup:
            print(f"{name}: UP, Speed: {stat.speed} Mbps")
    
    print(f"\n=== Recommendation ===")
    print("Try these Scapy interfaces in order for Wi-Fi capture:")
    print("1. Interface 2 (often Wi-Fi)")
    print("2. Interface 3") 
    print("3. Interface 4")
    print("Skip Interface 0 and 1 (often Ethernet)")

if __name__ == "__main__":
    find_wifi_interface()