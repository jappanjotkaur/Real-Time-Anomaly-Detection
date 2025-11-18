"""Quick script to analyze the last captured PCAP file"""
import dpkt
import socket
from datetime import datetime

pcap_file = 'captures\\capture_20251107_122811.pcap'

print(f"\n{'='*70}")
print(f"Analyzing: {pcap_file}")
print(f"{'='*70}\n")

with open(pcap_file, 'rb') as f:
    pcap = dpkt.pcap.Reader(f)
    
    for i, (timestamp, buf) in enumerate(pcap, 1):
        print(f"Packet {i}:")
        print(f"  Timestamp: {datetime.fromtimestamp(timestamp).strftime('%H:%M:%S.%f')[:-3]}")
        print(f"  Size: {len(buf)} bytes")
        
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            print(f"  Ethernet: {eth.__class__.__name__}")
            
            # IP layer
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
                print(f"  IP: {src_ip} -> {dst_ip}")
                
                # Transport layer
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    print(f"  Protocol: TCP")
                    print(f"  Ports: {tcp.sport} -> {tcp.dport}")
                    print(f"  Flags: {tcp.flags}")
                    
                elif isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    print(f"  Protocol: UDP")
                    print(f"  Ports: {udp.sport} -> {udp.dport}")
                    
                elif isinstance(ip.data, dpkt.icmp.ICMP):
                    print(f"  Protocol: ICMP")
                    
                elif ip.p == 2:  # IGMP
                    print(f"  Protocol: IGMP")
                    
                else:
                    print(f"  Protocol: Other (IP protocol {ip.p})")
                    
            elif isinstance(eth.data, dpkt.arp.ARP):
                arp = eth.data
                print(f"  Protocol: ARP")
                
            else:
                print(f"  Protocol: Non-IP ({eth.data.__class__.__name__})")
                
        except Exception as e:
            print(f"  Error parsing: {e}")
        
        print()

print(f"{'='*70}")
print(f"Analysis complete!")
print(f"{'='*70}\n")
