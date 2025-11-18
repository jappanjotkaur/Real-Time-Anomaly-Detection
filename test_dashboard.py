"""
Test Web Dashboard - Runs only the web server without packet capture
Useful for testing the dashboard interface
"""

from web_app import run_web_server, add_packet, add_alert
import time
import random
from datetime import datetime

print("=" * 60)
print("     WEB DASHBOARD TEST MODE")
print("=" * 60)
print("\n[+] Starting web server...")
print("[+] This will generate demo packets for testing")
print("[+] Open http://127.0.0.1:5000 in your browser\n")

# Start web server in background
import threading
web_thread = threading.Thread(target=run_web_server, kwargs={'host': '127.0.0.1', 'port': 5000}, daemon=True)
web_thread.start()

# Wait for server to start
time.sleep(3)

print("\n[+] Generating demo packets... Press Ctrl+C to stop\n")

# Generate demo packets
protocols = ['TCP', 'UDP', 'ICMP', 'ARP', 'DNS', 'HTTP', 'HTTPS']
ips = ['192.168.1.100', '192.168.1.1', '8.8.8.8', '1.1.1.1', '10.0.0.1']

try:
    packet_id = 0
    while True:
        packet_id += 1
        
        # Create demo packet
        packet_info = {
            'src_ip': random.choice(ips),
            'dst_ip': random.choice(ips),
            'protocol': random.choice(protocols),
            'src_port': random.randint(1024, 65535) if random.random() > 0.3 else 'N/A',
            'dst_port': random.choice([80, 443, 53, 22, 3389]) if random.random() > 0.3 else 'N/A',
            'app_proto': random.choice(['', 'HTTP', 'HTTPS', 'DNS', 'SSH']),
            'size': random.randint(64, 1500)
        }
        
        # Random anomaly detection
        is_anomaly = -1 if random.random() < 0.1 else 1
        anomaly_score = random.uniform(0.6, 0.95) if is_anomaly == -1 else random.uniform(0.1, 0.4)
        flow_score = random.randint(0, 8)
        
        # Send to dashboard
        add_packet(packet_info, (is_anomaly, anomaly_score, flow_score))
        
        # Generate alert occasionally
        if flow_score >= 7 and random.random() < 0.3:
            add_alert(f"High risk flow detected: {packet_info['src_ip']} → {packet_info['dst_ip']}")
        
        # Print progress
        if packet_id % 10 == 0:
            print(f"[+] Generated {packet_id} demo packets...")
        
        # Wait before next packet (faster for demo)
        time.sleep(random.uniform(0.1, 0.5))
        
except KeyboardInterrupt:
    print("\n[+] Demo stopped. Web dashboard remains active.")
    print("[+] Press Ctrl+C again to exit completely.")
    
    # Keep server running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Shutting down...")
