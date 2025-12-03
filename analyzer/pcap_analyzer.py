from rich.console import Console
from rich.table import Table
from rich.text import Text
import dpkt
import os
from datetime import datetime
from collections import defaultdict
from analyzer.packet_sniffer import PacketSniffer
from utils.packet_parser import PacketParser
from models.anomaly_detector import EnhancedAnomalyDetection

def analyze_pcap_file(pcap_file, model_path="./model/anomaly_model.pkl"):
    """Main function to analyze stored PCAP files offline."""
    print(f"[+] Starting PCAP file analysis: {pcap_file}")
    
    # Initialize ML anomaly detection model
    detector = EnhancedAnomalyDetection(model_path=model_path)
    
    # Prepare Rich table for console output
    console = Console()
    table = Table(title=f"[~] PCAP file analysis: {os.path.basename(pcap_file)}")
    table.add_column("ID", style="cyan", width=5)
    table.add_column("Timestamp", width=12)
    table.add_column("Src IP", width=15)
    table.add_column("Dest IP", width=15)
    table.add_column("Proto", width=10)
    table.add_column("App Proto", width=10)
    table.add_column("Details", width=20)
    table.add_column("Size", style="cyan", width=6)
    table.add_column("Anomaly", style="red", width=8)
    
    # Open the PCAP file
    try:
        with open(pcap_file, 'rb') as f:
            pcap_reader = dpkt.pcap.Reader(f)
            
            packet_id = 0
            anomaly_count = 0
            feature_vectors = []
            flow_anomalies = defaultdict(int)
            
            # Create a PacketParser object to parse packets
            packet_parser = PacketParser()
            
            # Read packets one by one
            for timestamp, packet in pcap_reader:
                packet_id += 1
                
                # Parse packet
                packet_info = packet_parser.parse_packet(packet)
                
                # Skip if packet cannot be parsed
                if not packet_info:
                    continue
                
                # Extract ML features
                features, flow_key = detector.extract_features(packet_info, timestamp)
                feature_vectors.append(features)
                
                # Run anomaly detection
                is_anomaly, score = detector.predict(features)
                
                # Update anomaly statistics per flow
                if is_anomaly == -1:
                    anomaly_count += 1
                    flow_anomalies[flow_key] += 1
                
                # Prepare display text
                anomaly_text = "Normal"
                anomaly_style = "green"
                if is_anomaly == -1:
                    anomaly_text = f"Anomaly ({score:.2f})"
                    anomaly_style = "red"
                
                # Format timestamp to readable string
                time_str = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S.%f')[:-3]
                
                # Add packet information to the Rich table
                table.add_row(
                    str(packet_id),
                    time_str,
                    str(packet_info["src_ip"]),
                    str(packet_info["dst_ip"]),
                    str(packet_info["protocol"]),
                    str(packet_info["app_proto"]),
                    str(packet_info["details"]),
                    str(packet_info["size"]),
                    Text(anomaly_text, style=anomaly_style)
                )
                
                # Refresh output every 100 packets
                if packet_id % 100 == 0:
                    console.clear()
                    console.print(table)
                    console.print(f"Analyzed: {packet_id} packets, detected: {anomaly_count} anomalies")
                
                # Retrain model every 1000 packets (optional continuous learning)
                if packet_id % 1000 == 0 and len(feature_vectors) > 100:
                    detector.fit(feature_vectors[-1000:])
            
            # Final display output
            console.clear()
            console.print(table)
            
            # Identify flows with most anomalies
            top_flows = sorted(flow_anomalies.items(), key=lambda x: x[1], reverse=True)[:5]
            
            # Print summary results
            print(f"\n[+] Analysis completed: {packet_id} packets processed, {anomaly_count} anomalies detected")
            
            if top_flows:
                print("\n[~] Top 5 flows with the highest anomaly counts:")
                for flow, count in top_flows:
                    if len(flow) == 5:  # TCP/UDP flow format
                        print(f"  - {flow[0]}:{flow[1]} → {flow[2]}:{flow[3]} [{flow[4]}]: {count} anomalies")
                    else:  # Other protocol formats
                        print(f"  - {flow[0]} → {flow[1]} [{flow[2]}]: {count} anomalies")
            
    except Exception as e:
        print(f"[!] Error while analyzing PCAP file: {e}")
