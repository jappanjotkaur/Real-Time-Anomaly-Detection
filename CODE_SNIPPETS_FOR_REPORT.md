# NetSniff Guard - Key Code Snippets for Report

## 1. Packet Capture and Processing (packet_sniffer.py)

### 1.1 Main Packet Handler
```python
def packet_handler(self, packet):
    """Handle each captured packet"""
    try:
        self.packet_id += 1
        timestamp = time.time()
        raw_packet = bytes(packet)
        self.pcap_handler.save_packet_to_pcap(timestamp, raw_packet)
        packet_info = self.packet_parser.parse_packet(raw_packet)
        if not packet_info:
            return
        is_anomaly, anomaly_score, flow_score = self.detect_anomaly(packet_info, timestamp)
        if self.use_web and self.web_callback:
            self.web_callback(packet_info, (is_anomaly, anomaly_score, flow_score))
        if flow_score >= 5:
            alert_msg = f"Extended anomalous flow detected! ({packet_info.get('src_ip')}:{packet_info.get('src_port')} -> {packet_info.get('dst_ip')}:{packet_info.get('dst_port')} [{packet_info.get('protocol')}])"
            if self.use_web and self.alert_callback:
                self.alert_callback(alert_msg)
        if self.packet_id % 100 == 0 and len(self.feature_vectors) >= 100:
            if self.anomaly_detector.fit(self.feature_vectors[-1000:]):
                self.anomaly_detector.save_model()
    except Exception as e:
        print(f"[!] Error processing packet: {e}")
```

### 1.2 Packet Capture Initialization
```python
def start_sniffing(self, max_packets=None):
    """Start packet capture and analysis"""
    sniff_params = {
        'prn': self.packet_handler,
        'store': False,
        'timeout': 5,
        'stop_filter': lambda x: self.stop_sniffing,
    }
    if self.interface:
        sniff_params['iface'] = self.interface
    if self.filter_exp:
        sniff_params['filter'] = self.filter_exp
    while not self.stop_sniffing:
        if max_packets:
            remaining = max_packets - packets_captured
            if remaining <= 0:
                break
            sniff_params['count'] = min(10, remaining)
        else:
            sniff_params['count'] = 10
        sniff(**sniff_params)
```

## 2. Feature Extraction (anomaly_detector.py)

### 2.1 8-Dimensional Feature Vector Extraction
```python
def extract_features(self, packet_info, timestamp):
    """Extract features from packet and flow statistics"""
    if packet_info['protocol'] in ["TCP", "UDP"]:
        flow_key = (packet_info["src_ip"], packet_info["src_port"],
                   packet_info["dst_ip"], packet_info["dst_port"],
                   packet_info["protocol"])
    else:
        flow_key = (packet_info["src_ip"], packet_info["dst_ip"],
                   packet_info["protocol"])
    flow = self.flow_stats[flow_key]
    time_delta = 0
    if flow["last_seen"] > 0:
        time_delta = timestamp - flow["last_seen"]
        flow["intervals"].append(time_delta)
        if len(flow["intervals"]) > 50:
            flow["intervals"] = flow["intervals"][-50:]
    flow["packet_count"] += 1
    flow["bytes_total"] += packet_info["size"]
    flow["last_seen"] = timestamp
    protocol_map = {"TCP": 6, "UDP": 17, "ICMP": 1, "HTTP": 80, "HTTPS": 443, "DNS": 53}
    protocol_num = protocol_map.get(packet_info["protocol"], 0)
    avg_packet_rate = 0
    if len(flow["intervals"]) > 0:
        avg_interval = sum(flow["intervals"]) / len(flow["intervals"])
        if avg_interval > 0:
            avg_packet_rate = 1.0 / avg_interval
    src_port = int(packet_info["src_port"]) if packet_info["src_port"] != "N/A" else 0
    dst_port = int(packet_info["dst_port"]) if packet_info["dst_port"] != "N/A" else 0
    features = [
        packet_info["size"],          # Feature 1: Packet size
        protocol_num,                 # Feature 2: Protocol number
        src_port,                     # Feature 3: Source port
        dst_port,                     # Feature 4: Destination port
        time_delta,                   # Feature 5: Time between packets
        flow["packet_count"],         # Feature 6: Packets in flow
        flow["bytes_total"],          # Feature 7: Total bytes in flow
        avg_packet_rate              # Feature 8: Average packet rate
    ]
    return np.array(features), flow_key
```

### 2.2 Anomaly Detection (Isolation Forest)
```python
def predict(self, feature_vector):
    """Predict if packet is anomalous"""
    if not self.is_trained:
        return 0, 0
    X = self.scaler.transform([feature_vector])
    result = self.model.predict(X)[0]  # -1 = anomaly, 1 = normal
    score = self.model.decision_function(X)[0]
    return result, score

def fit(self, feature_vectors):
    """Train model on new data"""
    if len(feature_vectors) < 10:
        return False
    X = self.scaler.fit_transform(feature_vectors)
    self.model.fit(X)
    self.is_trained = True
    return True
```

## 3. Packet Parsing (packet_parser.py)

### 3.1 Main Packet Parser
```python
@staticmethod
def parse_packet(packet):
    """Parse packet and extract protocol information"""
    result = {
        "src_ip": "Unknown", "dst_ip": "Unknown", "protocol": "Unknown",
        "src_port": "N/A", "dst_port": "N/A", "app_proto": "",
        "details": "", "size": len(packet),
        "dns_query": None, "dns_answers": [], "tls_sni": None
    }
    try:
        eth = dpkt.ethernet.Ethernet(packet)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = eth.data
            result["src_ip"] = socket.inet_ntoa(ip.src)
            result["dst_ip"] = socket.inet_ntoa(ip.dst)
            result["protocol"] = PROTOCOL_MAP.get(ip.p, "Unknown")
            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                result["src_port"] = tcp.sport
                result["dst_port"] = tcp.dport
                flags = []
                if tcp.flags & dpkt.tcp.TH_SYN: flags.append("SYN")
                if tcp.flags & dpkt.tcp.TH_ACK: flags.append("ACK")
                if tcp.flags & dpkt.tcp.TH_FIN: flags.append("FIN")
                result["details"] = f"Flags: {' '.join(flags)}"
                if tcp.dport == 443 or tcp.sport == 443:
                    result["app_proto"] = "HTTPS"
                    if len(tcp.data) > 0 and tcp.data[0] == 0x16:
                        sni = PacketParser.extract_tls_sni(tcp.data)
                        if sni:
                            result["tls_sni"] = sni
            elif isinstance(ip.data, dpkt.udp.UDP):
                udp = ip.data
                result["src_port"] = udp.sport
                result["dst_port"] = udp.dport
                if udp.sport == 53 or udp.dport == 53:
                    result["app_proto"] = "DNS"
                    try:
                        dns = dpkt.dns.DNS(udp.data)
                        if dns.qr == dpkt.dns.DNS_Q:
                            if dns.qd:
                                result["dns_query"] = dns.qd[0].name.decode('utf-8')
                        elif dns.qr == dpkt.dns.DNS_R:
                            for answer in dns.an:
                                if answer.type == dpkt.dns.DNS_A:
                                    result["dns_answers"].append(socket.inet_ntoa(answer.rdata))
                    except:
                        pass
    except Exception as e:
        print(f"[!] Error parsing packet: {e}")
    return result
```

### 3.2 TLS SNI Extraction
```python
@staticmethod
def extract_tls_sni(tls_data):
    """Extract Server Name Indication from TLS ClientHello"""
    try:
        if len(tls_data) < 5 or tls_data[0] != 0x16:
            return None
        handshake_type = tls_data[5]
        if handshake_type != 0x01:  # ClientHello
            return None
        pos = 6 + 3 + 2 + 32  # Skip header, version, random
        pos += 1 + tls_data[pos]  # Skip session ID
        pos += 2 + int.from_bytes(tls_data[pos:pos+2], 'big')  # Skip cipher suites
        pos += 1 + tls_data[pos]  # Skip compression methods
        ext_len = int.from_bytes(tls_data[pos:pos+2], 'big')
        pos += 2
        while pos + 4 < len(tls_data):
            ext_type = int.from_bytes(tls_data[pos:pos+2], 'big')
            ext_size = int.from_bytes(tls_data[pos+2:pos+4], 'big')
            pos += 4
            if ext_type == 0x00:  # SNI extension
                list_len = int.from_bytes(tls_data[pos:pos+2], 'big')
                pos += 2
                name_type = tls_data[pos]
                pos += 1
                if name_type == 0x00:  # Hostname
                    name_len = int.from_bytes(tls_data[pos:pos+2], 'big')
                    pos += 2
                    server_name = tls_data[pos:pos+name_len].decode('utf-8')
                    return server_name
            pos += ext_size
    except Exception:
        return None
    return None
```

## 4. Web Dashboard Integration (web_app.py)

### 4.1 Packet Addition to Dashboard
```python
def add_packet(packet_info, anomaly_info):
    """Add packet to web dashboard with real-time updates"""
    global packet_data, statistics
    now = time.time()
    packet_info = enhance_packet_info(packet_info)
    dns_answers = packet_info.get('dns_answers') or []
    dns_query = packet_info.get('dns_query')
    if dns_answers and dns_query:
        for answer_ip in dns_answers:
            dns_cache[str(answer_ip)] = {'hostname': dns_query, 'expires': now + DNS_CACHE_TTL}
    tls_sni = packet_info.get('tls_sni')
    dst_ip = packet_info.get('dst_ip')
    if tls_sni and dst_ip:
        sni_cache[str(dst_ip)] = {'hostname': tls_sni, 'expires': now + DNS_CACHE_TTL}
    statistics['total_packets'] += 1
    is_anomaly, anomaly_score, flow_score = anomaly_info
    if is_anomaly == -1:
        statistics['anomaly_packets'] += 1
    statistics['protocols'][packet_info.get('protocol')] += 1
    statistics['anomaly_rate'] = (statistics['anomaly_packets'] / statistics['total_packets']) * 100
    packet_entry = {
        'id': statistics['total_packets'],
        'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
        'src_ip': packet_info.get('src_ip'),
        'dst_ip': packet_info.get('dst_ip'),
        'src_hostname': packet_info.get('src_hostname', ''),
        'dst_hostname': packet_info.get('dst_hostname', ''),
        'protocol': packet_info.get('protocol'),
        'src_port': packet_info.get('src_port', 'N/A'),
        'dst_port': packet_info.get('dst_port', 'N/A'),
        'service': packet_info.get('service', ''),
        'size': packet_info.get('size', 0),
        'is_anomaly': is_anomaly == -1,
        'anomaly_score': round(anomaly_score, 2),
        'flow_score': flow_score
    }
    packet_data.append(packet_entry)
    if len(packet_data) > 1000:
        packet_data.pop(0)
    socketio.emit('new_packet', packet_entry)
    socketio.emit('stats_update', {
        'totalPackets': statistics['total_packets'],
        'anomalyPackets': statistics['anomaly_packets'],
        'anomalyRate': round(statistics['anomaly_rate'], 2),
        'runtime': int(time.time() - statistics['start_time'])
    })
```

### 4.2 WebSocket Event Handlers
```python
@socketio.on('connect')
def handle_connect():
    print('[+] Client connected to web dashboard')
    emit('connection_response', {'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    print('[+] Client disconnected from web dashboard')
```

## 5. Model Evaluation (evaluate_unsupervised_models.py)

### 5.1 Model Evaluation Function
```python
def evaluate_detector(name, detector, X_train, X_test, y_test, contamination):
    """Evaluate a single detector and return metrics"""
    detector.fit(X_train)
    scores = detector.score_samples(X_test)
    threshold = np.percentile(scores, 100 * (1 - contamination))
    y_pred = (scores >= threshold).astype(int)
    roc_auc = roc_auc_score(y_test, scores)
    pr_auc = average_precision_score(y_test, scores)
    f1 = f1_score(y_test, y_pred)
    tp, fp, tn, fn = confusion_from_scores(scores, y_test, threshold)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    mcc = calculate_mcc(tp, fp, tn, fn)
    return {
        "name": name, "roc_auc": roc_auc, "pr_auc": pr_auc, "f1": f1,
        "precision": precision, "recall": recall, "specificity": specificity,
        "mcc": mcc, "threshold": float(threshold)
    }
```

### 5.2 Multiple Model Evaluation
```python
# Isolation Forest
iso = IsolationForest(contamination=contamination, random_state=42)
iso.fit(X_train_scaled)
iso_scores = -iso.decision_function(X_test_scaled)
iso_metrics = eval_metrics_from_scores(iso_scores, y_test, contamination)
results.append({**iso_metrics, "name": "IsolationForest"})

# Kernel Density Estimation
kde = KernelDensityDetector(bandwidth=1.0)
kde_results = evaluate_detector("KernelDensity", kde, X_train_scaled, X_test_scaled, y_test, contamination)
results.append(kde_results)

# One-Class SVM
ocsvm = OneClassSVM(kernel="rbf", gamma="scale", nu=min(0.5, max(0.01, contamination + 0.02)))
ocsvm.fit(X_train_scaled)
ocsvm_scores = -ocsvm.decision_function(X_test_scaled)
ocsvm_metrics = eval_metrics_from_scores(ocsvm_scores, y_test, contamination)
results.append({**ocsvm_metrics, "name": "OneClassSVM"})

# Local Outlier Factor
lof = LocalOutlierFactor(novelty=True, contamination=contamination)
lof.fit(X_train_scaled)
lof_scores = -lof.decision_function(X_test_scaled)
lof_metrics = eval_metrics_from_scores(lof_scores, y_test, contamination)
results.append({**lof_metrics, "name": "LOF"})

# HBOS
hbos = HBOSDetector(bins=30)
hbos_results = evaluate_detector("HBOS", hbos, X_train_scaled, X_test_scaled, y_test, contamination)
results.append(hbos_results)
```

## 6. Quick Start Entry Point (quick_start_web.py)

### 6.1 Main Function
```python
def main():
    interface_info = select_best_interface()
    interface, ip = interface_info
    count_input = input("Number of packets (default: 100, 0 = unlimited): ")
    count = int(count_input) if count_input else 100
    if count == 0:
        count = None
    filter_exp = input("BPF filter (press Enter to skip): ").strip()
    if not filter_exp:
        filter_exp = None
    web_thread = threading.Thread(target=run_web_server, kwargs={'host': '127.0.0.1', 'port': 5004}, daemon=True)
    web_thread.start()
    time.sleep(2)
    browser_thread = threading.Thread(target=open_browser_delayed, args=('http://127.0.0.1:5004', 2), daemon=True)
    browser_thread.start()
    sniffer = PacketSniffer(interface=interface, output_dir=DEFAULT_OUTPUT_DIR, model_path=DEFAULT_MODEL_PATH,
                           filter_exp=filter_exp, use_web=True, web_callback=add_packet, alert_callback=add_alert)
    sniffer.start_sniffing(max_packets=count)
```

## 7. Flow-Based Anomaly Detection

### 7.1 Flow Score Calculation
```python
def detect_anomaly(self, packet_info, timestamp):
    """Detect anomalies and calculate flow scores"""
    features, flow_key = self.anomaly_detector.extract_features(packet_info, timestamp)
    self.feature_vectors.append(features)
    is_anomaly, score = self.anomaly_detector.predict(features)
    if is_anomaly == -1:
        self.flow_anomalies[flow_key] += 1
    flow_score = 0
    if flow_key in self.flow_anomalies:
        flow_score = self.flow_anomalies[flow_key]
    return is_anomaly, score, flow_score
```

## Summary of Key Components

1. **Packet Capture**: Scapy-based real-time packet sniffing
2. **Feature Extraction**: 8-dimensional feature vector from packet and flow statistics
3. **Anomaly Detection**: Multiple unsupervised ML models (Isolation Forest, KDE, One-Class SVM, LOF, HBOS)
4. **Protocol Parsing**: Deep packet inspection including TLS SNI and DNS extraction
5. **Web Dashboard**: Real-time visualization via Flask and SocketIO
6. **Continuous Learning**: Model retraining every 100 packets
7. **Flow Tracking**: Connection-based anomaly scoring
8. **Threat Intelligence**: DNS/TLS hostname resolution and caching
