"""
NetSniff Guard - Web Dashboard
Real-time packet capture visualization with Flask and SocketIO
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import threading
import time
from datetime import datetime
from collections import defaultdict
import json
from utils.dns_resolver import enhance_packet_info

app = Flask(__name__)
app.config['SECRET_KEY'] = 'netsniff-guard-secret-key'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global variables to store packet data
packet_data = []
statistics = {
    'total_packets': 0,
    'anomaly_packets': 0,
    'protocols': defaultdict(int),
    'top_sources': defaultdict(int),
    'top_destinations': defaultdict(int),
    'anomaly_rate': 0.0,
    'start_time': None
}
flow_data = defaultdict(int)
alerts = []

# Caches for quick hostname lookups
DNS_CACHE_TTL = 600  # seconds
dns_cache = {}
sni_cache = {}

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/stats')
def get_stats():
    """Get current statistics"""
    return jsonify(statistics)

@app.route('/api/packets')
def get_packets():
    """Get recent packets (last 100)"""
    return jsonify(packet_data[-100:])

@app.route('/api/flows')
def get_flows():
    """Get suspicious flows"""
    sorted_flows = sorted(flow_data.items(), key=lambda x: x[1], reverse=True)[:10]
    return jsonify([{'flow': flow, 'score': score} for flow, score in sorted_flows])

@app.route('/api/alerts')
def get_alerts():
    """Get recent alerts"""
    return jsonify(alerts[-50:])

def _prune_cache(cache, now):
    remove = [key for key, meta in cache.items() if meta.get('expires', 0) < now]
    for key in remove:
        cache.pop(key, None)


def _get_cached_hostname(ip, now):
    if not ip:
        return None
    record = dns_cache.get(ip)
    if record and record.get('expires', 0) >= now:
        return record.get('hostname')
    elif record:
        dns_cache.pop(ip, None)
    record = sni_cache.get(ip)
    if record and record.get('expires', 0) >= now:
        return record.get('hostname')
    elif record:
        sni_cache.pop(ip, None)
    return None


def add_packet(packet_info, anomaly_info):
    """Add a new packet to the web dashboard"""
    global packet_data, statistics
    now = time.time()

    try:
        # Enhance packet with hostname/service info
        packet_info = enhance_packet_info(packet_info)
    except Exception as e:
        print(f"[!] Warning: DNS enhancement failed: {e}")
        # Continue without enhancement

    # Update DNS cache from responses
    dns_answers = packet_info.get('dns_answers') or []
    dns_query = packet_info.get('dns_query')
    if dns_answers and dns_query:
        for answer_ip in dns_answers:
            dns_cache[str(answer_ip)] = {
                'hostname': dns_query,
                'expires': now + DNS_CACHE_TTL
            }

    # Update SNI cache for TLS ClientHello packets
    tls_sni = packet_info.get('tls_sni')
    dst_ip = packet_info.get('dst_ip')
    if tls_sni and dst_ip and dst_ip not in ('Unknown', 'N/A'):
        sni_cache[str(dst_ip)] = {
            'hostname': tls_sni,
            'expires': now + DNS_CACHE_TTL
        }

    # Prune expired cache entries periodically
    if statistics['total_packets'] % 100 == 0:
        _prune_cache(dns_cache, now)
        _prune_cache(sni_cache, now)

    # Apply cached hostname info if missing
    if not packet_info.get('dst_hostname') and dst_ip:
        cached = _get_cached_hostname(str(dst_ip), now)
        if cached:
            packet_info['dst_hostname'] = cached

    src_ip = packet_info.get('src_ip')
    if not packet_info.get('src_hostname') and src_ip:
        cached_src = _get_cached_hostname(str(src_ip), now)
        if cached_src:
            packet_info['src_hostname'] = cached_src

    if statistics['start_time'] is None:
        statistics['start_time'] = time.time()
    
    statistics['total_packets'] += 1
    
    # Unpack and normalize anomaly details to native Python types
    is_anomaly, anomaly_score, flow_score = anomaly_info
    try:
        is_anomaly_flag = bool(is_anomaly == -1)
    except Exception:
        # Fallback in case comparison fails (e.g., None)
        is_anomaly_flag = False
    try:
        anomaly_score_val = float(anomaly_score) if anomaly_score is not None else 0.0
    except Exception:
        anomaly_score_val = 0.0
    try:
        flow_score_val = int(flow_score) if flow_score is not None else 0
    except Exception:
        # Some detectors may return float; coerce safely
        try:
            flow_score_val = int(float(flow_score))
        except Exception:
            flow_score_val = 0
    
    if is_anomaly_flag:
        statistics['anomaly_packets'] += 1
    
    # Update protocol statistics
    protocol = packet_info.get('protocol', 'Unknown')
    statistics['protocols'][protocol] += 1
    
    # Update top sources/destinations
    src_ip = packet_info.get('src_ip', 'Unknown')
    dst_ip = packet_info.get('dst_ip', 'Unknown')
    statistics['top_sources'][src_ip] += 1
    statistics['top_destinations'][dst_ip] += 1
    
    # Calculate anomaly rate
    if statistics['total_packets'] > 0:
        statistics['anomaly_rate'] = (statistics['anomaly_packets'] / statistics['total_packets']) * 100
    
    # Create packet entry
    packet_entry = {
        'id': int(statistics['total_packets']),
        'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
        'src_ip': str(src_ip),
        'dst_ip': str(dst_ip),
        'src_hostname': str(packet_info.get('src_hostname', '') or ''),
        'dst_hostname': str(packet_info.get('dst_hostname', '') or ''),
        'protocol': str(protocol),
        'src_port': int(packet_info.get('src_port')) if isinstance(packet_info.get('src_port'), (int, float)) and packet_info.get('src_port') is not None else packet_info.get('src_port', 'N/A'),
        'dst_port': int(packet_info.get('dst_port')) if isinstance(packet_info.get('dst_port'), (int, float)) and packet_info.get('dst_port') is not None else packet_info.get('dst_port', 'N/A'),
        'app_proto': str(packet_info.get('app_proto', '') or ''),
        'service': str(packet_info.get('service', '') or ''),
        'size': int(packet_info.get('size', 0) or 0),
        'is_anomaly': bool(is_anomaly_flag),
        'anomaly_score': round(float(anomaly_score_val), 2),
        'flow_score': int(flow_score_val)
    }
    
    packet_data.append(packet_entry)
    
    # Keep only last 1000 packets in memory
    if len(packet_data) > 1000:
        packet_data.pop(0)
    
    # Track suspicious flows
    if flow_score >= 3:
        flow_key = f"{src_ip}:{packet_info.get('src_port', '')} → {dst_ip}:{packet_info.get('dst_port', '')} [{protocol}]"
        flow_data[flow_key] = flow_score
    
    # Emit to connected clients
    try:
        socketio.emit('new_packet', packet_entry)
        socketio.emit('stats_update', {
            'totalPackets': statistics['total_packets'],
            'anomalyPackets': statistics['anomaly_packets'],
            'anomalyRate': round(statistics['anomaly_rate'], 2),
            'runtime': int(time.time() - statistics['start_time']) if statistics['start_time'] else 0
        })
    except Exception as e:
        print(f"[!] Error emitting to web dashboard: {e}")

def add_alert(message):
    """Add an alert to the dashboard"""
    alert = {
        'timestamp': datetime.now().strftime('%H:%M:%S'),
        'message': message
    }
    alerts.append(alert)
    
    # Keep only last 100 alerts
    if len(alerts) > 100:
        alerts.pop(0)
    
    socketio.emit('new_alert', alert)

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print('[+] Client connected to web dashboard')
    emit('connection_response', {'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print('[+] Client disconnected from web dashboard')

def run_web_server(host='127.0.0.1', port=5000):
    """Run the Flask web server"""
    import socket
    
    # Try to find an available port if the default is in use
    original_port = port
    max_attempts = 10
    
    for attempt in range(max_attempts):
        try:
            # Test if port is available
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.bind((host, port))
            test_socket.close()
            
            # Port is available
            print(f'\n[+] Starting web dashboard at http://{host}:{port}')
            print(f'[+] Open your browser and navigate to: http://{host}:{port}\n')
            
            try:
                socketio.run(app, host=host, port=port, debug=False, use_reloader=False, log_output=False)
            except Exception as e:
                print(f'[!] Error starting web server: {e}')
            break
            
        except OSError:
            if attempt < max_attempts - 1:
                port += 1
            else:
                print(f'[!] Could not find available port between {original_port} and {port}')
                print(f'[!] Please close applications using these ports or specify a different port')
                return

if __name__ == '__main__':
    run_web_server()
