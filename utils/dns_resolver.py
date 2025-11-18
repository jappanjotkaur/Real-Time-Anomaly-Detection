"""
Enhanced packet parser with DNS resolution for better website visibility
"""
import socket
from functools import lru_cache

@lru_cache(maxsize=1000)
def resolve_ip_to_hostname(ip):
    """Resolve IP address to hostname/domain name"""
    try:
        # Set timeout for DNS lookup to prevent blocking
        socket.setdefaulttimeout(0.5)  # 500ms timeout
        
        # Quick reverse DNS lookup
        hostname = socket.gethostbyaddr(ip)[0]
        
        # Reset timeout
        socket.setdefaulttimeout(None)
        
        # Simplify common domains
        if 'google' in hostname.lower():
            return 'google.com'
        elif 'facebook' in hostname.lower() or 'fb' in hostname.lower():
            return 'facebook.com'
        elif 'youtube' in hostname.lower():
            return 'youtube.com'
        elif 'github' in hostname.lower():
            return 'github.com'
        elif 'cloudflare' in hostname.lower():
            return 'cloudflare.com'
        elif 'amazon' in hostname.lower() or 'aws' in hostname.lower():
            return 'amazon.com/aws'
        elif 'microsoft' in hostname.lower() or 'windows' in hostname.lower():
            return 'microsoft.com'
        elif 'apple' in hostname.lower():
            return 'apple.com'
        
        # Return simplified hostname
        parts = hostname.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])  # Return last 2 parts (e.g., example.com)
        return hostname
    except Exception as e:
        # Reset timeout on error
        socket.setdefaulttimeout(None)
        return None

def get_service_name(port, protocol):
    """Get common service name from port"""
    common_ports = {
        80: 'HTTP',
        443: 'HTTPS',
        53: 'DNS',
        22: 'SSH',
        21: 'FTP',
        25: 'SMTP',
        110: 'POP3',
        143: 'IMAP',
        3389: 'RDP',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        6379: 'Redis',
        27017: 'MongoDB',
        8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt'
    }
    
    if protocol in ['TCP', 'UDP']:
        try:
            port_num = int(port) if port != 'N/A' else 0
            return common_ports.get(port_num, '')
        except:
            return ''
    return ''

def enhance_packet_info(packet_info):
    """Add hostname and service information to packet"""
    # Resolve destination IP to hostname (most interesting)
    dst_ip = packet_info.get('dst_ip', '')
    if dst_ip and dst_ip not in ['N/A', 'Unknown', '127.0.0.1', '0.0.0.0']:
        hostname = resolve_ip_to_hostname(dst_ip)
        if hostname:
            packet_info['dst_hostname'] = hostname
    
    # Resolve source IP to hostname
    src_ip = packet_info.get('src_ip', '')
    if src_ip and src_ip not in ['N/A', 'Unknown', '127.0.0.1', '0.0.0.0']:
        hostname = resolve_ip_to_hostname(src_ip)
        if hostname:
            packet_info['src_hostname'] = hostname
    
    # Add service name based on port
    dst_port = packet_info.get('dst_port', 'N/A')
    protocol = packet_info.get('protocol', '')
    service = get_service_name(dst_port, protocol)
    if service:
        packet_info['service'] = service
    
    return packet_info
