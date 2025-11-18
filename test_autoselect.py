from colorama import init, Fore
from scapy.all import get_if_list, get_if_addr, conf

init(autoreset=True)

def select_best_interface(devices):
    """Try to automatically select the best network interface"""
    if not devices:
        return None
    
    from scapy.all import get_if_addr, conf
    
    # First try Scapy's default interface
    try:
        default_iface = conf.iface
        if default_iface in devices:
            ip = get_if_addr(default_iface)
            if ip and ip != '0.0.0.0' and "Loopback" not in default_iface:
                print(Fore.GREEN + f"[+] Auto-selected default interface: {default_iface} (IP: {ip})")
                return default_iface
    except:
        pass
    
    # Try to find an interface with a valid IP address
    for i, device in enumerate(devices):
        if "Loopback" not in device:
            try:
                ip = get_if_addr(device)
                # Prefer non-link-local addresses (not 169.254.x.x)
                if ip and ip != '0.0.0.0' and not ip.startswith('169.254'):
                    print(Fore.GREEN + f"[+] Auto-selected interface {i}: {device} (IP: {ip})")
                    return device
            except:
                pass
    
    # Fallback: try to find any interface with an IP (including link-local)
    for i, device in enumerate(devices):
        if "Loopback" not in device:
            try:
                ip = get_if_addr(device)
                if ip and ip != '0.0.0.0':
                    print(Fore.YELLOW + f"[+] Auto-selected interface {i}: {device} (IP: {ip})")
                    return device
            except:
                pass
    
    # Last resort - return first non-loopback interface
    for device in devices:
        if "Loopback" not in device:
            print(Fore.YELLOW + f"[+] Auto-selected first non-loopback interface: {device}")
            return device
    
    return devices[0] if devices else None

# Test the function
print(Fore.CYAN + "Testing automatic interface selection...\n")
devices = get_if_list()
selected = select_best_interface(devices)
print(Fore.CYAN + f"\nResult: {selected}")
