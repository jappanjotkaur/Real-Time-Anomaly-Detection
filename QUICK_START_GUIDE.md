# Quick Start Web Dashboard Guide

## Overview
`quick_start_web.py` provides the fastest way to start capturing packets with the web dashboard interface.

## Features
- ✅ **Automatic interface selection** - No manual interface configuration needed
- ✅ **Auto-opens browser** - Dashboard opens automatically in your default browser
- ✅ **Minimal prompts** - Only 2 simple questions to get started
- ✅ **Persistent dashboard** - Web interface stays running after capture completes
- ✅ **Smart defaults** - Pre-configured with sensible defaults

## Quick Start

### Option 1: Default Configuration (Fastest)
```powershell
python quick_start_web.py
# Press Enter twice to use defaults
# Captures 100 packets, no filter
```

### Option 2: Custom Configuration
```powershell
python quick_start_web.py
# Enter number of packets (0 for unlimited)
# Enter BPF filter if needed (e.g., "tcp port 80")
```

## Usage Examples

### Capture 50 packets
```powershell
python quick_start_web.py
# Enter: 50
# Press Enter (no filter)
```

### Capture HTTP traffic only
```powershell
python quick_start_web.py
# Enter: 100
# Enter: tcp port 80
```

### Capture DNS queries
```powershell
python quick_start_web.py
# Enter: 0 (unlimited)
# Enter: udp port 53
```

### Monitor specific IP
```powershell
python quick_start_web.py
# Enter: 0
# Enter: host 192.168.1.100
```

## What Happens When You Run It

1. **Auto-detects** your best network interface
2. **Asks** for packet count (default: 100)
3. **Asks** for optional BPF filter
4. **Starts** web server at http://127.0.0.1:5000
5. **Opens** browser automatically after 2 seconds
6. **Begins** packet capture
7. **Keeps running** after capture completes so you can analyze data

## Stopping the Application

- **During capture**: Press `Ctrl+C` once
- **After capture**: Press `Ctrl+C` to stop web server

## Dashboard Features

The web dashboard displays:
- 📊 Real-time packet statistics
- 📈 Packet rate graphs
- 📋 Recent packets table
- 🚨 Anomaly alerts
- 🔍 Protocol distribution
- ⚠️ Suspicious flow detection

## Comparison with Other Scripts

| Feature | quick_start_web.py | main_web.py | main.py |
|---------|-------------------|-------------|---------|
| Auto interface | ✅ Yes | ⚠️ Optional | ⚠️ Optional |
| Auto browser | ✅ Yes | ❌ No | ❌ No |
| Web dashboard | ✅ Yes | ✅ Yes | ❌ No |
| Minimal prompts | ✅ 2 questions | ⚠️ 7 questions | ⚠️ 6 questions |
| Persistent dashboard | ✅ Yes | ✅ Yes* | N/A |
| Best for | Quick testing | Detailed config | Terminal only |

*After recent fix

## Troubleshooting

### Browser doesn't open automatically
- Manually navigate to http://127.0.0.1:5000
- Check firewall settings

### Connection refused error
- Wait a few seconds for server to fully start
- Refresh the browser page

### No packets captured
- Generate network traffic (browse web, ping)
- Check if running as Administrator
- Try different network interface (use main_web.py for manual selection)

### Port 5000 already in use
- Close other applications using port 5000
- Or modify the port in the script

## Advanced Usage

### Change default port
Edit `quick_start_web.py` line with `run_web_server`:
```python
web_thread = threading.Thread(
    target=run_web_server, 
    kwargs={'host': '127.0.0.1', 'port': 8080},  # Change to 8080
    daemon=True
)
```

### Change default packet count
Edit the default value:
```python
else:
    count = 100  # Change this number
```

### Disable auto-browser opening
Comment out the browser thread section:
```python
# browser_thread = threading.Thread(
#     target=open_browser_delayed,
#     args=('http://127.0.0.1:5000', 2),
#     daemon=True
# )
# browser_thread.start()
```

## Requirements
- Python 3.7+
- Scapy
- Flask
- Flask-SocketIO
- Npcap (Windows)
- Administrator/Root privileges

## Tips
1. **Start with 50-100 packets** to test functionality
2. **Use filters** to focus on specific traffic
3. **Keep dashboard open** after capture to analyze results
4. **Check Recent Alerts** section for anomalies
5. **Export PCAP files** from captures/ directory for further analysis

## Support
For issues or questions:
1. Check WEB_DASHBOARD_GUIDE.md for detailed dashboard info
2. Review README.md for general project information
3. Check captures/ directory for saved PCAP files
