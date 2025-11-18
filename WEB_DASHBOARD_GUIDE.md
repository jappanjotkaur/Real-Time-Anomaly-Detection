# NetSniff Guard - Web Dashboard Guide

## 🌐 Web Dashboard Features

The web dashboard provides a modern, real-time visualization of network traffic with:

- **Real-time Statistics**: Total packets, anomalies, anomaly rate, runtime
- **Interactive Charts**: Protocol distribution (doughnut chart), packet rate over time (line chart)
- **Live Packet Table**: Last 50 packets with color-coded anomaly indicators
- **Alert System**: Real-time alerts for suspicious traffic
- **Responsive Design**: Works on desktop and mobile browsers

## 🚀 Quick Start

### Option 1: Run with Web Dashboard

```powershell
python main_web.py
```

Follow the prompts:
1. **Use web dashboard?** → Type `y`
2. **Analyze existing PCAP?** → Type `n` (for live capture)
3. **Use automatic detection?** → Type `y`
4. **BPF filter** → Press Enter
5. **Max packets** → Type a number or press Enter for unlimited
6. **Output directory** → Press Enter
7. **Model file** → Press Enter
8. **Start capture?** → Type `y`

**Open your browser to: http://127.0.0.1:5000**

### Option 2: Run Terminal Mode Only

```powershell
python main.py
```

This runs the original terminal-based interface without the web dashboard.

## 📊 Dashboard Sections

### Statistics Cards
- **Total Packets**: Count of all captured packets
- **Anomaly Packets**: Count of packets flagged as anomalous
- **Anomaly Rate**: Percentage of anomalous packets
- **Runtime**: How long capture has been running

### Protocol Distribution Chart
Shows breakdown of traffic by protocol (TCP, UDP, ICMP, ARP, etc.)

### Packet Rate Chart
Real-time line graph showing packets captured per second over the last 60 seconds

### Recent Packets Table
- Shows last 50 packets
- Color-coded rows (red background = anomaly)
- Columns: ID, Time, Source IP, Dest IP, Protocol, Ports, Size, Status, Flow Score
- Flow scores: Green (0-3), Yellow (4-5), Red (6+)

### Alerts Section
Displays critical alerts when highly suspicious flows are detected (flow score ≥ 5)

## 🎨 Features

### Real-time Updates
- Dashboard updates instantly as packets are captured
- Uses WebSocket (Socket.IO) for low-latency updates
- No page refresh needed

### Visual Indicators
- **Green badges**: Normal traffic
- **Red badges**: Anomaly detected
- **Flow scores**: Color-coded severity (low/medium/high)
- **Anomalous rows**: Red-tinted background

### Connection Status
- Top-right indicator shows connection to capture engine
- Green pulsing dot = Connected
- Red dot = Disconnected

## 🔧 Technical Details

### Architecture
- **Backend**: Flask web server with Socket.IO
- **Frontend**: HTML5, CSS3, vanilla JavaScript
- **Charts**: Chart.js library
- **Communication**: WebSocket for real-time data push

### Ports
- Web dashboard: `http://127.0.0.1:5000`
- Change in `main_web.py` if port 5000 is in use

### Browser Compatibility
- Chrome/Edge (recommended)
- Firefox
- Safari
- Any modern browser with WebSocket support

## 📝 Usage Tips

1. **Generate Traffic**: Browse websites, download files, or ping servers to see packets flow
2. **Filter Traffic**: Use BPF filters like `tcp port 443` to focus on HTTPS traffic
3. **Watch for Anomalies**: Red-highlighted packets indicate suspicious behavior
4. **Monitor Flow Scores**: High scores (6+) indicate persistent suspicious connections
5. **Check Alerts**: Bottom section shows critical security alerts

## 🐛 Troubleshooting

### Web Dashboard Won't Load
- Ensure port 5000 is not in use
- Check firewall settings
- Verify Flask and Flask-SocketIO are installed: `pip list | findstr flask`

### No Packets Appearing
- Make sure you're running as Administrator (required for packet capture)
- Generate network traffic (browse web, ping google.com)
- Check if correct network interface is selected
- Verify Npcap is installed

### Connection Issues
- Refresh the browser page
- Restart the capture application
- Check console for errors (F12 in browser)

## 📦 Required Packages

```
flask
flask-socketio
flask-cors
eventlet
scapy
```

All installed automatically when you first ran the application.

## 🎯 Example Session

```powershell
PS> python main_web.py
Do you want to use the web dashboard? (y/n): y
[+] Web dashboard starting...
[+] Open your browser to: http://127.0.0.1:5000

Do you want to analyze an existing PCAP file? (y/n): n
Use automatic interface detection? (recommended) (y/n): y
[+] Auto-selected interface 3: \Device\NPF_{...} (IP: 192.168.29.40)

... (follow remaining prompts) ...

[+] Starting packet capture... Press Ctrl+C to stop
[+] View real-time dashboard at: http://127.0.0.1:5000
```

Then open http://127.0.0.1:5000 in your browser to see the beautiful dashboard!

## 🌟 Benefits Over Terminal Interface

- **Better Visualization**: Charts and graphs vs. text tables
- **Persistent View**: Dashboard stays visible while capturing
- **Multi-Device**: View from any device on your network
- **Historical Data**: Scroll through captured packets easily
- **Professional Look**: Modern UI perfect for demos or presentations

---

**Enjoy your enhanced NetSniff Guard experience!** 🛡️
