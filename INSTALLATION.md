# Installation Guide - Advanced Features

## Prerequisites

- Python 3.8 or higher
- Administrator/root privileges (for auto-blocking feature)
- Windows: Npcap or WinPcap installed
- Linux: libpcap development headers

## Step-by-Step Installation

### 1. Create Virtual Environment (Recommended)

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

**Note for Windows users:** The `pcap` package is Linux-only. On Windows, the project uses Scapy instead, which is already in requirements.txt.

### 3. Install Additional Dependencies (if needed)

If you encounter any missing module errors, install them individually:

```bash
# Required for advanced features
pip install networkx
pip install requests

# Already in requirements.txt but verify:
pip install scapy
pip install flask flask-socketio flask-cors
pip install scikit-learn numpy pandas joblib
pip install tensorflow  # Optional, for advanced ML models
```

### 4. Verify Installation

Test that all modules can be imported:

```bash
python -c "from detectors.advanced_integration import AdvancedDetectionEngine; print('✓ All modules installed successfully!')"
```

### 5. Configure Advanced Features

Edit `config_advanced.py` to configure:
- Incident response settings
- Alert channels (Email, Slack, Telegram)
- Threat intelligence feeds
- Continuous learning parameters

### 6. Run the Application

**Standard Mode:**
```bash
python main_web.py
```

**Advanced Mode (with all features):**
```bash
python main_advanced.py
```

## Windows-Specific Installation

### Installing Npcap

1. Download Npcap from: https://nmap.org/npcap/
2. Install with "WinPcap API-compatible Mode" option
3. Restart your computer if prompted

### Running as Administrator

For auto-blocking features, run PowerShell or Command Prompt as Administrator:

```powershell
# Right-click PowerShell -> Run as Administrator
cd D:\celebalnetsniff
venv\Scripts\Activate.ps1
python main_advanced.py
```

## Linux-Specific Installation

### Install libpcap Development Headers

```bash
# Ubuntu/Debian
sudo apt-get install libpcap-dev

# CentOS/RHEL
sudo yum install libpcap-devel

# Fedora
sudo dnf install libpcap-devel
```

### Running with Root Privileges

For packet capture and auto-blocking:

```bash
sudo python main_advanced.py
```

## Troubleshooting

### ModuleNotFoundError: No module named 'networkx'

```bash
pip install networkx
```

### ModuleNotFoundError: No module named 'requests'

```bash
pip install requests
```

### Permission Denied (Packet Capture)

**Windows:**
- Run as Administrator
- Ensure Npcap is installed
- Check that your user has permission to capture packets

**Linux:**
- Run with `sudo`
- Add your user to appropriate groups: `sudo usermod -aG wireshark $USER`
- Log out and log back in

### Auto-blocking Not Working

1. Verify you're running as Administrator/root
2. Check firewall configuration
3. Review logs: `logs/incident_response.log`
4. Test manually:
   ```bash
   # Linux
   sudo iptables -A INPUT -s 1.2.3.4 -j DROP
   
   # Windows
   netsh advfirewall firewall add rule name="Test" dir=in action=block remoteip=1.2.3.4
   ```

### TensorFlow Installation Issues

TensorFlow is optional for basic functionality. If you encounter issues:

```bash
# CPU-only version (smaller, easier to install)
pip install tensorflow-cpu

# Or skip TensorFlow and use scikit-learn only
# The system will fall back to scikit-learn models
```

### Web Dashboard Not Loading

1. Check if port 5000 is available:
   ```bash
   # Windows
   netstat -ano | findstr :5000
   
   # Linux
   netstat -tuln | grep 5000
   ```

2. Try a different port by editing `web_app.py` or `main_advanced.py`

3. Check firewall settings

## Development Setup

For development, install additional packages:

```bash
pip install pytest pytest-cov black flake8
```

## Docker Installation (Optional)

```dockerfile
FROM python:3.11-slim

# Install dependencies
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["python", "main_advanced.py"]
```

## Verification Checklist

- [ ] Python 3.8+ installed
- [ ] Virtual environment created and activated
- [ ] All dependencies installed
- [ ] NetworkX installed
- [ ] Requests installed
- [ ] Scapy installed
- [ ] Npcap installed (Windows) or libpcap-dev (Linux)
- [ ] Configuration file edited (`config_advanced.py`)
- [ ] Test import successful
- [ ] Can run `main_advanced.py` without errors

## Next Steps

1. Review `config_advanced.py` and configure settings
2. Read `ADVANCED_FEATURES.md` for feature documentation
3. Check `QUICK_START_ADVANCED.md` for usage guide
4. Start with monitoring only (disable auto-blocking initially)
5. Configure alert channels
6. Monitor and tune thresholds

## Support

If you encounter issues:
1. Check the troubleshooting section above
2. Review logs in `logs/` directory
3. Check GitHub issues
4. Review documentation files

