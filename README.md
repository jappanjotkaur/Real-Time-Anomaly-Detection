# NetCortex: Advanced Network Traffic Anomaly Detection System

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)

## Overview
NetCortex is a **cutting-edge network security tool** that combines real-time packet capture with advanced AI-powered anomaly detection. This unique and innovative system goes beyond traditional network monitoring by implementing zero-day attack detection, automated incident response, continuous learning, and multi-channel alerting. It provides comprehensive network visibility and proactive threat detection capabilities.

## 🚀 Unique & Innovative Features

### 🔍 Zero-Day Attack Detection
- **Graph Neural Network-based Detection**: Uses network topology graphs to identify unknown attack patterns
- **Behavioral Pattern Analysis**: Detects novel attack vectors by analyzing network structure anomalies
- **Multi-stage Attack Recognition**: Identifies complex attack chains (recon → exploit → C2 → exfiltration)
- **Real-time Pattern Matching**: Detects never-before-seen attack signatures

### 🤖 Automated Incident Response
- **Intelligent IP Blocking**: Automatically blocks/throttles malicious IPs (Linux/Windows)
- **Rate Limiting**: Dynamic traffic shaping based on threat severity
- **Whitelist Management**: Protects trusted IPs from false positives
- **Response Logging**: Complete audit trail of all response actions

### 🌐 Threat Intelligence Integration
- **Multi-Source Feed Aggregation**: Integrates data from Abuse.ch, AlienVault OTX, Emerging Threats, and more
- **Real-time IOC Checking**: Instantly identifies known malicious IPs, domains, and URLs
- **Local Cache System**: Fast lookups with automatic cache updates
- **Custom IOC Support**: Add your own threat indicators

### 📢 Multi-Channel Alerting System
- **Email Notifications**: Rich HTML emails with threat details
- **Slack Integration**: Real-time alerts to Slack channels
- **Telegram Bot**: Mobile-friendly threat notifications
- **Webhook Support**: Integrate with any custom system
- **Rate Limiting**: Prevents alert fatigue

### 🧠 Continuous Learning Pipeline
- **Automatic Model Retraining**: Continuously improves detection accuracy
- **Adaptive Thresholds**: Adjusts to your network's normal behavior
- **Version Control**: Tracks model improvements over time
- **Performance Monitoring**: Real-time accuracy metrics

### 💡 Explainable AI
- **Human-Readable Explanations**: Understand why threats were detected
- **Confidence Scores**: Know how certain the system is about each alert
- **Recommendation Engine**: Actionable security recommendations
- **Severity Classification**: Clear threat severity levels (low/medium/high/critical)

### 📊 Advanced Analytics
- **Behavioral Profiling**: Learn normal behavior for each device/IP
- **Temporal Pattern Analysis**: Detect anomalies based on time patterns
- **Network Topology Mapping**: Visualize network connections and relationships
- **TLS/SSL Fingerprinting**: Analyze encrypted traffic without decryption

### Real-time Packet Analysis
- Capture packets on any network interface with promiscuous mode support
- Detailed protocol identification and packet decoding (Ethernet, IPv4, IPv6, TCP, UDP, ICMP, etc.)
- Application protocol recognition (HTTP, HTTPS, DNS, DHCP, etc.)
- BPF filter support for targeted packet capture
- TCP flags and connection state tracking

### Machine Learning Detection
- **Ensemble Models**: Isolation Forest, Autoencoder, and LSTM working together
- **Multi-dimensional Feature Analysis**:
  - Packet size deviations
  - Protocol anomalies
  - Timing pattern irregularities
  - Flow behavior analysis
  - Port usage statistics
- **Adaptive Learning**: Continuous model updates with new data
- **Persistent Model Storage**: Improved detection over time

### Interactive Web Dashboard
- Real-time packet stream visualization
- Protocol distribution charts
- Threat severity heatmaps
- Network topology graphs
- Alert history and statistics
- Device behavior profiles

## Technical Details

### Architecture
NetCortex is organized into modular components:
- **Packet Capture**: Interfaces directly with network hardware
- **Packet Parser**: Decodes and extracts packet information
- **Anomaly Detector**: Applies machine learning for threat detection
- **Visualizer**: Presents information in a readable format
- **PCAP Handler**: Manages storage and retrieval of packet data

### Machine Learning Implementation
- **Algorithm**: Isolation Forest for unsupervised anomaly detection
- **Feature Extraction**: 8 dimensional feature vectors including:
  - Packet size
  - Protocol identification
  - Source/destination port analysis
  - Inter-packet timing
  - Flow metrics (packet count, byte count)
  - Rate analysis
- **Model Persistence**: Continuous learning with model saving/loading
- **Adaptive Thresholds**: Dynamic anomaly scoring based on historical data

## Requirements
- Python 3.7 for pcap library
- Root/sudo privileges (required for packet capture)
- Linux-based operating system (tested on Ubuntu/Debian)
- Required packages:
  - pcap
  - dpkt
  - rich
  - colorama
  - scikit-learn
  - numpy
  - pandas
  - joblib

## Installation

```bash
# Clone the repository
git clone https://github.com/your-username/NetCortex.git
cd NetCortex

# Create a virtual environment with Python 3.7 (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Ensure you have libpcap development headers
# On Debian/Ubuntu systems:
sudo apt-get install libpcap-dev
```

We strongly recommend using a virtual environment with Python 3.7, as this version has been thoroughly tested with all dependencies in this project. This ensures compatibility and prevents conflicts with other Python packages installed on your system.

## Usage

### Basic Usage
```bash
# Run with sudo (required for packet capture)
sudo python3 main.py
```

The interactive prompt will guide you through:
1. Selecting a network interface from available options
2. Setting optional BPF filters (e.g., "tcp port 80" to capture only HTTP traffic)
3. Configuring maximum packet count or continuous capture
4. Specifying output directory for PCAP files
5. Selecting existing model or creating a new one

### Command Line Options
```bash
# Analyze an existing PCAP file
sudo python3 main.py -a /path/to/capture.pcap

# Specify a network interface directly
sudo python3 main.py -i eth0

# Set a maximum packet count
sudo python3 main.py -c 1000

# Specify custom output directory
sudo python3 main.py -o ./my_captures

# Use a specific model file
sudo python3 main.py -m ./my_model/custom_model.pkl
```

### Understanding the Interface
- The main display shows captured packets with protocol information and anomaly scores
- Red highlighted entries indicate potential anomalies
- The "Flow Score" column shows the suspicion level of the packet's connection
- Alerts appear when flow scores exceed the threshold
- Summary statistics are displayed at the bottom

## Project Structure
```
NetCortex/
├── main.py                      # Application entry point
├── config.py                    # Configuration settings
├── requirements.txt             # Dependencies
├── README.md                    # Documentation
├── LICENSE                      # MIT License
├── analyzer/                    # Analysis components
│   ├── __init__.py
│   ├── packet_sniffer.py        # Main packet capturing class
│   ├── pcap_analyzer.py         # PCAP file analyzer
│   └── visualizer.py            # TUI display
├── models/                      # Machine learning
│   ├── __init__.py
│   └── anomaly_detector.py      # ML-based detection
├── utils/                       # Utilities
│   ├── __init__.py
│   ├── packet_parser.py         # Packet decoding
│   ├── pcap_handler.py          # PCAP file operations
│   └── protocol_maps.py         # Protocol definitions
├── captures/                    # Output directory
└── model/                       # Saved ML models
```

## Quick Start

### Basic Usage
```bash
# Standard mode
python main_web.py

# Advanced mode (with all features)
python main_advanced.py
```

### Advanced Configuration
Edit `config_advanced.py` to configure:
- Incident response settings
- Alert channels (Email, Slack, Telegram)
- Threat intelligence feeds
- Continuous learning parameters

### Enable Alert Channels

**Email Alerts:**
```python
ALERTING_CONFIG = {
    'email': {
        'enabled': True,
        'smtp_server': 'smtp.gmail.com',
        'smtp_port': 587,
        'username': 'your_email@gmail.com',
        'password': 'your_app_password',
        'recipients': ['admin@yourdomain.com']
    }
}
```

**Slack Alerts:**
```python
ALERTING_CONFIG = {
    'slack': {
        'enabled': True,
        'webhook_url': 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL',
        'channel': '#security-alerts'
    }
}
```

## Advanced Features Guide

### Zero-Day Detection
The zero-day detector builds network graphs over time windows and identifies structural anomalies that indicate unknown attacks. It detects:
- Lateral movement patterns
- Data exfiltration attempts
- Command and control communication
- Privilege escalation chains
- Reconnaissance activities

### Automated Incident Response
When threats are detected, the system can automatically:
- Block malicious IPs using firewall rules
- Throttle suspicious traffic
- Log all response actions
- Respect whitelisted IPs

**Warning**: Auto-blocking requires administrator/root privileges.

### Threat Intelligence
The system automatically updates threat intelligence feeds and checks all network traffic against:
- Known malicious IP addresses
- Malware domains
- Compromised URLs
- Emerging threat indicators

### Continuous Learning
The continuous learning pipeline:
- Collects packet features in real-time
- Retrains models automatically (configurable interval)
- Improves detection accuracy over time
- Maintains version history

## Architecture

### Component Overview
```
┌─────────────────────────────────────────────────────────┐
│              NetCortex Advanced Edition                 │
├─────────────────────────────────────────────────────────┤
│  Packet Capture → Parser → Feature Extraction          │
│       ↓                                                  │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Advanced Detection Engine                       │  │
│  │  • ML Models (Isolation Forest, Autoencoder,     │  │
│  │    LSTM)                                         │  │
│  │  • Zero-Day Detector                             │  │
│  │  • Behavioral Profiler                           │  │
│  │  • Threat Intelligence                           │  │
│  │  • TLS Fingerprinting                            │  │
│  │  • Explainable AI                                │  │
│  └──────────────────────────────────────────────────┘  │
│       ↓                                                  │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Response & Alerting                             │  │
│  │  • Incident Response Engine                      │  │
│  │  • Multi-Channel Alerting                        │  │
│  │  • Continuous Learning                           │  │
│  └──────────────────────────────────────────────────┘  │
│       ↓                                                  │
│  Web Dashboard / Alerts / Logs                          │
└─────────────────────────────────────────────────────────┘
```

## Limitations and Future Work
- Currently supports Ethernet-based networks
- TLS fingerprinting works without decryption
- Auto-blocking requires admin privileges
- Future enhancements:
  - Distributed sensor deployment
  - Deep packet inspection capabilities
  - Honeypot integration
  - Advanced forensics tools (packet replay, timeline reconstruction)
  - Machine learning model explainability improvements
  - 3D network visualization
  - Dark web intelligence integration

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing
Contributions are welcome! Please feel free to submit pull requests.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Acknowledgments
- Thanks to the developers of pcap, dpkt, and scikit-learn
- Inspired by tools like Wireshark, Suricata, and Zeek

## Contact
For questions or support, please open an issue on GitHub.
