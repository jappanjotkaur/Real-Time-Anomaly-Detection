# NetSniff Guard - Comprehensive Project Documentation

## Executive Summary

**NetSniff Guard** is an advanced network traffic anomaly detection system that combines real-time packet capture with machine learning-based threat detection. The system monitors network traffic in real-time, extracts meaningful features from packets, applies multiple unsupervised learning algorithms to identify anomalies, and presents results through an interactive web dashboard.

---

## 1. Project Architecture Overview

### 1.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    NetSniff Guard System                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────────┐ │
│  │   Network    │      │   Packet     │      │   Feature    │ │
│  │  Interface   │─────▶│   Capture    │─────▶│  Extraction  │ │
│  │  (Npcap/     │      │   (Scapy)    │      │   (8-Dim)    │ │
│  │  Scapy)      │      │              │      │              │ │
│  └──────────────┘      └──────────────┘      └──────────────┘ │
│                                 │                              │
│                                 ▼                              │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │         Anomaly Detection Engine (ML Models)              │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │ │
│  │  │Isolation │ │  Kernel  │ │ One-Class│ │   LOF    │   │ │
│  │  │ Forest   │ │ Density  │ │   SVM    │ │          │   │ │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐               │ │
│  │  │  HBOS    │ │Autoencoder│ │  Custom  │               │ │
│  │  └──────────┘ └──────────┘ └──────────┘               │ │
│  └──────────────────────────────────────────────────────────┘ │
│                                 │                              │
│                                 ▼                              │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────────┐ │
│  │   Threat     │      │   Web        │      │   PCAP       │ │
│  │ Intelligence │      │  Dashboard   │      │   Storage    │ │
│  │  (DNS/TLS)   │      │  (Flask)     │      │   (Files)    │ │
│  └──────────────┘      └──────────────┘      └──────────────┘ │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Component Breakdown

The system consists of several interconnected modules:

1. **Packet Capture Layer** - Raw network traffic interception
2. **Packet Parser** - Protocol decoding and information extraction
3. **Feature Engineering** - Statistical feature computation
4. **ML Detection Engine** - Multiple unsupervised anomaly detectors
5. **Web Dashboard** - Real-time visualization and monitoring
6. **Evaluation Framework** - Model benchmarking and metrics
7. **Threat Intelligence** - DNS/TLS hostname resolution

---

## 2. Packet Capture and Parsing

### 2.1 Network Interface Selection

**Technology**: Scapy (cross-platform), Npcap (Windows)

The system automatically detects and selects the best network interface:
- **Priority 1**: Interface with valid non-link-local IP (e.g., 192.168.x.x)
- **Priority 2**: Any interface with assigned IP
- **Priority 3**: First non-loopback interface

**Implementation** (`quick_start_web.py`, `main_web.py`):
```python
def select_best_interface():
    # Scans all interfaces
    # Filters out loopback and link-local addresses
    # Returns interface with best connectivity
```

### 2.2 Packet Capture Process

**Capture Method**: Promiscuous mode packet sniffing

1. **Initialization**: Opens network interface in promiscuous mode
2. **Filtering**: Optional BPF (Berkeley Packet Filter) support
   - Example: `tcp port 443` (HTTPS only)
   - Example: `udp port 53` (DNS only)
3. **Storage**: All packets saved to PCAP files in `captures/` directory
4. **Real-time Processing**: Each packet immediately parsed and analyzed

**Key Files**:
- `analyzer/packet_sniffer.py` - Main capture engine
- `utils/packet_parser.py` - Protocol decoding

### 2.3 Protocol Parsing

**Supported Protocols**:

#### Layer 2 (Data Link)
- **Ethernet**: MAC address extraction, frame type identification
- **ARP**: Request/Reply detection, IP-to-MAC mapping

#### Layer 3 (Network)
- **IPv4**: Source/destination IP extraction, protocol identification
- **ICMP**: Type and code analysis (Echo, Unreachable, etc.)

#### Layer 4 (Transport)
- **TCP**: 
  - Port extraction (source/destination)
  - Flag analysis (SYN, ACK, FIN, RST, PSH, URG)
  - Sequence number tracking
  - Application protocol detection (HTTP, HTTPS)
- **UDP**:
  - Port extraction
  - Application protocol detection (DNS, DHCP, NTP)

#### Layer 7 (Application)
- **HTTP**: Request method extraction (GET, POST), URL parsing
- **HTTPS/TLS**: 
  - Handshake detection
  - **SNI (Server Name Indication) extraction** - Identifies target domain
- **DNS**: 
  - Query/Response parsing
  - Domain name extraction
  - IP address resolution tracking

**Parsing Flow**:
```
Raw Packet Bytes
    ↓
Ethernet Frame Analysis
    ↓
IP Header Extraction
    ↓
Protocol-Specific Parsing (TCP/UDP/ICMP)
    ↓
Application Layer Detection
    ↓
Structured Packet Info Dictionary
```

**Output Structure**:
```python
packet_info = {
    "src_ip": "192.168.1.100",
    "dst_ip": "104.18.18.125",
    "src_port": 52391,
    "dst_port": 443,
    "protocol": "TCP",
    "app_proto": "HTTPS",
    "size": 135,
    "details": "Flags: PSH ACK",
    "tls_sni": "example.com",  # Extracted from TLS handshake
    "dns_query": "example.com",  # From DNS packets
    "dns_answers": ["104.18.18.125"]
}
```

---

## 3. Feature Engineering

### 3.1 Feature Extraction Pipeline

**Purpose**: Convert raw packet information into numerical features suitable for machine learning.

**8-Dimensional Feature Vector**:

1. **Packet Size** (`packet_size`)
   - Raw packet size in bytes
   - Indicates data transfer patterns
   - Anomalies: Unusually large/small packets

2. **Protocol Number** (`protocol_num`)
   - Mapped protocol identifier
   - TCP=6, UDP=17, ICMP=1, etc.
   - Detects protocol misuse

3. **Source Port** (`src_port`)
   - Client-side port number
   - Ephemeral ports (49152-65535) vs. well-known ports
   - Identifies client behavior patterns

4. **Destination Port** (`dst_port`)
   - Server-side port number
   - Service identification (80=HTTP, 443=HTTPS, 22=SSH)
   - Detects port scanning or unusual service access

5. **Time Delta** (`time_delta`)
   - Time between consecutive packets in same flow
   - Measures communication frequency
   - Anomalies: Burst traffic, slow loris attacks

6. **Packet Count** (`packet_count`)
   - Total packets in current flow
   - Tracks connection duration/activity
   - Identifies long-lived suspicious connections

7. **Bytes Total** (`bytes_total`)
   - Cumulative bytes transferred in flow
   - Detects data exfiltration or large transfers
   - Anomalies: Unusually high data volumes

8. **Average Packet Rate** (`avg_packet_rate`)
   - Packets per second in flow
   - Calculated from time intervals
   - Identifies flooding or DDoS patterns

**Implementation** (`models/anomaly_detector.py`):
```python
def extract_features(packet_info, timestamp):
    # Flow tracking per (src_ip, src_port, dst_ip, dst_port, protocol)
    # Updates flow statistics
    # Computes time-based features
    # Returns 8-dimensional numpy array
```

### 3.2 Flow Tracking

**Flow Definition**: A flow is a unique communication stream identified by:
- Source IP + Source Port
- Destination IP + Destination Port  
- Protocol

**Flow Statistics Maintained**:
- Packet count per flow
- Total bytes per flow
- Inter-packet intervals (last 50)
- Last seen timestamp

**Purpose**: 
- Context-aware anomaly detection
- Identifies persistent suspicious connections
- Tracks communication patterns over time

---

## 4. Anomaly Detection Models

### 4.1 Model Architecture

The system employs **multiple unsupervised learning algorithms** working in parallel:

#### 4.1.1 Isolation Forest
**Type**: Tree-based ensemble method

**How It Works**:
- Randomly selects features and split values
- Creates isolation trees
- Anomalies are easier to isolate (fewer splits needed)
- Returns anomaly score based on path length

**Advantages**:
- Fast training and prediction
- Handles high-dimensional data well
- No assumptions about data distribution
- Effective for network traffic patterns

**Configuration**:
- Contamination: 5% (expected anomaly rate)
- Random state: 42 (reproducibility)

**Performance** (from evaluation):
- ROC AUC: 0.978
- PR AUC: 0.957
- F1 Score: 0.897

#### 4.1.2 Kernel Density Estimation (KDE)
**Type**: Non-parametric density estimation

**How It Works**:
- Estimates probability density function using Gaussian kernels
- Low-density regions = anomalies
- Uses bandwidth parameter to control smoothness

**Advantages**:
- Captures complex distributions
- No parametric assumptions
- Good for multi-modal data

**Performance**:
- ROC AUC: 1.000
- PR AUC: 0.999
- F1 Score: 0.991
- **Best performing model**

#### 4.1.3 One-Class SVM
**Type**: Support Vector Machine for novelty detection

**How It Works**:
- Learns a decision boundary around normal data
- Uses RBF (Radial Basis Function) kernel
- Points outside boundary = anomalies

**Advantages**:
- Robust to outliers
- Handles non-linear boundaries
- Good generalization

**Performance**:
- ROC AUC: 0.999
- PR AUC: 0.997
- F1 Score: 0.966

#### 4.1.4 Local Outlier Factor (LOF)
**Type**: Density-based local anomaly detection

**How It Works**:
- Compares local density of point to neighbors
- Points with significantly lower density = anomalies
- Uses k-nearest neighbors

**Advantages**:
- Detects local anomalies
- Handles clusters of different densities
- Good for network traffic with multiple normal patterns

**Performance**:
- ROC AUC: 0.990
- PR AUC: 0.949
- F1 Score: 0.897

#### 4.1.5 Histogram-Based Outlier Score (HBOS)
**Type**: Histogram-based statistical method

**How It Works**:
- Creates histograms for each feature dimension
- Calculates probability density from histograms
- Low probability = anomaly

**Advantages**:
- Very fast computation
- Handles high-dimensional data
- Simple and interpretable

**Performance**:
- ROC AUC: 0.973
- PR AUC: 0.957
- F1 Score: 0.906

#### 4.1.6 Autoencoder (Neural Network)
**Type**: Deep learning reconstruction-based method

**Architecture**:
```
Input (8 features)
    ↓
Dense Layer (16 neurons, ReLU)
    ↓
Dropout (0.2)
    ↓
Dense Layer (8 neurons, ReLU)
    ↓
Latent Layer (4 neurons, ReLU)  [Bottleneck]
    ↓
Dense Layer (8 neurons, ReLU)
    ↓
Output (8 features)  [Reconstruction]
```

**How It Works**:
- Trains to reconstruct normal data
- High reconstruction error = anomaly
- Uses Mean Squared Error (MSE) loss

**Advantages**:
- Learns complex non-linear patterns
- Can capture feature interactions
- Adapts to data distribution

**Note**: Requires TensorFlow (optional dependency)

### 4.2 Model Training Process

**Training Data**: Only normal samples (unsupervised learning)

**Steps**:
1. Feature extraction from normal traffic
2. StandardScaler normalization (zero mean, unit variance)
3. Model fitting on normalized features
4. Model persistence to disk (`model/anomaly_model.pkl`)

**Continuous Learning**:
- Model retrained every 100 packets
- Uses sliding window of last 1000 samples
- Adapts to changing network patterns
- Saves updated model automatically

### 4.3 Anomaly Scoring

**Score Calculation**:
- Each model produces anomaly scores
- Higher score = more anomalous
- Threshold determined by contamination rate (percentile)

**Flow Score**:
- Tracks number of anomalies per flow
- Flow score = count of anomalous packets in flow
- Flow score ≥ 5 triggers alert

**Decision Process**:
```
Packet → Feature Extraction → Model Prediction → Anomaly Score
    ↓
Threshold Comparison → Binary Decision (Normal/Anomaly)
    ↓
Flow Score Update → Alert Generation (if flow_score ≥ 5)
```

---

## 5. Threat Intelligence Integration

### 5.1 DNS Resolution

**Purpose**: Map IP addresses to domain names for better visibility

**Implementation** (`utils/dns_resolver.py`):
- Reverse DNS lookup (PTR records)
- Caching with LRU cache (1000 entries)
- Timeout: 500ms per lookup
- Domain simplification (extracts main domain)

**Example**:
```
IP: 104.18.18.125 → Hostname: cloudflare.com
IP: 8.8.8.8 → Hostname: dns.google
```

### 5.2 TLS SNI Extraction

**Purpose**: Identify target websites from HTTPS traffic

**How It Works**:
- Parses TLS ClientHello handshake
- Extracts Server Name Indication (SNI) extension
- Maps destination IP to domain name

**Implementation** (`utils/packet_parser.py`):
- Binary parsing of TLS records
- Extracts SNI from extension type 0x00
- Handles TLS version negotiation

**Example**:
```
HTTPS packet to 104.18.18.125:443
    ↓
TLS SNI: "example.com"
    ↓
Dashboard shows: "example.com" instead of just IP
```

### 5.3 DNS Query Tracking

**Purpose**: Build IP-to-domain mapping from DNS responses

**Process**:
1. Capture DNS response packets
2. Extract query name and answer IPs
3. Cache mapping: `IP → Domain`
4. Apply to subsequent packets

**Cache Management**:
- TTL: 600 seconds (10 minutes)
- Automatic expiration
- Periodic cleanup

---

## 6. Web Dashboard

### 6.1 Architecture

**Technology Stack**:
- **Backend**: Flask (Python web framework)
- **Real-time Communication**: Flask-SocketIO (WebSocket)
- **Frontend**: HTML5, CSS3, JavaScript
- **Charts**: Chart.js library
- **Port**: 5004 (configurable)

### 6.2 Dashboard Components

#### 6.2.1 Statistics Cards
- **Total Packets**: Cumulative packet count
- **Anomaly Packets**: Count of detected anomalies
- **Anomaly Rate**: Percentage of anomalous packets
- **Runtime**: Capture duration (MM:SS format)

#### 6.2.2 Protocol Distribution Chart
- **Type**: Doughnut chart
- **Data**: Protocol breakdown (TCP, UDP, ICMP, etc.)
- **Update**: Real-time as packets arrive
- **Colors**: Distinct colors per protocol

#### 6.2.3 Packet Rate Chart
- **Type**: Line chart
- **Time Window**: Last 60 minutes
- **Y-axis**: Packets per minute
- **Update**: Rolling window, updates every second
- **Purpose**: Visualize traffic patterns over time

#### 6.2.4 Recent Packets Table
- **Columns**:
  - ID: Sequential packet number
  - Time: Timestamp (HH:MM:SS.mmm)
  - Source: Source IP with hostname (if available)
  - Destination: Destination IP with website name
  - Protocol: Transport protocol
  - Service/Port: Service name and port number
  - Size: Packet size in bytes
  - Status: Normal/Anomaly badge
  - Threat: Flow score indicator (Safe/Low/Medium/High)
- **Features**:
  - Color-coded rows (red for anomalies)
  - Hostname resolution display
  - Website name from DNS/TLS
  - Last 50 packets shown

#### 6.2.5 Alerts Section
- **Trigger**: Flow score ≥ 5
- **Format**: Timestamp + detailed message
- **Content**: Source/destination IPs, ports, protocol
- **Example**: `[17:01:51] Extended anomalous flow detected! (192.168.249.211:55769 -> 8.8.4.4:443 [UDP])`

### 6.3 Real-time Updates

**WebSocket Communication**:
- Server emits `new_packet` event for each packet
- Server emits `stats_update` event for statistics
- Server emits `new_alert` event for alerts
- Client receives and updates UI instantly

**Data Flow**:
```
Packet Capture → Feature Extraction → Anomaly Detection
    ↓
web_app.add_packet() → SocketIO.emit('new_packet')
    ↓
Browser receives event → JavaScript updates DOM
    ↓
Charts and tables refresh automatically
```

### 6.4 Connection Status

- **Green pulsing dot**: Connected to capture engine
- **Red dot**: Disconnected
- **Auto-reconnect**: Handles temporary disconnections

---

## 7. Evaluation Framework

### 7.1 Evaluation Pipeline

**Purpose**: Benchmark multiple unsupervised models on packet data

**Process**:
1. **Data Collection**: Load features from PCAP files
2. **Synthetic Anomaly Generation**: Create realistic anomalies
3. **Train/Test Split**: 65% train, 35% test (stratified)
4. **Model Training**: Train on normal samples only
5. **Model Evaluation**: Test on normal + anomaly samples
6. **Metrics Calculation**: Compute comprehensive metrics
7. **Visualization**: Generate plots and charts

### 7.2 Synthetic Anomaly Generation

**Method**: Statistical anomaly injection

**Process**:
1. Calculate mean and standard deviation of normal features
2. Generate exaggerated samples: `mean ± 4*std` with random direction
3. Generate shuffled samples: Random feature permutation
4. Combine: 60% exaggerated + 40% shuffled

**Purpose**: 
- Simulate real attack patterns
- Test model robustness
- Evaluate detection capabilities

### 7.3 Evaluation Metrics

#### 7.3.1 Classification Metrics

**Confusion Matrix**:
- **True Positives (TP)**: Anomalies correctly identified
- **True Negatives (TN)**: Normal packets correctly identified
- **False Positives (FP)**: Normal packets flagged as anomalies
- **False Negatives (FN)**: Anomalies missed

**Derived Metrics**:
- **Precision**: TP / (TP + FP) - Accuracy of positive predictions
- **Recall (Sensitivity)**: TP / (TP + FN) - Ability to find anomalies
- **Specificity**: TN / (TN + FP) - Ability to identify normal traffic
- **F1 Score**: Harmonic mean of precision and recall
- **F0.5 Score**: Emphasizes precision over recall
- **F2 Score**: Emphasizes recall over precision
- **Balanced Accuracy**: (Recall + Specificity) / 2
- **Matthews Correlation Coefficient (MCC)**: Overall quality metric (-1 to +1)

#### 7.3.2 Ranking Metrics

**ROC AUC** (Receiver Operating Characteristic Area Under Curve):
- Plots True Positive Rate vs. False Positive Rate
- Measures ability to distinguish normal from anomalous
- Range: 0.0 (worst) to 1.0 (perfect)
- **Interpretation**: 
  - 0.9-1.0: Excellent
  - 0.8-0.9: Good
  - 0.7-0.8: Fair
  - <0.7: Poor

**PR AUC** (Precision-Recall Area Under Curve):
- Plots Precision vs. Recall
- Better for imbalanced datasets (few anomalies)
- More informative when anomalies are rare
- Range: 0.0 to 1.0

### 7.4 Visualizations Generated

#### 7.4.1 ROC Curves
- **File**: `reports/roc_curves.png`
- **Content**: ROC curves for all models on same plot
- **Features**: 
  - Model comparison
  - AUC values in legend
  - Random classifier baseline
  - Grid for readability

#### 7.4.2 Precision-Recall Curves
- **File**: `reports/pr_curves.png`
- **Content**: PR curves for all models
- **Features**:
  - Model comparison
  - PR AUC values
  - Baseline (anomaly ratio)
  - Better for imbalanced data

#### 7.4.3 Confusion Matrices
- **File**: `reports/confusion_matrices.png`
- **Content**: Heatmap confusion matrices for each model
- **Layout**: Grid of subplots (3 columns)
- **Features**:
  - TP, FP, TN, FN counts
  - F1 score in title
  - Color intensity indicates magnitude

#### 7.4.4 Score Distributions
- **File**: `reports/score_distributions.png`
- **Content**: Histograms of anomaly scores
- **Features**:
  - Normal vs. Anomaly distributions
  - Threshold line (green dashed)
  - Model comparison
  - Shows score separation quality

### 7.5 Evaluation Results Summary

**Best Performing Models** (from evaluation):
1. **Kernel Density**: ROC AUC 1.000, PR AUC 0.999, F1 0.991
2. **One-Class SVM**: ROC AUC 0.999, PR AUC 0.997, F1 0.966
3. **LOF**: ROC AUC 0.990, PR AUC 0.949, F1 0.897
4. **Isolation Forest**: ROC AUC 0.978, PR AUC 0.957, F1 0.897
5. **HBOS**: ROC AUC 0.973, PR AUC 0.957, F1 0.906

**Key Insights**:
- All models perform excellently (ROC AUC > 0.97)
- Kernel Density is best for this dataset
- Models complement each other (ensemble potential)
- Synthetic anomalies are well-separated from normal traffic

---

## 8. Technical Implementation Details

### 8.1 Data Flow

**Complete Packet Processing Pipeline**:

```
1. Network Interface
   ↓
2. Scapy Packet Capture (promiscuous mode)
   ↓
3. Raw Packet Bytes
   ↓
4. Packet Parser (dpkt library)
   ├─ Ethernet frame
   ├─ IP header
   ├─ TCP/UDP/ICMP
   └─ Application layer (HTTP/HTTPS/DNS)
   ↓
5. Structured Packet Info Dictionary
   ↓
6. Feature Extraction (8 dimensions)
   ├─ Packet size
   ├─ Protocol number
   ├─ Source/destination ports
   ├─ Time delta
   ├─ Flow statistics
   └─ Packet rate
   ↓
7. Feature Normalization (StandardScaler)
   ↓
8. Anomaly Detection Models
   ├─ Isolation Forest
   ├─ Kernel Density
   ├─ One-Class SVM
   ├─ LOF
   ├─ HBOS
   └─ Autoencoder (optional)
   ↓
9. Anomaly Scores & Predictions
   ↓
10. Flow Score Calculation
    ↓
11. Alert Generation (if flow_score ≥ 5)
    ↓
12. Web Dashboard Update (SocketIO)
    ├─ Statistics update
    ├─ Packet table row
    ├─ Chart updates
    └─ Alert notification
    ↓
13. PCAP File Storage
```

### 8.2 File Structure

```
celebalnetsniff/
├── analyzer/
│   ├── packet_sniffer.py      # Main capture engine
│   ├── pcap_analyzer.py        # PCAP file analysis
│   └── visualizer.py          # Terminal UI
├── models/
│   └── anomaly_detector.py    # ML model implementation
├── utils/
│   ├── packet_parser.py       # Protocol parsing
│   ├── dns_resolver.py        # DNS/TLS resolution
│   ├── pcap_handler.py        # PCAP file I/O
│   └── protocol_maps.py       # Protocol mappings
├── detectors/                  # Advanced detection modules
├── evaluation/
│   └── evaluate_unsupervised_models.py  # Model benchmarking
├── templates/
│   └── dashboard.html         # Web dashboard UI
├── captures/                  # PCAP file storage
├── model/
│   └── anomaly_model.pkl     # Saved ML model
├── reports/                   # Evaluation results
│   ├── anomaly_eval.json     # Metrics JSON
│   ├── roc_curves.png        # ROC visualization
│   ├── pr_curves.png         # PR visualization
│   ├── confusion_matrices.png # Confusion matrices
│   └── score_distributions.png # Score distributions
├── main.py                    # Terminal-only interface
├── main_web.py               # Web dashboard interface
├── quick_start_web.py        # Quick start script
├── web_app.py                # Flask web server
└── config.py                 # Configuration settings
```

### 8.3 Key Technologies

**Python Libraries**:
- **Scapy**: Packet capture and manipulation
- **dpkt**: Fast packet parsing
- **scikit-learn**: Machine learning algorithms
- **Flask**: Web framework
- **Flask-SocketIO**: WebSocket support
- **Chart.js**: Client-side charting
- **matplotlib/seaborn**: Visualization
- **numpy/pandas**: Data manipulation
- **joblib**: Model persistence

**System Requirements**:
- **Windows**: Npcap (WinPcap API compatible)
- **Linux**: libpcap development headers
- **Python**: 3.7+ (tested with 3.8+)
- **Privileges**: Administrator/root (for packet capture)

### 8.4 Performance Characteristics

**Packet Processing**:
- **Throughput**: ~1000-5000 packets/second (depends on hardware)
- **Latency**: <10ms per packet (parsing + detection)
- **Memory**: ~50-200MB (depends on flow table size)
- **CPU**: Moderate (ML inference is fast)

**Model Inference**:
- **Isolation Forest**: ~0.1ms per packet
- **Kernel Density**: ~0.5ms per packet
- **One-Class SVM**: ~0.2ms per packet
- **LOF**: ~1ms per packet
- **HBOS**: ~0.05ms per packet
- **Autoencoder**: ~2ms per packet (GPU faster)

**Web Dashboard**:
- **Update Rate**: Real-time (WebSocket)
- **Latency**: <50ms (network dependent)
- **Concurrent Users**: Supports multiple connections

---

## 9. Usage Workflows

### 9.1 Quick Start (Web Dashboard)

**Command**:
```powershell
python quick_start_web.py
```

**Process**:
1. Auto-detects network interface
2. Prompts for packet count (default: 100)
3. Prompts for BPF filter (optional)
4. Starts web server on port 5004
5. Opens browser automatically
6. Begins packet capture
7. Dashboard updates in real-time

### 9.2 Full Configuration (Web Dashboard)

**Command**:
```powershell
python main_web.py
```

**Interactive Prompts**:
1. Use web dashboard? (y/n)
2. Analyze existing PCAP? (y/n)
3. Use automatic interface detection? (y/n)
4. BPF filter (optional)
5. Maximum packets (0 = unlimited)
6. Output directory
7. Model file path
8. Start capture? (y/n)

### 9.3 Terminal-Only Mode

**Command**:
```powershell
python main.py
```

**Features**:
- Rich terminal UI (tables, colors)
- No web server required
- Same detection capabilities
- Good for server environments

### 9.4 Model Evaluation

**Command**:
```powershell
python evaluation\evaluate_unsupervised_models.py --max-packets 4000 --anomaly-ratio 0.25
```

**Process**:
1. Loads PCAP files from `captures/` directory
2. Extracts features from packets
3. Generates synthetic anomalies
4. Trains all models
5. Evaluates on test set
6. Computes metrics
7. Generates visualizations
8. Saves results to `reports/`

**Output**:
- Console table with metrics
- JSON report (`reports/anomaly_eval.json`)
- 4 visualization PNG files

### 9.5 PCAP File Analysis

**Command**:
```powershell
python main_web.py
# Select: Analyze existing PCAP? (y)
# Enter: path/to/capture.pcap
```

**Process**:
- Loads PCAP file
- Parses all packets
- Applies anomaly detection
- Displays results in terminal
- Shows top suspicious flows

---

## 10. Advanced Features

### 10.1 Continuous Learning

**Implementation**:
- Model retrained every 100 packets
- Uses sliding window (last 1000 samples)
- Adapts to network changes
- Saves updated model automatically

**Benefits**:
- Handles concept drift
- Adapts to new normal patterns
- Reduces false positives over time

### 10.2 Flow-Based Detection

**Flow Tracking**:
- Maintains statistics per connection
- Tracks packet count, bytes, timing
- Computes flow anomaly scores
- Alerts on persistent suspicious flows

**Flow Score Calculation**:
```
flow_score = count(anomalous_packets_in_flow)
Alert if flow_score >= 5
```

### 10.3 Multi-Model Ensemble

**Current State**: Multiple models run in parallel

**Potential Enhancement**: 
- Weighted voting
- Stacking ensemble
- Model selection based on flow characteristics

### 10.4 Threat Intelligence Caching

**DNS Cache**:
- LRU cache (1000 entries)
- 10-minute TTL
- Fast hostname lookups

**TLS SNI Cache**:
- Maps IP to domain from TLS handshakes
- Same TTL as DNS cache
- Automatic expiration

---

## 11. Security Considerations

### 11.1 Privacy

- **Local Processing**: All analysis done locally
- **No Data Transmission**: Packets not sent to external services
- **PCAP Storage**: User controls file storage
- **Hostname Resolution**: Only reverse DNS (no external queries for sensitive data)

### 11.2 Access Control

- **Localhost Only**: Web dashboard binds to 127.0.0.1 by default
- **No Authentication**: Intended for single-user local use
- **Network Access**: Requires administrator privileges (by design)

### 11.3 Data Handling

- **Memory Management**: Limits flow table size
- **PCAP Rotation**: Automatic file management
- **Model Storage**: Encrypted pickle files (joblib)

---

## 12. Limitations and Future Work

### 12.1 Current Limitations

1. **Synthetic Anomalies**: Evaluation uses generated anomalies, not real attacks
2. **Single Interface**: Captures from one interface at a time
3. **No Encryption**: Cannot decrypt TLS/HTTPS traffic
4. **Limited Protocols**: Focus on TCP/UDP/ICMP
5. **No Distributed Deployment**: Single-machine solution

### 12.2 Potential Enhancements

1. **Real Attack Datasets**: Evaluate on labeled attack datasets (CICIDS, UNSW-NB15)
2. **Deep Packet Inspection**: Extract more features from packet payloads
3. **Graph Neural Networks**: Model network topology for better detection
4. **Distributed Architecture**: Multi-sensor deployment
5. **Real-time Blocking**: Automatic firewall rule generation
6. **Threat Intelligence Feeds**: Integration with external threat databases
7. **Machine Learning Pipeline**: Automated hyperparameter tuning
8. **Explainable AI**: Feature importance and decision explanations

---

## 13. Conclusion

**NetSniff Guard** is a comprehensive network anomaly detection system that combines:

- **Real-time packet capture** with cross-platform support
- **Advanced protocol parsing** including TLS SNI and DNS extraction
- **Multiple unsupervised ML models** for robust detection
- **Interactive web dashboard** for visualization
- **Comprehensive evaluation framework** with detailed metrics
- **Continuous learning** for adaptation to network changes

The system achieves **excellent performance** (ROC AUC > 0.97) across all evaluated models, with Kernel Density Estimation showing near-perfect detection capabilities. The modular architecture allows for easy extension and customization, making it suitable for both research and production environments.

**Key Achievements**:
- ✅ Real-time anomaly detection
- ✅ Multiple ML algorithms
- ✅ Web-based visualization
- ✅ Comprehensive evaluation
- ✅ Threat intelligence integration
- ✅ Continuous learning capability

The project demonstrates practical application of machine learning to network security, providing a foundation for advanced threat detection and network monitoring systems.

