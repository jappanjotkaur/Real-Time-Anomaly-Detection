#!/bin/bash
# NetSniff Guard - Linux Setup Script
# This script sets up the environment for NetSniff Guard on Linux

echo "========================================"
echo "NetSniff Guard - Linux Setup"
echo "========================================"
echo ""

# Check Python version
echo "[*] Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo "[!] Python 3 is not installed"
    echo "    Install with: sudo apt-get install python3 python3-pip python3-venv"
    exit 1
fi

PYTHON_VERSION=$(python3 --version)
echo "[+] $PYTHON_VERSION"

# Check if running as root (needed for packet capture)
if [ "$EUID" -eq 0 ]; then
    echo "[!] Warning: Running as root. Consider using sudo only when needed."
fi

# Install system dependencies
echo ""
echo "[*] Checking system dependencies..."
if command -v apt-get &> /dev/null; then
    # Debian/Ubuntu
    echo "[*] Installing libpcap-dev (Debian/Ubuntu)..."
    sudo apt-get update
    sudo apt-get install -y libpcap-dev python3-dev
elif command -v yum &> /dev/null; then
    # CentOS/RHEL
    echo "[*] Installing libpcap-devel (CentOS/RHEL)..."
    sudo yum install -y libpcap-devel python3-devel
elif command -v dnf &> /dev/null; then
    # Fedora
    echo "[*] Installing libpcap-devel (Fedora)..."
    sudo dnf install -y libpcap-devel python3-devel
else
    echo "[!] Could not detect package manager"
    echo "    Please install libpcap development headers manually"
fi

# Check if virtual environment exists
if [ -d "venv" ]; then
    echo "[*] Virtual environment already exists"
    read -p "    Recreate virtual environment? (y/n): " recreate
    if [ "$recreate" = "y" ]; then
        rm -rf venv
        echo "[+] Removed existing virtual environment"
    else
        echo "[*] Using existing virtual environment"
    fi
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo "[!] Failed to create virtual environment"
        exit 1
    fi
    echo "[+] Virtual environment created"
fi

# Activate virtual environment
echo "[*] Activating virtual environment..."
source venv/bin/activate
if [ $? -ne 0 ]; then
    echo "[!] Failed to activate virtual environment"
    exit 1
fi

# Upgrade pip
echo "[*] Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "[*] Installing dependencies..."
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "[!] Some packages failed to install"
    echo "    Try installing them individually"
fi

# Verify installation
echo ""
echo "[*] Verifying installation..."
python -c "from detectors.advanced_integration import AdvancedDetectionEngine; print('✓ All modules installed successfully!')"
if [ $? -eq 0 ]; then
    echo "[+] Installation verified successfully!"
else
    echo "[!] Verification failed. Some modules may be missing."
    echo "    Try installing missing packages manually."
fi

# Create necessary directories
echo ""
echo "[*] Creating necessary directories..."
mkdir -p logs threat_intel_cache captures model
echo "[+] Directories created"

echo ""
echo "========================================"
echo "Setup Complete!"
echo "========================================"
echo ""
echo "Next steps:"
echo "1. Edit config_advanced.py to configure features"
echo "2. Run: sudo python main_advanced.py"
echo "3. Access web dashboard at: http://127.0.0.1:5000"
echo ""
echo "Note: Packet capture requires root privileges (use sudo)"
echo ""

