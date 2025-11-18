# NetSniff Guard - Windows Setup Script
# This script sets up the environment for NetSniff Guard on Windows

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "NetSniff Guard - Windows Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check Python version
Write-Host "[*] Checking Python version..." -ForegroundColor Yellow
$pythonVersion = python --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Python is not installed or not in PATH" -ForegroundColor Red
    Write-Host "    Please install Python 3.8+ from https://www.python.org/" -ForegroundColor Yellow
    exit 1
}
Write-Host "[+] $pythonVersion" -ForegroundColor Green

# Check if virtual environment exists
if (Test-Path "venv") {
    Write-Host "[*] Virtual environment already exists" -ForegroundColor Yellow
    $recreate = Read-Host "    Recreate virtual environment? (y/n)"
    if ($recreate -eq "y") {
        Remove-Item -Recurse -Force venv
        Write-Host "[+] Removed existing virtual environment" -ForegroundColor Green
    } else {
        Write-Host "[*] Using existing virtual environment" -ForegroundColor Yellow
    }
}

# Create virtual environment if it doesn't exist
if (-not (Test-Path "venv")) {
    Write-Host "[*] Creating virtual environment..." -ForegroundColor Yellow
    python -m venv venv
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Failed to create virtual environment" -ForegroundColor Red
        exit 1
    }
    Write-Host "[+] Virtual environment created" -ForegroundColor Green
}

# Activate virtual environment
Write-Host "[*] Activating virtual environment..." -ForegroundColor Yellow
& "venv\Scripts\Activate.ps1"
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Failed to activate virtual environment" -ForegroundColor Red
    Write-Host "    You may need to run: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser" -ForegroundColor Yellow
    exit 1
}

# Upgrade pip
Write-Host "[*] Upgrading pip..." -ForegroundColor Yellow
python -m pip install --upgrade pip
Write-Host "[+] Pip upgraded" -ForegroundColor Green

# Install dependencies (excluding pcap which is Linux-only)
Write-Host "[*] Installing dependencies..." -ForegroundColor Yellow
Write-Host "    (Skipping 'pcap' - Linux only, using scapy on Windows)" -ForegroundColor Gray

# Install packages individually to handle errors better
$packages = @(
    "dpkt",
    "scapy",
    "flask",
    "flask-socketio",
    "flask-cors",
    "scikit-learn",
    "numpy",
    "pandas",
    "joblib",
    "networkx",
    "requests",
    "rich",
    "colorama"
)

foreach ($package in $packages) {
    Write-Host "    Installing $package..." -ForegroundColor Gray
    pip install $package
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Warning: Failed to install $package" -ForegroundColor Yellow
    }
}

# TensorFlow is optional and can be large, ask user
Write-Host ""
$installTensorflow = Read-Host "[?] Install TensorFlow? (y/n) - Required for advanced ML models"
if ($installTensorflow -eq "y") {
    Write-Host "[*] Installing TensorFlow (this may take a while)..." -ForegroundColor Yellow
    pip install tensorflow
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Failed to install TensorFlow. You can install it later with: pip install tensorflow" -ForegroundColor Yellow
    } else {
        Write-Host "[+] TensorFlow installed" -ForegroundColor Green
    }
} else {
    Write-Host "[*] Skipping TensorFlow. Install later with: pip install tensorflow" -ForegroundColor Yellow
}

# Verify installation
Write-Host ""
Write-Host "[*] Verifying installation..." -ForegroundColor Yellow
python -c "from detectors.advanced_integration import AdvancedDetectionEngine; print('✓ All modules installed successfully!')"
if ($LASTEXITCODE -eq 0) {
    Write-Host "[+] Installation verified successfully!" -ForegroundColor Green
} else {
    Write-Host "[!] Verification failed. Some modules may be missing." -ForegroundColor Red
    Write-Host "    Try installing missing packages manually." -ForegroundColor Yellow
}

# Check for Npcap
Write-Host ""
Write-Host "[*] Checking for Npcap (required for packet capture)..." -ForegroundColor Yellow
$npcapInstalled = Test-Path "C:\Program Files\Npcap"
if ($npcapInstalled) {
    Write-Host "[+] Npcap is installed" -ForegroundColor Green
} else {
    Write-Host "[!] Npcap is not installed" -ForegroundColor Yellow
    Write-Host "    Download from: https://nmap.org/npcap/" -ForegroundColor Yellow
    Write-Host "    Install with 'WinPcap API-compatible Mode' option" -ForegroundColor Yellow
}

# Create necessary directories
Write-Host ""
Write-Host "[*] Creating necessary directories..." -ForegroundColor Yellow
$directories = @("logs", "threat_intel_cache", "captures", "model")
foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
        Write-Host "    Created: $dir" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Setup Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Edit config_advanced.py to configure features" -ForegroundColor White
Write-Host "2. Run: python main_advanced.py" -ForegroundColor White
Write-Host "3. Access web dashboard at: http://127.0.0.1:5000" -ForegroundColor White
Write-Host ""
Write-Host "Note: For auto-blocking features, run PowerShell as Administrator" -ForegroundColor Yellow
Write-Host ""

