# NetSniff Guard - Quick Start Script
# This script runs the packet capture with recommended settings

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "     NETSNIFF GUARD - QUICK START" -ForegroundColor Cyan
Write-Host "============================================================`n" -ForegroundColor Cyan

Write-Host "This will:" -ForegroundColor Yellow
Write-Host "  1. Auto-select your network interface (192.168.29.40)" -ForegroundColor White
Write-Host "  2. Capture 10 packets for testing" -ForegroundColor White
Write-Host "  3. Display results with anomaly detection`n" -ForegroundColor White

Write-Host "IMPORTANT: Start browsing the web NOW to generate traffic!`n" -ForegroundColor Green

# Create input file with automatic responses
$responses = @"
n
y


10


y
"@

$responses | & ".\venv\Scripts\python.exe" main.py

Write-Host "`nCapture complete!" -ForegroundColor Green
