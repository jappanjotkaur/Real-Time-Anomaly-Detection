# NetSniff Guard - Analyze Existing PCAP
# This script analyzes one of the existing PCAP files

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "     NETSNIFF GUARD - PCAP ANALYZER" -ForegroundColor Cyan
Write-Host "============================================================`n" -ForegroundColor Cyan

Write-Host "Available PCAP files in captures/ directory:" -ForegroundColor Yellow
Get-ChildItem -Path ".\captures\*.pcap" | ForEach-Object { Write-Host "  - $($_.Name)" -ForegroundColor White }

Write-Host "`nAnalyzing: capture_20250908_011650.pcap`n" -ForegroundColor Green

# Create input file with automatic responses
$responses = @"
y
captures\capture_20250908_011650.pcap

"@

$responses | & ".\venv\Scripts\python.exe" main.py

Write-Host "`nAnalysis complete!" -ForegroundColor Green
