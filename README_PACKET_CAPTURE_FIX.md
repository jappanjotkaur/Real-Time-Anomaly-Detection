# Packet Capture Not Working - Quick Fix Guide

## Problem
The dashboard shows 0 or very few packets (like "7 packets" over 155 minutes) even though you're browsing the internet.

## Root Cause
The wrong network interface is likely selected, or packet capture isn't working on the selected interface.

## Solution

### Step 1: Run Diagnostic Test
```bash
python test_packet_capture.py
```

This will:
- List all available interfaces
- Test packet capture for 10 seconds
- Show which interface captures packets
- Tell you which interface to use

### Step 2: Use the Correct Interface
When you run `main_advanced.py` or `main_web.py`:
1. When prompted "Use automatic interface detection?", type **n** (no)
2. Manually select the interface number that worked in the diagnostic test
3. Usually this is the interface with IP address `192.168.x.x`

### Step 3: Run as Administrator
**Important:** Packet capture requires administrator privileges on Windows.

1. Close the current application
2. Right-click PowerShell
3. Select "Run as Administrator"
4. Navigate to project: `cd D:\celebalnetsniff`
5. Activate venv: `venv\Scripts\Activate.ps1`
6. Run: `python main_advanced.py`
7. Select the correct interface (from Step 2)

### Step 4: Generate Traffic
While the application is running:
- Browse the web
- Open multiple websites
- Ping servers: `ping 8.8.8.8 -t` (in a separate terminal)
- Download files
- Stream videos

## Expected Results

**Console output should show:**
```
[DEBUG] Received packet 1
[DEBUG] Packet 1 parsed: TCP 192.168.x.x -> x.x.x.x (Size: 1234 bytes)
[DEBUG] Sent packet 1 to web dashboard
[DEBUG] Received packet 2
...
```

**Web dashboard should show:**
- Total packets increasing rapidly
- Protocol distribution chart filling up
- Recent packets table showing packets
- Packet rate graph showing activity

## Common Issues

### Issue 1: Wrong Interface
**Symptom:** 0 or very few packets captured

**Fix:**
1. Run `python test_packet_capture.py`
2. Note which interface captures packets
3. Use that interface in the main application

### Issue 2: Not Running as Administrator
**Symptom:** No packets captured, or error messages

**Fix:**
- Run PowerShell as Administrator
- Then run the application

### Issue 3: Npcap Not Installed
**Symptom:** Error about packet capture not working

**Fix:**
1. Download Npcap: https://nmap.org/npcap/
2. Install with "WinPcap API-compatible Mode"
3. Restart computer
4. Run as Administrator

### Issue 4: Interface Has No Traffic
**Symptom:** Interface selected but no packets

**Fix:**
- Select the interface with a valid IP (192.168.x.x, 10.x.x.x)
- Make sure you're actively using the network
- Browse the web while the application is running

## Quick Checklist

- [ ] Ran `python test_packet_capture.py` and identified working interface
- [ ] Running PowerShell as Administrator
- [ ] Selected the correct interface (the one that worked in diagnostic)
- [ ] Npcap is installed
- [ ] Generating network traffic (browsing web, pinging)
- [ ] Console shows `[DEBUG] Received packet X` messages
- [ ] Web dashboard is updating

## Still Not Working?

1. Check console for error messages
2. Verify Npcap installation
3. Try a different interface
4. Make sure you're connected to a network
5. Check Windows Firewall settings
6. Review `TROUBLESHOOTING_PACKET_CAPTURE.md` for more details

## Interface Selection Tips

**GOOD interfaces (use these):**
- Has IP like `192.168.x.x`, `10.x.x.x`, or `172.16-31.x.x`
- Shows as "connected" in Windows
- Usually interface #3 or #4 in the list

**BAD interfaces (avoid these):**
- Loopback (`127.0.0.1`)
- Link-local (`169.254.x.x`)
- No IP address
- Disabled interfaces

## Test Command

Quick test to verify packet capture works:
```bash
python test_packet_capture.py
```

While it's running, browse the web. You should see packets being captured.

