# Quick Fix: Packet Capture Not Working

## Issue
The dashboard shows 0 or very few packets even though you're browsing the internet.

## Quick Solution

### Step 1: Run Diagnostic Test
```bash
python test_packet_capture.py
```

This will:
- Show all available interfaces
- Test packet capture
- Identify which interface works

### Step 2: Note the Working Interface
The diagnostic will show which interface captures packets. Note the interface name (e.g., `\Device\NPF_{...}` or interface number).

### Step 3: Run Main Application
When prompted to select an interface, choose the one that worked in the diagnostic test.

### Step 4: Generate Network Traffic
While the application is running:
- Browse the web
- Ping servers: `ping 8.8.8.8`
- Download files
- Stream videos

## Common Fixes

### Fix 1: Wrong Interface Selected
**Problem:** The auto-selected interface might not be the active one.

**Solution:** 
1. Run `python test_packet_capture.py`
2. Note which interface captures packets
3. In main application, manually select that interface

### Fix 2: Need Administrator Privileges
**Problem:** Packet capture requires admin rights on Windows.

**Solution:**
1. Right-click PowerShell
2. Select "Run as Administrator"
3. Navigate to project: `cd D:\celebalnetsniff`
4. Activate venv: `venv\Scripts\Activate.ps1`
5. Run: `python main_advanced.py`

### Fix 3: Npcap Not Working
**Problem:** Npcap might not be installed or configured correctly.

**Solution:**
1. Download Npcap: https://nmap.org/npcap/
2. Install with "WinPcap API-compatible Mode"
3. Restart computer
4. Run as Administrator

### Fix 4: Interface Has No Traffic
**Problem:** The selected interface might not have active network traffic.

**Solution:**
- Make sure you're connected to a network
- Select the interface that shows a valid IP address (not 169.254.x.x)
- Select the interface that's connected to your router/network

## Expected Behavior

When working correctly:
1. Console shows: `[DEBUG] Received packet X`
2. Console shows: `[DEBUG] Packet X parsed: TCP/IP...`
3. Web dashboard updates with packet counts
4. Protocol distribution chart fills up
5. Recent packets table shows packets

## Still Not Working?

1. **Check console output** - Look for error messages
2. **Try different interface** - Select manually from the list
3. **Run as Administrator** - Required for packet capture
4. **Verify Npcap** - Reinstall if needed
5. **Generate traffic** - Browse web while application is running
6. **Check firewall** - Allow application through firewall

## Interface Selection Tips

**Good interfaces:**
- Has IP address like 192.168.x.x, 10.x.x.x, or 172.16-31.x.x
- Not "Loopback" or "169.254.x.x" (link-local)
- Shows as "connected" in Windows Network Settings

**Bad interfaces:**
- Loopback (127.0.0.1)
- Link-local (169.254.x.x)
- No IP address
- Disabled interfaces

