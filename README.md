# 🔍 Advanced Port & OS Scanner

An advanced Python-based port scanner that supports:

✅ **TCP Connect scan (0–65535)**  
✅ **SYN scan (stealth, Nmap-style -sS)**  
✅ **UDP scan with protocol-specific probes (DNS, SNMP, NTP)**  
✅ **OS fingerprinting (based on TTL & TCP Window Size)**  
✅ **Banner grabbing for UDP services**  
✅ **Multithreading for speed**  
✅ **Results logging to scan_results.txt**  

---

## ⚡ Features

### 🔹 1. TCP Connect Scan
- Uses a full TCP 3-way handshake (safe, no raw sockets needed).  
- Works on all systems without special privileges.  

**Example output:**  
```
[TCP] Port 80 OPEN (HTTP)
[TCP] Port 443 OPEN (HTTPS)
```

### 🔹 2. SYN Scan (Stealth Mode)
- Faster & stealthier than TCP Connect.  
- Does not complete the TCP handshake (like nmap -sS).  
- Requires root/Administrator privileges.  

### 🔹 3. UDP Scan with Probes
- Detects services on common UDP ports.  
- Sends protocol-specific packets for deeper analysis:  
  - **DNS** → queries example.com  
  - **SNMP** → requests sysDescr.0  
  - **NTP** → sends client request  

**Example:**  
```
[+] UDP Port 53 Open (DNS)
    └─ Banner: DNS Answers: ['93.184.216.34']
```

### 🔹 4. OS Fingerprinting
- Sends ICMP Echo + TCP SYN packets.  
- Uses TTL and TCP window size heuristics to guess OS family.  

**Example:**  
```
[*] OS Fingerprinting
    ◦ ICMP TTL: 64
    ◦ TCP TTL : 64 (port 443)
    ◦ TCP Win : 0
    ◦ Guess   : Linux/Unix/macOS (likely)
    ◦ Basis   : TTL≈64 heuristic (+ window-size hint if available)
```

### 🔹 5. Logging
All scan results are written to:  
```
scan_results.txt
```

---

## ⚙️ Requirements

Install dependencies:  
```
pip install scapy
```

For UDP/OS fingerprinting & SYN scan on **Windows**:  
- Install **Npcap** (WinPcap is obsolete).  
- Run VS Code / PowerShell as Administrator.  

On **Linux/macOS**:  
Run with sudo for SYN/UDP/OS scans:  
```
sudo python scanner.py 192.168.1.1 --syn --udp --os
```

---

## 🚀 Usage
```
python scanner.py <IP> [options]
```

### Options
```
-s, --start <port>     Start port (default 0)
-e, --end <port>       End port (default 1024)
-t, --timeout <sec>    Timeout per probe (default 0.5)
-T, --threads <num>    Max threads (default 100)

--syn                  Use SYN scan (requires root/Admin)
--udp                  Use UDP scan with probes (requires root/Admin)
--os                   Perform OS fingerprinting
```

---

## 🔧 Examples

1. Basic TCP scan (ports 0–1024)  
```
python scanner.py 192.168.1.174
```

2. Stealth SYN scan  
```
sudo python scanner.py 192.168.1.1 --syn
```

3. UDP probe scan  
```
sudo python scanner.py 192.168.1.1 --udp
```

4. Full scan (TCP + UDP + OS fingerprinting)  
```
sudo python scanner.py 192.168.1.1 --syn --udp --os
```

---

## 📖 Example Output
```
[*] TCP Connect Scan 192.168.1.1 ports 0-1024
[TCP] Port 80 OPEN (HTTP)
[TCP] Port 443 OPEN (HTTPS)
[TCP] Port 502 OPEN (Modbus)
[TCP] Port 501 OPEN (Unknown)
[TCP] Port 853 OPEN (DNS-over-TLS)

[*] OS Fingerprinting
    ◦ ICMP TTL: 64
    ◦ TCP TTL : 64 (port 443)
    ◦ TCP Win : 0
    ◦ Guess   : Linux/Unix/macOS (likely)
    ◦ Basis   : TTL≈64 heuristic
```

---

## ⚠️ Legal Disclaimer
This tool is for educational and authorized security testing only.  
Do **NOT** scan networks or devices without explicit permission.  
The authors are not responsible for misuse or damage caused.  
