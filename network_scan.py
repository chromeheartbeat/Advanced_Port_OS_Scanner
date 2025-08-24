import os
import platform
import ipaddress
import socket
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor
from mac_vendor_lookup import MacLookup

# ------------------ Network Utilities ------------------ #

def ping(ip):
    """Ping an IP address, return True if alive."""
    param = "-n 1" if platform.system().lower() == "windows" else "-c 1"
    response = os.system(
        f"ping {param} -w 1000 {ip} >nul 2>&1" if platform.system().lower() == "windows"
        else f"ping {param} -W 1 {ip} >/dev/null 2>&1"
    )
    return response == 0

def get_hostname(ip):
    """Try to resolve hostname from IP."""
    try:
        return socket.getfqdn(ip)
    except Exception:
        return "Unknown"

def get_mac(ip):
    """Get MAC address from ARP table after pinging."""
    try:
        if platform.system().lower() == "windows":
            output = subprocess.check_output(f"arp -a {ip}", shell=True).decode()
        else:
            output = subprocess.check_output(f"arp -n {ip}", shell=True).decode()
        
        mac_regex = r"(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))"
        match = re.search(mac_regex, output)
        if match:
            return match.group(0)
        return "Unknown"
    except Exception:
        return "Unknown"

def detect_device_type(mac, hostname=""):
    """Guess device type based on MAC vendor + hostname clues."""
    try:
        vendor = MacLookup().lookup(mac)
        vendor_lower = vendor.lower()
        host_lower = hostname.lower()

        # Apple detection
        if "apple" in vendor_lower:
            if "iphone" in host_lower:
                return "Apple iPhone"
            elif "ipad" in host_lower:
                return "Apple iPad"
            elif any(x in host_lower for x in ["macbook", "imac", "mac"]):
                return "Apple Mac"
            else:
                return "Apple Device"

        # Mobile vendors
        if any(x in vendor_lower for x in ["samsung", "huawei", "xiaomi", "oneplus", "oppo", "motorola", "nokia"]):
            return f"Mobile ({vendor})"

        # PC vendors
        if any(x in vendor_lower for x in ["microsoft", "intel", "hewlett", "dell", "asus", "lenovo", "acer"]):
            return f"PC ({vendor})"

        return vendor
    except Exception:
        return "Unknown"

def fingerprint_os(ip):
    """Guess OS based on TTL value from ping response."""
    try:
        if platform.system().lower() == "windows":
            output = subprocess.check_output(f"ping -n 1 {ip}", shell=True).decode(errors="ignore")
            match = re.search(r"TTL=(\d+)", output)
        else:
            output = subprocess.check_output(f"ping -c 1 {ip}", shell=True).decode(errors="ignore")
            match = re.search(r"ttl=(\d+)", output, re.IGNORECASE)
        if match:
            ttl = int(match.group(1))
            if ttl >= 120:
                return "Windows (likely)"
            elif ttl >= 60:
                return "Linux/Android (likely)"
            elif ttl >= 240:
                return "Cisco/Network Device (likely)"
            else:
                return f"Unknown (TTL={ttl})"
        return "Unknown"
    except Exception:
        return "Unknown"

# ------------------ Scanner ------------------ #

def scan_ip(ip):
    """Scan a single IP, return details if alive."""
    if ping(ip):
        hostname = get_hostname(ip)
        mac = get_mac(ip)
        device_type = detect_device_type(mac, hostname) if mac != "Unknown" else "Unknown"
        os_guess = fingerprint_os(ip)
        return {"ip": ip, "hostname": hostname, "mac": mac, "type": device_type, "os": os_guess}
    return None

def scan_network(network):
    """Scan the network and return list of alive hosts with details."""
    alive_hosts = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(scan_ip, [str(ip) for ip in ipaddress.IPv4Network(network, strict=False).hosts()])
        for result in results:
            if result:
                alive_hosts.append(result)
    return alive_hosts

# ------------------ Shutdown ------------------ #

def shutdown_device(ip, windows=True, username=None, key_path=None):
    """Shutdown a remote device (Windows via RPC, Linux/Mac via SSH keys)."""
    if windows:
        try:
            cmd = f"shutdown /s /m \\\\{ip} /t 0 /f"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"[+] Shutdown command sent to {ip}")
            else:
                print(f"[!] Failed to shutdown {ip}: {result.stderr}")
        except Exception as e:
            print(f"[!] Error shutting down {ip}: {e}")
    else:
        if username is None or key_path is None:
            print("[!] Username and key_path required for SSH shutdown.")
            return
        try:
            cmd = f'ssh -i {key_path} -o StrictHostKeyChecking=no {username}@{ip} "sudo shutdown -h now"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"[+] Shutdown command sent to {ip}")
            else:
                print(f"[!] Failed to shutdown {ip}: {result.stderr}")
        except Exception as e:
            print(f"[!] Error shutting down {ip}: {e}")

# ------------------ Main ------------------ #

if __name__ == "__main__":
    # Update MAC vendor database
    try:
        print("[+] Updating MAC vendor database...")
        MacLookup().update_vendors()
    except Exception as e:
        print(f"[!] Could not update MAC vendor DB: {e}")

    # Your network info
    local_ip = "192.168.1.163"
    gateway = "192.168.1.1"
    network = "192.168.1.0/24"

    print(f"[+] Router/Gateway IP (likely): {gateway}")
    print(f"[+] Local IP: {local_ip}")
    print(f"[+] Scanning network: {network}")

    alive = scan_network(network)

    print("\n[+] Active Devices:")
    for i, host in enumerate(alive, 1):
        print(f" {i}. {host['ip']} | Hostname: {host['hostname']} | MAC: {host['mac']} | "
              f"Type: {host['type']} | OS: {host['os']}")

    # Save to file
    with open("alive_hosts.txt", "w") as f:
        for host in alive:
            f.write(f"{host['ip']} | Hostname: {host['hostname']} | MAC: {host['mac']} | "
                    f"Type: {host['type']} | OS: {host['os']}\n")

    print("\n[+] Results saved to alive_hosts.txt")

    # Ask user if they want to shutdown a device
    choice = input("\nDo you want to shutdown a device? (y/n): ").strip().lower()
    if choice == "y":
        try:
            device_num = int(input("Enter the device number from the list: ").strip())
            target = alive[device_num - 1]
            print(f"[+] Selected: {target['ip']} ({target['hostname']}) - {target['type']} | OS: {target['os']}")

            if "Mobile" in target["type"]:
                print("[!] Shutdown not supported for mobile devices.")
            else:
                os_type = input("Is the target Windows (w) or Linux/Mac (l)? ").strip().lower()
                if os_type == "w":
                    shutdown_device(target["ip"], windows=True)
                else:
                    username = input("Enter SSH username: ").strip()
                    key_path = input("Enter path to your private key (e.g., ~/.ssh/id_rsa): ").strip()
                    shutdown_device(target["ip"], windows=False, username=username, key_path=key_path)

        except Exception as e:
            print(f"[!] Invalid selection: {e}")

# ------------------ End of network_scan.py ------------------ #
# This script scans a local network for active devices, retrieves their details, and allows for remote shutdown.
