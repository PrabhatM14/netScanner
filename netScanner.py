import socket
import ipaddress
import threading
from queue import Queue
import os
import subprocess

# Set the target network range
target_network = input("Enter network range (e.g., 192.168.1.0/24): ")

# Validate IP range
try:
    ip_net = ipaddress.ip_network(target_network, strict=False)
except ValueError as e:
    print(f"Invalid network: {e}")
    exit(1)

print("\n[!] Scanning network, please wait...\n")

# Thread-safe queue for IPs
queue = Queue()
open_hosts = []

# Ping host to check if it's alive
def ping_host(ip):
    if os.name == 'nt':  # Windows
        cmd = ["ping", "-n", "1", str(ip)]
    else:  # Unix
        cmd = ["ping", "-c", "1", "-W", "1", str(ip)]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if result.returncode == 0:
        open_hosts.append(str(ip))

# Worker thread for pinging
def worker():
    while not queue.empty():
        ip = queue.get()
        ping_host(ip)
        queue.task_done()

# Fill queue with IPs
for ip in ip_net.hosts():
    queue.put(ip)

# Start threads
threads = []
for _ in range(100):
    t = threading.Thread(target=worker)
    t.start()
    threads.append(t)

for t in threads:
    t.join()

# Get hostname for each IP (Reverse DNS Lookup)
host_info = {}
for ip in open_hosts:
    try:
        hostname = socket.gethostbyaddr(ip)[0]  # Reverse DNS lookup
    except (socket.herror, socket.gaierror):
        hostname = "Unknown"  # If hostname cannot be resolved
    host_info[ip] = hostname

# Output scan header
print(f"\nScan Report - {target_network}\n")

# Scan common ports
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
}

def scan_ports(ip):
    open_ports = []
    warnings = []
    for port, service in common_ports.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append((port, service))
                if port == 23:
                    warnings.append("Warning: TELNET detected - insecure protocol")
                elif port == 21:
                    warnings.append("Warning: FTP detected - check for anonymous access")
            s.close()
        except Exception:
            pass

    print(f"[{ip}] ({host_info[ip]})")  # Now includes hostname
    if open_ports:
        print("  - Open Ports: " + ", ".join([f"{p} ({s})" for p, s in open_ports]))
    else:
        print("  - No open common ports detected")

    if warnings:
        for warning in warnings:
            print(f"  - {warning}")
    else:
        print("  - No immediate vulnerabilities detected")

for host in open_hosts:
    scan_ports(host)

print("\n[✓] Scan Complete.")
