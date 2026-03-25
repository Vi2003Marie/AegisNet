from database import log_alert, block_ip
from database import log_alert
from collections import defaultdict
import time

import socket

def get_local_ips():
    local_ips = ['127.0.0.1', 'localhost']
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        local_ips.append(local_ip)
    except:
        pass
    return local_ips

WHITELIST = get_local_ips()
print(f"[WHITELIST] Ignoring traffic from: {WHITELIST}")

# Storage for tracking
port_tracker = defaultdict(set)
brute_force_tracker = defaultdict(list)
port_scan_timestamps = defaultdict(list)

PORT_SCAN_THRESHOLD = 10
PORT_SCAN_WINDOW = 5
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = 10

def detect_port_scan(src_ip, dst_port):
    now = time.time()
    port_scan_timestamps[src_ip].append(now)
    port_scan_timestamps[src_ip] = [
        t for t in port_scan_timestamps[src_ip] if now - t < PORT_SCAN_WINDOW
    ]
    port_tracker[src_ip].add(dst_port)

    if len(port_tracker[src_ip]) >= PORT_SCAN_THRESHOLD:
        print(f"[ALERT] Port Scan detected from {src_ip}")
        log_alert(
            alert_type="Port Scan",
            src_ip=src_ip,
            description=f"{len(port_tracker[src_ip])} ports scanned in {PORT_SCAN_WINDOW} seconds",
            severity="High"
        )
        block_ip(src_ip, "Automatic block - Port Scan detected")
        port_tracker[src_ip].clear()

def detect_brute_force(src_ip, dst_port):
    common_auth_ports = [22, 23, 3389, 21, 80, 443, 3306]
    if dst_port not in common_auth_ports:
        return

    now = time.time()
    brute_force_tracker[src_ip].append(now)
    brute_force_tracker[src_ip] = [
        t for t in brute_force_tracker[src_ip] if now - t < BRUTE_FORCE_WINDOW
    ]

    count = len(brute_force_tracker[src_ip])
    if count >= BRUTE_FORCE_THRESHOLD:
        print(f"[ALERT] Possible Brute Force from {src_ip} - {count} attempts on port {dst_port}")
        log_alert(
            alert_type="Brute Force Attempt",
            src_ip=src_ip,
            description=f"{count} connection attempts to port {dst_port} in {BRUTE_FORCE_WINDOW} seconds",
            severity="Critical"
        )
        brute_force_tracker[src_ip].clear()

def analyze_packet(src_ip, dst_port, protocol):
    if src_ip in WHITELIST:
        return
    detect_port_scan(src_ip, dst_port)
    if protocol == "TCP":
        detect_brute_force(src_ip, dst_port)