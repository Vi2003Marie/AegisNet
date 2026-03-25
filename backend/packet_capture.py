from detection_engine import analyze_packet
from scapy.all import sniff, ARP, IP, TCP, UDP
from database import log_packet, log_device, log_alert
from collections import defaultdict
import time
import threading

def scan_network():
    from scapy.all import ARP, Ether, srp
    import ipaddress
    while True:
        try:
            arp = ARP(pdst="192.168.1.0/24")
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            result = srp(packet, timeout=2, verbose=False)[0]
            for sent, received in result:
                ip = received.psrc
                mac = received.hwsrc
                print(f"[SCAN] Found device: {ip} - {mac}")
                log_device(ip, mac)
        except Exception as e:
            print(f"[SCAN ERROR] {e}")
        time.sleep(30)

packet_count = defaultdict(list)
PACKET_THRESHOLD = 100
TIME_WINDOW = 10

def detect_threats(src_ip):
    from detection_engine import WHITELIST
    if src_ip in WHITELIST:
        return
    from database import block_ip
    now = time.time()
    packet_count[src_ip].append(now)
    packet_count[src_ip] = [
        t for t in packet_count[src_ip] if now - t < TIME_WINDOW
    ]
    count = len(packet_count[src_ip])
    if count > PACKET_THRESHOLD:
        print(f"[ALERT] Possible DDoS/Flood from {src_ip} - {count} packets in {TIME_WINDOW}s")
        log_alert(
            alert_type="Traffic Flood",
            src_ip=src_ip,
            description=f"{count} packets detected in {TIME_WINDOW} seconds",
            severity="High"
        )
        block_ip(src_ip, "Automatic block - Excessive traffic detected")
        packet_count[src_ip].clear()

def process_packet(packet):
    if packet.haslayer(ARP):
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc
        print(f"[DEVICE] {ip} - {mac}")
        log_device(ip, mac)

    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "OTHER"
        size = len(packet)

        dst_port = 0
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            dst_port = packet[UDP].dport

        print(f"[PACKET] {src} -> {dst} | {proto} | {size} bytes")
        log_packet(src, dst, proto, size)
        detect_threats(src)
        analyze_packet(src, dst_port, proto)

def start():
    print("AegisNet - Monitoring Started...")
    scan_thread = threading.Thread(target=scan_network, daemon=True)
    scan_thread.start()
    while True:
        try:
            sniff(prn=process_packet, store=False, timeout=30)
        except Exception as e:
            print(f"[WARNING] Restarting capture: {e}")
            time.sleep(2)