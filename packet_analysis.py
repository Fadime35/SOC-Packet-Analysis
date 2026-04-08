# soc_packet_analysis_final.py
from scapy.all import sniff, TCP, IP, ICMP, UDP
from collections import defaultdict
import logging
import os
import time
import threading

# ---------- LOG AYARLARI ----------
log_file = 'alerts.log'
if os.path.exists(log_file):
    open(log_file, 'w').close()

logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(message)s')

def log_alert(message):
    logging.info(message)
    print(message)

# ---------- ANOMALİ SAYACI ----------
syn_count = defaultdict(int)
icmp_count = defaultdict(int)
udp_count = defaultdict(int)

# Eşik değerleri (test amaçlı düşük, gerçek kullanımda artırabilirsin)
SYN_THRESHOLD = 1
ICMP_THRESHOLD = 1
UDP_THRESHOLD = 3

# Toplam paket sayısı ve ALERT sayısı
total_packets = 0
total_alerts = 0

# ---------- ZAMANLI ÖZET RAPOR ----------
def print_summary():
    while True:
        time.sleep(30)  # her 30 saniyede bir rapor
        print("\n=== Summary Report ===")
        print(f"Total packets captured: {total_packets}")
        print(f"Total ALERTs: {total_alerts}")
        print(f"SYN alerts: {sum(1 for v in syn_count.values() if v > SYN_THRESHOLD)}")
        print(f"ICMP alerts: {sum(1 for v in icmp_count.values() if v > ICMP_THRESHOLD)}")
        print(f"UDP alerts: {sum(1 for v in udp_count.values() if v > UDP_THRESHOLD)}")
        print("====================\n")

# Zamanlı rapor thread olarak çalışsın
threading.Thread(target=print_summary, daemon=True).start()

# ---------- PAKET ANALİZ FONKSİYONU ----------
def analyze_packet(packet):
    global total_packets, total_alerts
    total_packets += 1

    if not packet.haslayer(IP):
        return

    src = packet[IP].src
    dst = packet[IP].dst
    proto = packet[IP].proto
    print(f"Packet: {src} -> {dst}, Protocol: {proto}")

    # TCP SYN tespiti
    if packet.haslayer(TCP) and packet[TCP].flags == 'S':
        dst_port = packet[TCP].dport
        syn_count[(src, dst_port)] += 1
        if syn_count[(src, dst_port)] > SYN_THRESHOLD:
            message = f"[ALERT] Possible SYN Port Scan from {src} to port {dst_port}"
            log_alert(message)
            total_alerts += 1

    # ICMP flood tespiti
    if packet.haslayer(ICMP):
        icmp_count[src] += 1
        if icmp_count[src] > ICMP_THRESHOLD:
            message = f"[ALERT] ICMP Flood detected from {src}"
            log_alert(message)
            total_alerts += 1

    # UDP flood tespiti
    if packet.haslayer(UDP):
        dst_port = packet[UDP].dport
        udp_count[(src, dst_port)] += 1
        if udp_count[(src, dst_port)] > UDP_THRESHOLD:
            message = f"[ALERT] UDP Flood detected from {src} to port {dst_port}"
            log_alert(message)
            total_alerts += 1

# ---------- PAKET YAKALAMA ----------
print("Starting packet sniffing... Press Ctrl+C to stop.")
sniff(filter="ip", prn=analyze_packet, store=0)