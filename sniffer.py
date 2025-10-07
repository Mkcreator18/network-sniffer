# Network Packet Sniffer with Alert System
# Author: Grok (built by xAI)
# Description: A simple MVP for real-time network packet sniffing, anomaly detection,
# logging to SQLite, traffic summary display using Matplotlib, and email alerts on thresholds.
# Requirements: Run as root/admin for packet capture (e.g., sudo python sniffer.py).
# Libraries: scapy (for packet capture), sqlite3 (built-in), matplotlib (for graphs),
# smtplib/email (built-in for alerts).
#
# Usage: python sniffer.py --interface <network_interface> --email <your_email> --password <app_password> --receiver <alert_email>
# Example: python sniffer.py --interface Wi-Fi --email sender@gmail.com --password app_pass --receiver alert@gmail.com
# Note: For email, use an app password if using Gmail (enable 2FA and create app password).
# Press Ctrl+C to stop and view summary graph.

import argparse
import sqlite3
import time
from collections import defaultdict, Counter
import smtplib
from email.mime.text import MIMEText
from scapy.all import sniff, IP, TCP, UDP
import matplotlib.pyplot as plt
import threading

# Database setup
DB_NAME = 'network_logs.db'

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            length INTEGER,
            protocol TEXT,
            flags TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            alert_type TEXT,
            details TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Logging function
def log_packet(packet_data):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, length, protocol, flags)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', packet_data)
    conn.commit()
    conn.close()

def log_alert(alert_type, details):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO alerts (timestamp, alert_type, details)
        VALUES (?, ?, ?)
    ''', (time.strftime("%Y-%m-%d %H:%M:%S"), alert_type, details))
    conn.commit()
    conn.close()

# Email alert function
def send_email_alert(subject, body, sender_email, app_password, receiver_email):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = receiver_email

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, app_password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()
        print("Alert email sent successfully.")
    except Exception as e:
        print(f"Failed to send email: {e}")

# Anomaly detection trackers
packet_counts = defaultdict(int)  # Per source IP
port_scans = defaultdict(set)     # Ports per destination IP
start_time = time.time()
FLOOD_THRESHOLD = 100  # Packets per second threshold for flooding
SCAN_THRESHOLD = 10    # Different ports to same IP in short time
CHECK_INTERVAL = 10    # Seconds to check anomalies

def check_anomalies(sender_email, app_password, receiver_email):
    while True:
        time.sleep(CHECK_INTERVAL)
        elapsed = time.time() - start_time
        if elapsed > 0:
            rate = sum(packet_counts.values()) / elapsed
            if rate > FLOOD_THRESHOLD:
                details = f"High packet rate: {rate:.2f} packets/sec"
                log_alert("Flooding", details)
                send_email_alert("Network Flood Alert", details, sender_email, app_password, receiver_email)
                print(details)

        for ip, ports in port_scans.items():
            if len(ports) > SCAN_THRESHOLD:
                details = f"Possible port scan on {ip} with {len(ports)} ports"
                log_alert("Port Scan", details)
                send_email_alert("Port Scan Alert", details, sender_email, app_password, receiver_email)
                print(details)
                port_scans[ip].clear()  # Reset after alert

        # Reset counters periodically
        packet_counts.clear()
        global start_time
        start_time = time.time()

# Packet callback
def packet_callback(packet, sender_email, app_password, receiver_email):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        length = len(packet)
        protocol = "Other"
        src_port = dst_port = flags = None

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        packet_data = (timestamp, src_ip, dst_ip, src_port, dst_port, length, protocol, str(flags))
        log_packet(packet_data)

        # Update anomaly trackers
        packet_counts[src_ip] += 1
        if dst_port:
            port_scans[dst_ip].add(dst_port)

        print(f"Captured: {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Proto: {protocol} | Len: {length} | Flags: {flags}")

# Display summary
def display_summary():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Fetch data
    cursor.execute("SELECT src_ip, COUNT(*) FROM packets GROUP BY src_ip")
    src_ip_counts = cursor.fetchall()

    cursor.execute("SELECT protocol, COUNT(*) FROM packets GROUP BY protocol")
    proto_counts = cursor.fetchall()

    conn.close()

    if src_ip_counts:
        ips, counts = zip(*src_ip_counts)
        plt.figure(figsize=(10, 5))
        plt.bar(ips, counts)
        plt.xlabel('Source IPs')
        plt.ylabel('Packet Count')
        plt.title('Traffic Summary by Source IP')
        plt.xticks(rotation=45)
        plt.show()

    if proto_counts:
        protos, counts = zip(*proto_counts)
        plt.figure(figsize=(6, 6))
        plt.pie(counts, labels=protos, autopct='%1.1f%%')
        plt.title('Protocol Distribution')
        plt.show()

def main():
    parser = argparse.ArgumentParser(description="Network Packet Sniffer with Alerts")
    parser.add_argument("--interface", required=True, help="Network interface to sniff (e.g., eth0)")
    parser.add_argument("--email", required=True, help="Sender email for alerts")
    parser.add_argument("--password", required=True, help="App password for sender email")
    parser.add_argument("--receiver", required=True, help="Receiver email for alerts")
    args = parser.parse_args()

    init_db()

    # Start anomaly checker thread
    anomaly_thread = threading.Thread(target=check_anomalies, args=(args.email, args.password, args.receiver), daemon=True)
    anomaly_thread.start()

    print("Starting packet capture... Press Ctrl+C to stop.")
    try:
        sniff(iface=args.interface, prn=lambda p: packet_callback(p, args.email, args.password, args.receiver), store=0)
    except KeyboardInterrupt:
        print("Stopping capture...")
        display_summary()

if __name__ == "__main__":
    main()