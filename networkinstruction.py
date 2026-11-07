
from scapy.all import sniff, IP, TCP, ICMP
from collections import defaultdict, deque
from datetime import datetime
import logging
import time

# ==========================================
# SHADOWX - NETWORK INTRUSION DETECTION SYSTEM
# ==========================================

print("=" * 65)
print("          SHADOWX NETWORK INTRUSION DETECTION SYSTEM")
print("=" * 65)

# Detection configuration
TIME_WINDOW = 10
SYN_THRESHOLD = 20
ICMP_THRESHOLD = 30
ALERT_COOLDOWN = 15

# Ports that deserve additional monitoring
WATCHED_PORTS = {
    23: "Telnet",
    445: "SMB",
    3389: "Remote Desktop",
    4444: "Unusual Service Port",
    2323: "Alternative Telnet"
}

# Store traffic history
syn_history = defaultdict(deque)
icmp_history = defaultdict(deque)

# Store alert cooldown timestamps
last_alert = {}

# Statistics
total_packets = 0
total_alerts = 0

# Configure logging
logging.basicConfig(
    filename="alerts.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


# ==========================================
# ALERT SYSTEM
# ==========================================

def generate_alert(rule, source, details):

    global total_alerts

    current_time = time.time()
    alert_key = (rule, source)

    # Avoid repeated alerts
    if current_time - last_alert.get(alert_key, 0) < ALERT_COOLDOWN:
        return

    last_alert[alert_key] = current_time
    total_alerts += 1

    message = (
        f"[SECURITY ALERT] {rule} | "
        f"Source: {source} | {details}"
    )

    print("\n" + "!" * 65)
    print(message)
    print("!" * 65 + "\n")

    # Save alert to log file
    logging.warning(message)


# ==========================================
# REMOVE OLD PACKET RECORDS
# ==========================================

def clean_history(history, current_time):

    while history and current_time - history[0][0] > TIME_WINDOW:
        history.popleft()


# ==========================================
# PACKET ANALYSIS
# ==========================================

def analyze_packet(packet):

    global total_packets

    if IP not in packet:
        return

    total_packets += 1

    current_time = time.time()

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    # TCP analysis
    if TCP in packet:

        tcp = packet[TCP]
        destination_port = tcp.dport

        # Check watched destination ports
        if destination_port in WATCHED_PORTS:

            service = WATCHED_PORTS[destination_port]

            generate_alert(
                "Watched Destination Port",
                source_ip,
                f"Destination: {destination_ip}, "
                f"Port: {destination_port} ({service})"
            )

        # Detect SYN packets (without ACK)
        if tcp.flags & 0x02 and not tcp.flags & 0x10:

            history = syn_history[source_ip]

            history.append((current_time, destination_port))

            clean_history(history, current_time)

            unique_ports = len(set(port for _, port in history))

            if len(history) >= SYN_THRESHOLD:

                generate_alert(
                    "High TCP SYN Activity",
                    source_ip,
                    f"{len(history)} SYN packets "
                    f"within {TIME_WINDOW} seconds"
                )

            elif unique_ports >= 10:

                generate_alert(
                    "Multiple Destination Ports",
                    source_ip,
                    f"{unique_ports} different destination ports "
                    f"within {TIME_WINDOW} seconds"
                )

    # ICMP analysis
    if ICMP in packet:

        history = icmp_history[source_ip]

        history.append((current_time, None))

        clean_history(history, current_time)

        if len(history) >= ICMP_THRESHOLD:

            generate_alert(
                "High ICMP Traffic",
                source_ip,
                f"{len(history)} ICMP packets "
                f"within {TIME_WINDOW} seconds"
            )


# ==========================================
# START NETWORK MONITORING
# ==========================================

def start_ids():

    print("\n[+] Initializing detection engine...")
    print("[+] Detection rules loaded.")
    print("[+] Alert logging enabled.")
    print("[+] Network monitoring started.")
    print("\nMonitoring traffic. Press CTRL+C to stop.\n")

    try:

        sniff(
            filter="ip",
            prn=analyze_packet,
            store=False,
            promisc=False
        )

    except KeyboardInterrupt:

        print("\n\n" + "=" * 65)
        print("             NETWORK MONITORING STOPPED")
        print("=" * 65)

        print(f"Total Packets Analyzed : {total_packets}")
        print(f"Security Alerts        : {total_alerts}")

        print("Alert Log              : alerts.log")
        print("=" * 65)

    except Exception as error:

        print("\n[ERROR]", error)
        print("Check administrator/root permissions and Npcap.")


# ==========================================
# MAIN
# ==========================================

if __name__ == "__main__":
    start_ids()
