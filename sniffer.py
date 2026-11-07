
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR
from datetime import datetime

# Network Sniffer
print("=" * 65)
print("             SHADOWX - BASIC NETWORK SNIFFER")
print("=" * 65)

packet_count = 0


def analyze_packet(packet):

    global packet_count

    if IP not in packet:
        return

    packet_count += 1

    # Basic packet information
    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    packet_size = len(packet)

    protocol = "OTHER"
    source_port = "-"
    destination_port = "-"
    payload_size = 0

    # TCP Protocol
    if TCP in packet:
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
        payload_size = len(bytes(packet[TCP].payload))

    # UDP Protocol
    elif UDP in packet:
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport
        payload_size = len(bytes(packet[UDP].payload))

    # ICMP Protocol
    elif ICMP in packet:
        protocol = "ICMP"

    # Display packet information
    print("\n" + "-" * 65)
    print(f"PACKET NUMBER : {packet_count}")
    print(f"TIME          : {datetime.now().strftime('%H:%M:%S')}")
    print("-" * 65)

    print(f"Source IP      : {source_ip}")
    print(f"Destination IP : {destination_ip}")
    print(f"Protocol       : {protocol}")
    print(f"Source Port    : {source_port}")
    print(f"Destination Port: {destination_port}")
    print(f"Packet Size    : {packet_size} bytes")
    print(f"Payload Size   : {payload_size} bytes")

    # DNS Information
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        try:
            dns_query = packet[DNSQR].qname.decode(
                "utf-8", errors="replace"
            )
            print(f"DNS Query      : {dns_query}")
        except Exception:
            print("DNS Query      : Unable to decode")

    print("-" * 65)


# Start packet capture
def start_sniffer():

    print("\nStarting Network Sniffer...")
    print("Capturing IPv4 packets visible to this device.")
    print("Press CTRL + C to stop capturing.\n")

    try:
        sniff(
            filter="ip",
            prn=analyze_packet,
            store=False,
            promisc=False
        )

    except KeyboardInterrupt:
        print("\n\n" + "=" * 65)
        print("             CAPTURE STOPPED")
        print("=" * 65)
        print(f"Total Packets Captured: {packet_count}")
        print("Thank you for using ShadowX Network Sniffer!")

    except Exception as error:
        print("\nError:", error)
        print("Check your permissions and network capture driver.")


if __name__ == "__main__":
    start_sniffer()
