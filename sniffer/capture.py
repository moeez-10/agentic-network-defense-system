"""
Day 3 - Agentic Network Defense System
Packet capture + basic Layer 7 identification.

- Captures packets using Scapy
- Extracts src/dst IP (IP layer)
- Extracts payload (Raw) safely
- Labels L7 traffic as:
  - DNS (UDP port 53)
  - HTTP (payload starts with GET/POST/HTTP/)
  - UNKNOWN otherwise
"""

from scapy.all import sniff, Raw
from scapy.layers.inet import IP, UDP

counter = 0


def handle_packet(packet):
    global counter

    # Process only IP packets
    if not packet.haslayer(IP):
        return

    counter += 1

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # Default payload values
    payload_len = 0
    payload_text = ""

    # Extract payload safely (if exists)
    if packet.haslayer(Raw):
        payload_bytes = packet[Raw].load
        payload_len = len(payload_bytes)
        
        payload_text = payload_bytes.decode("utf-8", errors="ignore")

    # L7 detection
    l7_type = "UNKNOWN"

    # DNS detection by UDP port 53
    if packet.haslayer(UDP):
        if packet[UDP].sport == 53 or packet[UDP].dport == 53:
            l7_type = "DNS"

    # HTTP detection by payload prefix (plaintext HTTP only)
    if payload_text.startswith("GET ") or payload_text.startswith("POST ") or payload_text.startswith("HTTP/"):
        l7_type = "HTTP"

    print(f"[PACKET {counter}] {src_ip} -> {dst_ip} | L7={l7_type} | payload_len={payload_len}")


if __name__ == "__main__":
    print("Starting packet capture...")
    sniff(count=10, prn=handle_packet, store=False)
    print("Packet capture complete.")