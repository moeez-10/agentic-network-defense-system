# Agentic Network Defense System

A modular network security project designed to monitor network traffic, detect malicious activity, apply Zero Trust principles, and make autonomous defense decisions. The system combines packet sniffing, signature-based and anomaly-based intrusion detection, trust scoring, policy enforcement, and a live monitoring dashboard.

## Core Modules
- **Sniffer** – Captures live network packets and extracts important packet information.
- **Detection Engine** – Identifies suspicious or malicious traffic using signatures and anomaly detection.
- **Zero Trust Engine** – Maintains trust scores and enforces access decisions based on policy.
- **Agent Engine** – Makes autonomous decisions such as allow, alert, throttle, or block.
- **Dashboard** – Displays alerts, trust scores, blocked IPs, and agent decisions in real time.

## Technologies Used
- Python
- Scapy
- Flask
- Wireshark

## Project Structure
agentic-network-defense-system/
├── sniffer/
├── detection/
├── agent/
├── zero_trust/
├── dashboard/
│   └── templates/
├── config.yaml
├── requirements.txt
└── README.md
