# Agentic Network Defense System

Zero-Trust based network security framework implementing 
application-layer IDS/IPS with dynamic trust scoring 
and agent-driven policy enforcement.

## Technologies Used
- Python
- Scapy
- Flask
- SQLite
- JSON

## Features
- Layer 7 traffic inspection
- Signature & anomaly detection
- Dynamic trust scoring
- Adaptive allow/block decisions
- Real-time monitoring dashboard
## Project Structure

Agentic_Network_Defense_System/
├── .gitignore
├── README.md
├── requirements.txt
├── config.yaml
├── sniffer/
│   ├── __init__.py
│   └── capture.py
├── detection/
│   ├── __init__.py
│   ├── signature_engine.py
│   └── anomaly_engine.py
├── agent/
│   ├── __init__.py
│   └── decision_agent.py
├── zero_trust/
│   ├── __init__.py
│   ├── trust_score.py
│   └── policy_engine.py
├── dashboard/
│   ├── __init__.py
│   ├── app.py
│   └── templates/
│       └── index.html
└── tests/
    ├── __init__.py
    └── test_detection.py

# How to run
Setup
Bash

## Create virtual environment
python -m venv venv

## Activate venv (Windows)
venv\Scripts\activate

## Install dependencies
pip install -r requirements.txt







