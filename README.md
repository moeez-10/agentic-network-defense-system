# Agentic Network Defense System

A modular network security defense system that combines packet capture, intrusion detection, zero trust policy enforcement, and autonomous agent-based decision making.

## Architecture
1. **Network Sensor** - Packet capture and L7 classification  
2. **Detection Engine** - Signature + Anomaly based IDS/IPS  
3. **Agentic Decision Engine** - Autonomous threat response  
4. **Zero Trust Policy Engine** - Trust scoring + micro-segmentation  
5. **Dashboard** - Live monitoring UI  

## Project Structure
```text
agentic-network-defense-system/
├── sniffer/                # Packet capture and preprocessing
├── detection/              # IDS/IPS signature + anomaly detection
├── agent/                  # Autonomous decision engine
├── zero_trust/             # Trust scoring and policy enforcement
├── dashboard/              # Flask monitoring dashboard
│   └── templates/
├── tests/                  # Test suite
├── config.yaml             # Project configuration
├── requirements.txt        # Python dependencies
└── README.md
Setup
Bash

# Create virtual environment
python -m venv venv

# Activate venv (Windows)
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
Current Status
✅ Day 1: Environment setup
✅ Day 2: Basic packet capture
✅ Day 3: Layer 7 classification
✅ Day 4: Architecture diagram
✅ Day 5: Project skeleton + configuration

Phases
Phase 1: Foundation / Setup / Architecture
Phase 2: Core Engine / IDS/IPS
Phase 3: Zero Trust + Agentic Defense
Phase 4: Dashboard + Final Testing
Verified Skeleton Structure
text

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





