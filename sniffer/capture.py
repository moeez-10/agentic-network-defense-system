"""
Agentic Network Defense System (Day 20)
Full Pipeline Integration:

Capture -> Detect (Signature+Anomaly) -> Trust Score -> Zero Trust Policy -> Agent Decision -> IPS Action

Run:
  python -m sniffer.capture
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Callable

from scapy.all import sniff, Raw
from scapy.layers.inet import IP, TCP, UDP, ICMP

from detection.signature_engine import SignatureEngine
from detection.anomaly_engine import AnomalyEngine
from zero_trust.trust_score import TrustScorer
from zero_trust.policy_engine import ZeroTrustPolicyEngine
from agent.decision_agent import SecurityAgent
from ips.blocker import IPSBlocker


# -----------------------------
# Helpers
# -----------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_packet_record() -> Dict[str, Any]:
    return {
        "timestamp": now_iso(),
        "src_ip": None,
        "dst_ip": None,
        "protocol": "OTHER",
        "src_port": None,
        "dst_port": None,
        "packet_length": 0,
        "payload": b"",
        "payload_len": 0,
        "layer7_type": "UNKNOWN",
    }


# -----------------------------
# L7 detection
# -----------------------------
def detect_l7(packet, payload_text: str, src_port: Optional[int], dst_port: Optional[int]) -> str:
    # DNS + mDNS by UDP ports
    if packet.haslayer(UDP):
        udp = packet[UDP]
        if udp.sport == 53 or udp.dport == 53:
            return "DNS"
        if udp.sport == 5353 or udp.dport == 5353:
            return "MDNS"

    # HTTP by plaintext payload prefix (best effort)
    if payload_text.startswith("GET ") or payload_text.startswith("POST ") or payload_text.startswith("HTTP/"):
        return "HTTP"

    # HTTPS by port 443 (TCP or UDP/QUIC)
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        if tcp.sport == 443 or tcp.dport == 443:
            return "HTTPS"
    if packet.haslayer(UDP):
        udp = packet[UDP]
        if udp.sport == 443 or udp.dport == 443:
            return "HTTPS"

    return "UNKNOWN"


# -----------------------------
# Extract packet record
# -----------------------------
def extract_packet_info(packet) -> Optional[Dict[str, Any]]:
    if not packet.haslayer(IP):
        return None

    rec = new_packet_record()

    ip = packet[IP]
    rec["src_ip"] = ip.src
    rec["dst_ip"] = ip.dst

    try:
        rec["packet_length"] = len(packet)
    except Exception:
        rec["packet_length"] = 0

    # protocol + ports
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        rec["protocol"] = "TCP"
        rec["src_port"] = int(tcp.sport)
        rec["dst_port"] = int(tcp.dport)
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        rec["protocol"] = "UDP"
        rec["src_port"] = int(udp.sport)
        rec["dst_port"] = int(udp.dport)
    elif packet.haslayer(ICMP):
        rec["protocol"] = "ICMP"
    else:
        rec["protocol"] = "OTHER"

    # payload extraction
    payload_text = ""
    if packet.haslayer(Raw):
        payload_bytes = bytes(packet[Raw].load)
        rec["payload"] = payload_bytes
        rec["payload_len"] = len(payload_bytes)
        payload_text = payload_bytes.decode("utf-8", errors="ignore")

    # L7 label
    rec["layer7_type"] = detect_l7(packet, payload_text, rec.get("src_port"), rec.get("dst_port"))
    return rec


# -----------------------------
# Console formatting
# -----------------------------
def format_packet_line(i: int, rec: Dict[str, Any]) -> str:
    src = rec["src_ip"]
    dst = rec["dst_ip"]
    proto = rec["protocol"]
    sp = rec["src_port"]
    dp = rec["dst_port"]
    l7 = rec["layer7_type"]
    plen = rec["payload_len"]
    pktlen = rec["packet_length"]

    if sp is not None and dp is not None:
        return f"[{i:03d}] {proto} {src}:{sp} -> {dst}:{dp} | L7={l7:<7} | pkt_len={pktlen:<5} | payload_len={plen}"
    return f"[{i:03d}] {proto} {src} -> {dst} | L7={l7:<7} | pkt_len={pktlen:<5} | payload_len={plen}"


def print_sig_alert(alert: Dict[str, Any]) -> None:
    sev = alert.get("severity")
    rid = alert.get("rule_id")
    cat = alert.get("category")
    act = alert.get("action")
    src = alert.get("src_ip")
    match = alert.get("matched_pattern")
    print(f"  [SIG][{sev}] {rid} {cat} action={act} src={src} matched={match}")


def print_anom_alert(alert: Dict[str, Any]) -> None:
    sev = alert.get("severity")
    a_type = alert.get("type")
    src = alert.get("src_ip")
    evid = alert.get("evidence")
    print(f"  [ANOM][{sev}] {a_type} src={src} evidence={evid}")


# -----------------------------
# Capture runner
# -----------------------------
def run_capture(
    count: int = 80,
    interface: Optional[str] = None,
    print_packets: bool = True,
    on_packet: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> None:
    packet_counter = 0

    def handler(pkt):
        nonlocal packet_counter
        rec = extract_packet_info(pkt)
        if rec is None:
            return

        packet_counter += 1

        if print_packets:
            print(format_packet_line(packet_counter, rec))

        if on_packet:
            on_packet(rec)

    print("Starting packet capture...")
    print(f"Mode: count-based (count={count})")
    if interface:
        print(f"Interface: {interface}")

    try:
        sniff(count=count, prn=handler, store=False, iface=interface)
    except KeyboardInterrupt:
        print("\nStopped by user (Ctrl+C).")

    print("Packet capture complete.")
    print(f"IP packets processed: {packet_counter}")


# -----------------------------
# Main pipeline (Day 20)
# -----------------------------
if __name__ == "__main__":
    sig_engine = SignatureEngine("detection/rules.json")
    anom_engine = AnomalyEngine(
        rate_window_sec=5,
        rate_threshold=20,
        payload_size_threshold=5000,
        portscan_window_sec=60,
        portscan_unique_ports=10,
    )

    trust_scorer = TrustScorer()
    policy_engine = ZeroTrustPolicyEngine()
    agent = SecurityAgent()
    blocker = IPSBlocker()

    def pipeline(packet_record: Dict[str, Any]) -> None:
        src_ip = packet_record.get("src_ip")
        dst_ip = packet_record.get("dst_ip")

        # 1) IPS hard block (skip everything)
        if src_ip and blocker.is_blocked(src_ip):
            print(f"  [IPS] SKIP blocked src_ip={src_ip}")
            return

        # 2) Detection
        sig_alerts = []
        if packet_record.get("layer7_type") == "HTTP":
            sig_alerts = sig_engine.check(packet_record)
            for a in sig_alerts:
                print_sig_alert(a)

        anom_alerts = anom_engine.check(packet_record)
        for a in anom_alerts:
            print_anom_alert(a)

        # 3) Trust scoring
        trust_result = trust_scorer.evaluate_packet(
            src_ip=src_ip,
            sig_alerts=sig_alerts,
            anom_alerts=anom_alerts,
        )

        # 4) Zero trust policy enforcement
        policy_result = policy_engine.enforce(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_trust_score=trust_result.score,
        )

        # 5) Agent decision
        decision = agent.run(
            packet_record=packet_record,
            sig_alerts=sig_alerts,
            anom_alerts=anom_alerts,
            trust_result=trust_result,
            policy_result=policy_result,
        )

        # 6) Act on agent decision (IPS safeguard)
        final_action = decision["final_action"]

        if final_action == "BLOCK" and src_ip:
            try:
                ip_obj = ipaddress.ip_address(src_ip)
                if ip_obj.is_private or ip_obj.is_loopback:
                    print(f"  [IPS] BLOCK skipped for private/loopback ip={src_ip}")
                else:
                    reason = (
                        f"agent_threat={decision['threat_level']} policy={decision['policy_decision']} "
                        f"trust={decision['trust_score']}"
                    )
                    newly = blocker.block_ip(ip=src_ip, reason=reason)
                    if newly:
                        print(f"  [IPS] BLOCKED ip={src_ip} reason={reason}")
            except ValueError:
                print(f"  [IPS] BLOCK skipped (invalid ip) src_ip={src_ip}")

        elif final_action == "THROTTLE":
            print(f"  [AGENT] THROTTLE src_ip={src_ip} reason={decision['reason']}")

        # 7) Summary line
        print(
            f"  [AGENT_DECISION] action={decision['final_action']:<8} threat={decision['threat_level']:<8} "
            f"| trust={decision['trust_score']:3d}({decision['trust_action']}) "
            f"| policy={decision['policy_decision']:<5} "
            f"| sig={len(sig_alerts)} anom={len(anom_alerts)} "
            f"| {src_ip} -> {dst_ip} | reason={decision['reason']}"
        )

    run_capture(count=80, interface=None, print_packets=True, on_packet=pipeline)