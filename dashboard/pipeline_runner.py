from __future__ import annotations

import threading
import time
from typing import Any, Dict

from dashboard.data_store import STORE

from sniffer.capture import run_capture  # uses your sniffer module
from detection.signature_engine import SignatureEngine
from detection.anomaly_engine import AnomalyEngine
from zero_trust.trust_score import TrustScorer
from zero_trust.policy_engine import ZeroTrustPolicyEngine
from agent.decision_agent import SecurityAgent
from ips.blocker import IPSBlocker


def start_pipeline_in_background() -> None:
    """
    Starts the security pipeline in a background thread and continuously updates STORE.
    """

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

        # packets analyzed counter
        STORE.summary["packets_analyzed"] += 1

        # IPS skip
        if src_ip and blocker.is_blocked(src_ip):
            return

        # Detection
        sig_alerts = []
        if packet_record.get("layer7_type") == "HTTP":
            sig_alerts = sig_engine.check(packet_record)

        anom_alerts = anom_engine.check(packet_record)

        # Add alerts to store (convert to dashboard-friendly format)
        for a in sig_alerts:
            STORE.add_alert({
                "time": a.get("timestamp", ""),
                "src_ip": a.get("src_ip", ""),
                "type": a.get("category", ""),
                "severity": a.get("severity", "LOW"),
                "action": a.get("action", "ALERT"),
            })

        for a in anom_alerts:
            STORE.add_alert({
                "time": a.get("timestamp", ""),
                "src_ip": a.get("src_ip", ""),
                "type": a.get("type", ""),
                "severity": a.get("severity", "MEDIUM"),
                "action": a.get("action", "ALERT"),
            })

        # Trust scoring
        trust_result = trust_scorer.evaluate_packet(src_ip=src_ip, sig_alerts=sig_alerts, anom_alerts=anom_alerts)
        if src_ip:
            STORE.set_trust_score(src_ip, trust_result.score)

        # Policy
        policy_result = policy_engine.enforce(src_ip=src_ip, dst_ip=dst_ip, src_trust_score=trust_result.score)

        # Agent decision
        decision = agent.run(
            packet_record=packet_record,
            sig_alerts=sig_alerts,
            anom_alerts=anom_alerts,
            trust_result=trust_result,
            policy_result=policy_result,
        )
        STORE.add_agent_decision(decision)

        # Act: block if agent says block (simulation)
        if decision.get("final_action") == "BLOCK" and src_ip:
            blocker.block_ip(ip=src_ip, reason=decision.get("reason", "blocked by agent"))

        # Update blocked list + stats
        STORE.set_blocked_ips(blocker.get_blocked_ips())
        STORE.set_agent_stats(agent.get_stats())

        # Active threats (simple metric)
        # count last 20 decisions that are HIGH/CRITICAL
        recent = agent.get_recent_decisions(20)
        STORE.summary["active_threats"] = sum(1 for d in recent if d.get("threat_level") in ("HIGH", "CRITICAL"))

    def runner():
        # continuous capture: call run_capture in a loop
        while True:
            run_capture(count=50, interface=None, print_packets=False, on_packet=pipeline)
            time.sleep(0.5)

    t = threading.Thread(target=runner, daemon=True)
    t.start()