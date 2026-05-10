"""
Agentic Decision Engine (Days 18–21)

Day 18:
- OODA loop (Observe -> Analyze -> Decide -> Act)
- Decision logging

Day 19:
- Per-IP memory (seen counts, blocks, throttles, allows)
- Learning rules:
  - If an IP was blocked before, escalate future threat level by +1 step
  - If an IP is clean for many observations, mark as trusted

Day 21:
- Reporting/stats:
  - get_stats()
  - get_threat_summary()
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from collections import defaultdict


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def severity_rank(sev: str) -> int:
    sev = (sev or "").upper()
    mapping = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return mapping.get(sev, 0)


THREAT_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def bump_threat(threat_level: str, steps: int = 1) -> str:
    try:
        idx = THREAT_ORDER.index(threat_level)
    except ValueError:
        idx = 0
    idx = min(len(THREAT_ORDER) - 1, idx + steps)
    return THREAT_ORDER[idx]


@dataclass
class AgentDecision:
    timestamp: str
    src_ip: str
    dst_ip: Optional[str]
    threat_level: str
    policy_decision: str
    trust_score: int
    trust_action: str
    final_action: str
    reason: str
    memory_snapshot: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SecurityAgent:
    def __init__(self) -> None:
        # decision log for dashboard later
        self.decision_log: List[Dict[str, Any]] = []

        # per-IP memory
        self.memory: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {
                "seen": 0,
                "blocks": 0,
                "throttles": 0,
                "allows": 0,
                "last_threat_level": None,
                "trusted": False,
            }
        )

    # -------------------------
    # Memory update helpers
    # -------------------------
    def _update_memory_pre(self, src_ip: str) -> None:
        self.memory[src_ip]["seen"] += 1

        # Trusted rule: long clean history
        m = self.memory[src_ip]
        if m["seen"] >= 100 and m["blocks"] == 0 and m["throttles"] == 0:
            m["trusted"] = True

    def _update_memory_post(self, src_ip: str, threat_level: str, final_action: str) -> None:
        m = self.memory[src_ip]
        m["last_threat_level"] = threat_level

        if final_action == "BLOCK":
            m["blocks"] += 1
        elif final_action == "THROTTLE":
            m["throttles"] += 1
        elif final_action == "ALLOW":
            m["allows"] += 1

    # -------------------------
    # OODA: Observe
    # -------------------------
    def observe(
        self,
        packet_record: Dict[str, Any],
        sig_alerts: List[Dict[str, Any]],
        anom_alerts: List[Dict[str, Any]],
        trust_result: Any,
        policy_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {
            "packet": packet_record,
            "sig_alerts": sig_alerts or [],
            "anom_alerts": anom_alerts or [],
            "trust": trust_result,
            "policy": policy_result,
        }

    # -------------------------
    # OODA: Analyze
    # -------------------------
    def analyze(self, obs: Dict[str, Any]) -> Dict[str, Any]:
        packet = obs["packet"]
        sig_alerts = obs["sig_alerts"]
        anom_alerts = obs["anom_alerts"]
        trust = obs["trust"]
        policy = obs["policy"]

        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")

        policy_decision = policy.get("decision", "DENY")
        trust_action = getattr(trust, "action", "DENY")
        trust_score = int(getattr(trust, "score", 0))

        # Determine max signature severity
        max_sig_sev = 0
        for a in sig_alerts:
            max_sig_sev = max(max_sig_sev, severity_rank(a.get("severity")))

        anomaly_types = {a.get("type") for a in anom_alerts if isinstance(a, dict)}
        has_rate = "RATE_ANOMALY" in anomaly_types

        # Base threat level rules
        if policy_decision == "DENY" or trust_action == "DENY":
            threat_level = "CRITICAL"
            reason = "Zero Trust policy/trust denied the flow"
        elif max_sig_sev >= severity_rank("HIGH"):
            threat_level = "HIGH"
            reason = "High-severity signature alert detected"
        elif has_rate:
            threat_level = "HIGH"
            reason = "Rate anomaly detected"
        elif len(anom_alerts) > 0:
            threat_level = "MEDIUM"
            reason = "Anomaly detected"
        elif trust_action == "CHALLENGE":
            threat_level = "MEDIUM"
            reason = "Trust requires challenge"
        else:
            threat_level = "LOW"
            reason = "No significant threat indicators"

        # Day 19 learning: if previously blocked, escalate future encounters
        m = self.memory[src_ip]
        if m["blocks"] >= 1 and threat_level != "CRITICAL":
            threat_level = bump_threat(threat_level, steps=1)
            reason = reason + " + history: previously blocked"

        # Trusted behavior: if trusted and everything clean, keep LOW
        if m["trusted"] and policy_decision == "ALLOW" and not sig_alerts and not anom_alerts and trust_action == "ALLOW":
            threat_level = "LOW"
            reason = "Trusted source with clean history"

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "policy_decision": policy_decision,
            "trust_score": trust_score,
            "trust_action": trust_action,
            "threat_level": threat_level,
            "reason": reason,
        }

    # -------------------------
    # OODA: Decide
    # -------------------------
    def decide(self, analysis: Dict[str, Any]) -> str:
        tl = analysis["threat_level"]
        if tl == "CRITICAL":
            return "BLOCK"
        if tl == "HIGH":
            return "BLOCK"
        if tl == "MEDIUM":
            return "THROTTLE"
        return "ALLOW"

    # -------------------------
    # OODA: Act (log + memory)
    # -------------------------
    def act(self, analysis: Dict[str, Any], final_action: str) -> Dict[str, Any]:
        src_ip = analysis["src_ip"]
        mem_snapshot = dict(self.memory[src_ip])

        decision = AgentDecision(
            timestamp=now_iso(),
            src_ip=src_ip,
            dst_ip=analysis.get("dst_ip"),
            threat_level=analysis["threat_level"],
            policy_decision=analysis["policy_decision"],
            trust_score=analysis["trust_score"],
            trust_action=analysis["trust_action"],
            final_action=final_action,
            reason=analysis["reason"],
            memory_snapshot=mem_snapshot,
        ).to_dict()

        self.decision_log.append(decision)
        self._update_memory_post(src_ip, analysis["threat_level"], final_action)
        return decision

    # -------------------------
    # Full loop helper
    # -------------------------
    def run(
        self,
        packet_record: Dict[str, Any],
        sig_alerts: List[Dict[str, Any]],
        anom_alerts: List[Dict[str, Any]],
        trust_result: Any,
        policy_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        src_ip = packet_record.get("src_ip")
        if not src_ip:
            src_ip = "UNKNOWN"
            packet_record["src_ip"] = src_ip

        self._update_memory_pre(src_ip)

        obs = self.observe(packet_record, sig_alerts, anom_alerts, trust_result, policy_result)
        analysis = self.analyze(obs)
        action = self.decide(analysis)
        return self.act(analysis, action)

    # -------------------------
    # Reporting (Day 21)
    # -------------------------
    def get_recent_decisions(self, n: int = 20) -> List[Dict[str, Any]]:
        return self.decision_log[-n:]

    def get_memory(self) -> Dict[str, Dict[str, Any]]:
        return dict(self.memory)

    def get_stats(self) -> Dict[str, Any]:
        """
        Return overall agent statistics for reporting/dashboard.
        """
        total = len(self.decision_log)

        allows = 0
        throttles = 0
        blocks = 0

        src_counts: Dict[str, int] = {}

        for d in self.decision_log:
            action = d.get("final_action")
            src = d.get("src_ip")

            if action == "ALLOW":
                allows += 1
            elif action == "THROTTLE":
                throttles += 1
            elif action == "BLOCK":
                blocks += 1

            if src:
                src_counts[src] = src_counts.get(src, 0) + 1

        top_src = sorted(src_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        return {
            "total_decisions": total,
            "allows": allows,
            "throttles": throttles,
            "blocks": blocks,
            "top_src_ips": top_src,
        }

    def get_threat_summary(self) -> Dict[str, Any]:
        """
        Return per-IP threat level counts.
        """
        per_ip: Dict[str, Dict[str, int]] = {}

        for d in self.decision_log:
            src = d.get("src_ip", "UNKNOWN")
            tl = d.get("threat_level", "UNKNOWN")

            if src not in per_ip:
                per_ip[src] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0, "UNKNOWN": 0}

            if tl not in per_ip[src]:
                per_ip[src]["UNKNOWN"] += 1
            else:
                per_ip[src][tl] += 1

        return {"per_ip": per_ip}