from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class DataStore:
    summary: Dict[str, int] = field(default_factory=lambda: {
        "packets_analyzed": 0,
        "alerts": 0,
        "ips_blocked": 0,
        "active_threats": 0,
    })

    recent_alerts: List[Dict[str, Any]] = field(default_factory=list)
    trust_scores: Dict[str, int] = field(default_factory=dict)
    agent_decisions: List[Dict[str, Any]] = field(default_factory=list)
    blocked_ips: List[Dict[str, Any]] = field(default_factory=list)
    agent_stats: Dict[str, Any] = field(default_factory=dict)

    def add_alert(self, alert: Dict[str, Any], max_items: int = 50) -> None:
        self.recent_alerts.insert(0, alert)
        self.recent_alerts = self.recent_alerts[:max_items]
        self.summary["alerts"] += 1

    def add_agent_decision(self, decision: Dict[str, Any], max_items: int = 50) -> None:
        self.agent_decisions.insert(0, decision)
        self.agent_decisions = self.agent_decisions[:max_items]

    def set_trust_score(self, ip: str, score: int) -> None:
        self.trust_scores[ip] = score

    def set_blocked_ips(self, blocked: List[Dict[str, Any]]) -> None:
        self.blocked_ips = blocked
        self.summary["ips_blocked"] = len(blocked)

    def set_agent_stats(self, stats: Dict[str, Any]) -> None:
        self.agent_stats = stats


STORE = DataStore()