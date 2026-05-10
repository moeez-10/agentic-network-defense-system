"""
Signature-based detection engine.

- Loads signature rules from detection/rules.json
- Scans packet payload for known malicious patterns (case-insensitive substring matching)
- Returns structured alerts with severity, action, and matched pattern
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SignatureEngine:
    def __init__(self, rules_path: str = "detection/rules.json") -> None:
        self.rules_path = rules_path
        self.rules: List[Dict[str, Any]] = []
        self.load_rules()

    def load_rules(self) -> None:
        """Load rules from JSON file into memory."""
        with open(self.rules_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.rules = data.get("rules", [])

    @staticmethod
    def _payload_to_text(packet_record: Dict[str, Any]) -> str:
        """
        Convert payload (bytes or string) into a safe text string for matching.
        """
        payload = packet_record.get("payload", b"")
        if payload is None:
            return ""

        if isinstance(payload, bytes):
            return payload.decode("utf-8", errors="ignore")

        # If payload is already a string (unlikely but supported)
        if isinstance(payload, str):
            return payload

        return str(payload)

    def check(self, packet_record: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Scan a packet record for signature matches.

        Returns: list of alert dicts (empty if none).
        """
        alerts: List[Dict[str, Any]] = []

        payload_text = self._payload_to_text(packet_record)
        if not payload_text:
            return alerts

        payload_lower = payload_text.lower()

        src_ip = packet_record.get("src_ip")
        dst_ip = packet_record.get("dst_ip")

        for rule in self.rules:
            rule_id = rule.get("id")
            category = rule.get("category")
            severity = rule.get("severity")
            action = rule.get("action")
            description = rule.get("description", "")
            patterns = rule.get("patterns", [])

            for pat in patterns:
                if not isinstance(pat, str) or not pat:
                    continue

                if pat.lower() in payload_lower:
                    alerts.append(
                        {
                            "timestamp": now_iso(),
                            "rule_id": rule_id,
                            "category": category,
                            "severity": severity,
                            "action": action,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "matched_pattern": pat,
                            "description": description,
                        }
                    )
                    # Stop after first match per rule to reduce duplicate alerts
                    break

        return alerts
    @staticmethod
    def format_alert(alert: Dict[str, Any]) -> str:
        """
        Return a clean one-line string for console logging.
        """
        return (
            f"[{alert.get('severity')}] {alert.get('rule_id')} {alert.get('category')} "
            f"action={alert.get('action')} src={alert.get('src_ip')} matched={alert.get('matched_pattern')}"
        )