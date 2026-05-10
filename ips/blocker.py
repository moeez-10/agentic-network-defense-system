"""
IPS Blocker (Windows-safe simulation).

This module simulates blocking by maintaining an in-memory blocklist.
Later (optional), Linux iptables blocking can be added.

Responsibilities:
- block_ip(ip, reason, metadata)
- is_blocked(ip)
- get_blocked_ips()
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, Optional, Any, List


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class BlockEntry:
    ip: str
    timestamp: str
    reason: str
    rule_id: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = None


class IPSBlocker:
    def __init__(self) -> None:
        # key: ip, value: BlockEntry
        self._blocked: Dict[str, BlockEntry] = {}
        self._events: List[Dict[str, Any]] = []

    def block_ip(
        self,
        ip: str,
        reason: str,
        rule_id: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> bool:
        """
        Block an IP. Returns True if newly blocked, False if already blocked.
        """
        if not ip:
            return False

        if ip in self._blocked:
            return False

        entry = BlockEntry(
            ip=ip,
            timestamp=now_iso(),
            reason=reason,
            rule_id=rule_id,
            category=category,
            severity=severity,
        )
        self._blocked[ip] = entry

        self._events.append(
            {
                "timestamp": entry.timestamp,
                "ip": ip,
                "action": "BLOCK",
                "reason": reason,
                "rule_id": rule_id,
                "category": category,
                "severity": severity,
            }
        )
        return True

    def is_blocked(self, ip: str) -> bool:
        return ip in self._blocked

    def get_blocked_ips(self) -> List[Dict[str, Any]]:
        """
        Return blocked list as plain dicts (easy for dashboard later).
        """
        return [asdict(e) for e in self._blocked.values()]

    def get_events(self) -> List[Dict[str, Any]]:
        return list(self._events)