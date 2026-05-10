"""
Anomaly-based detection engine.

Alert format:
{
  "timestamp": "...",
  "type": "RATE_ANOMALY|PAYLOAD_SIZE|PORT_SCAN",
  "severity": "MEDIUM|HIGH|CRITICAL",
  "src_ip": "...",
  "dst_ip": "...",
  "evidence": { ... },
  "action": "ALERT"
}

Detections implemented:
- Rate anomaly: packets per src_ip in time window
- Payload size anomaly: payload_len above threshold
- Port scan: many unique dst ports from same src_ip in time window
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List, Optional, Set, Tuple


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AnomalyEngine:
    def __init__(
        self,
        rate_window_sec: int = 5,
        rate_threshold: int = 20,
        payload_size_threshold: int = 5000,
        portscan_window_sec: int = 60,
        portscan_unique_ports: int = 10,
    ) -> None:
        # Rate anomaly settings
        self.rate_window_sec = rate_window_sec
        self.rate_threshold = rate_threshold

        # Payload size settings
        self.payload_size_threshold = payload_size_threshold

        # Port scan settings
        self.portscan_window_sec = portscan_window_sec
        self.portscan_unique_ports = portscan_unique_ports

        # State
        self._rate_times: Dict[str, Deque[float]] = defaultdict(deque)
        self._port_hits: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)  # (timestamp, dst_port)

    def _alert(
        self,
        a_type: str,
        severity: str,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        evidence: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {
            "timestamp": now_iso(),
            "type": a_type,
            "severity": severity,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "evidence": evidence,
            "action": "ALERT",
        }

    def check(self, packet_record: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Check a packet record for anomalies.
        Returns a list of anomaly alerts (possibly empty).
        """
        alerts: List[Dict[str, Any]] = []

        src_ip = packet_record.get("src_ip")
        dst_ip = packet_record.get("dst_ip")
        dst_port = packet_record.get("dst_port")
        payload_len = int(packet_record.get("payload_len") or 0)

        now = time.time()

        # 1) Payload size anomaly (simple and immediate)
        if payload_len > self.payload_size_threshold:
            alerts.append(
                self._alert(
                    a_type="PAYLOAD_SIZE",
                    severity="MEDIUM",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    evidence={
                        "payload_len": payload_len,
                        "threshold": self.payload_size_threshold,
                    },
                )
            )

        # 2) Rate anomaly (per src IP)
        if src_ip:
            dq = self._rate_times[src_ip]
            dq.append(now)

            cutoff = now - self.rate_window_sec
            while dq and dq[0] < cutoff:
                dq.popleft()

            if len(dq) > self.rate_threshold:
                alerts.append(
                    self._alert(
                        a_type="RATE_ANOMALY",
                        severity="HIGH",
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        evidence={
                            "count_in_window": len(dq),
                            "window_sec": self.rate_window_sec,
                            "threshold": self.rate_threshold,
                        },
                    )
                )

        # 3) Port scan detection (unique dst ports in window)
        # Only meaningful if dst_port is present and src_ip exists
        if src_ip and isinstance(dst_port, int):
            hits = self._port_hits[src_ip]
            hits.append((now, dst_port))

            cutoff = now - self.portscan_window_sec
            while hits and hits[0][0] < cutoff:
                hits.popleft()

            unique_ports: Set[int] = {p for (_, p) in hits}

            if len(unique_ports) >= self.portscan_unique_ports:
                alerts.append(
                    self._alert(
                        a_type="PORT_SCAN",
                        severity="HIGH",
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        evidence={
                            "unique_ports_count": len(unique_ports),
                            "unique_ports_sample": sorted(list(unique_ports))[:15],
                            "window_sec": self.portscan_window_sec,
                            "threshold": self.portscan_unique_ports,
                        },
                    )
                )

        return alerts

    @staticmethod
    def format_alert(alert: Dict[str, Any]) -> str:
        """One-line console formatter for anomaly alerts."""
        a_type = alert.get("type")
        sev = alert.get("severity")
        src = alert.get("src_ip")
        evid = alert.get("evidence", {})
        return f"[{sev}] {a_type} src={src} evidence={evid}"