"""
Zero Trust Policy Engine

Practical live-mode behavior:
- If src or dst is outside defined internal micro-segments (unknown segment),
  ALLOW with monitoring (to avoid blocking normal internet traffic).
- If both src and dst are internal segments:
  - enforce allowed_flows
  - enforce destination min_trust threshold

This keeps micro-segmentation meaningful without breaking real-world connectivity.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Any


@dataclass
class Segment:
    name: str
    subnet: str
    min_trust: int


class ZeroTrustPolicyEngine:
    def __init__(self) -> None:
        # Micro-segments (lab-friendly defaults)
        self.segments: Dict[str, Segment] = {
            "web_tier": Segment("web_tier", "192.168.1.0/24", min_trust=60),
            "app_tier": Segment("app_tier", "10.0.0.0/24", min_trust=70),
            "db_tier": Segment("db_tier", "172.16.0.0/24", min_trust=80),
        }

        # Allowed flows between segments (from -> to)
        self.allowed_flows: List[Tuple[str, str]] = [
            ("web_tier", "app_tier"),
            ("app_tier", "db_tier"),
        ]

        self._networks = {
            name: ipaddress.ip_network(seg.subnet, strict=False)
            for name, seg in self.segments.items()
        }

    def ip_to_segment(self, ip: str) -> Optional[str]:
        """Return segment name for an IP, or None if unknown/external."""
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return None

        for name, net in self._networks.items():
            if ip_obj in net:
                return name
        return None

    def is_flow_allowed(self, src_segment: str, dst_segment: str) -> bool:
        """Same segment is allowed; cross-segment only if explicitly allowed."""
        if src_segment == dst_segment:
            return True
        return (src_segment, dst_segment) in self.allowed_flows

    def enforce(self, src_ip: str, dst_ip: str, src_trust_score: int) -> Dict[str, Any]:
        """
        Enforce Zero Trust policy decision for a single flow.
        Returns ALLOW/DENY with reason.
        """
        src_seg = self.ip_to_segment(src_ip)
        dst_seg = self.ip_to_segment(dst_ip)

        # Live-mode: if either side is external/unknown, allow with monitoring.
        # This prevents blocking normal internet traffic on a personal machine.
        if src_seg is None or dst_seg is None:
            return {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_segment": src_seg,
                "dst_segment": dst_seg,
                "decision": "ALLOW",
                "reason": "External/unknown endpoint - allowed with monitoring",
            }

        # Both endpoints are internal segments => enforce micro-segmentation rules
        if not self.is_flow_allowed(src_seg, dst_seg):
            return {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_segment": src_seg,
                "dst_segment": dst_seg,
                "decision": "DENY",
                "reason": f"Flow not allowed: {src_seg} -> {dst_seg}",
            }

        # Trust threshold for destination segment
        dst_min = self.segments[dst_seg].min_trust
        if src_trust_score < dst_min:
            return {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_segment": src_seg,
                "dst_segment": dst_seg,
                "decision": "DENY",
                "reason": f"Insufficient trust: score={src_trust_score} < dst_min_trust={dst_min} ({dst_seg})",
            }

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_segment": src_seg,
            "dst_segment": dst_seg,
            "decision": "ALLOW",
            "reason": "Policy OK",
        }