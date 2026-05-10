"""
Zero Trust - Trust Scoring Module (Day 13 + Day 16)

Day 16 additions:
- Trust recovery over time (if no alerts for cooldown period)
- Accelerated decay for repeat offenders (offense_count-based extra penalty)

Scoring rules (default):
- Signature alert: -30
- Rate anomaly:   -20
- Other anomaly:  -15

Recovery rules (default):
- If idle (no alerts) for cooldown_sec, recover +recovery_per_sec * elapsed_sec
- Max trust capped at 100
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, Optional, List


@dataclass
class TrustResult:
    ip: str
    score: int
    action: str  # ALLOW / CHALLENGE / DENY


class TrustScorer:
    def __init__(
        self,
        initial_trust: int = 100,
        min_trust: int = 0,
        max_trust: int = 100,
        sig_penalty: int = 30,
        rate_penalty: int = 20,
        anomaly_penalty: int = 15,
        # Day 16 settings
        cooldown_sec: int = 300,           # 5 minutes default
        recovery_per_sec: float = 5 / 60,  # +5 per minute
        repeat_extra_per_offense: int = 2, # extra penalty per offense
        repeat_extra_cap: int = 20,        # max extra penalty
    ) -> None:
        self.initial_trust = initial_trust
        self.min_trust = min_trust
        self.max_trust = max_trust

        self.sig_penalty = sig_penalty
        self.rate_penalty = rate_penalty
        self.anomaly_penalty = anomaly_penalty

        self.cooldown_sec = cooldown_sec
        self.recovery_per_sec = recovery_per_sec
        self.repeat_extra_per_offense = repeat_extra_per_offense
        self.repeat_extra_cap = repeat_extra_cap

        # Per-IP state
        self._trust: Dict[str, int] = {}
        self._last_alert_ts: Dict[str, float] = {}   # epoch seconds
        self._offenses: Dict[str, int] = {}
        self._last_tick_ts: Dict[str, float] = {}    # for recovery tick bookkeeping

    def get_score(self, ip: str) -> int:
        if ip not in self._trust:
            self._trust[ip] = self.initial_trust
            now = time.time()
            self._last_alert_ts[ip] = 0.0
            self._offenses[ip] = 0
            self._last_tick_ts[ip] = now
        return self._trust[ip]

    def _set_score(self, ip: str, score: int) -> int:
        score = max(self.min_trust, min(self.max_trust, int(score)))
        self._trust[ip] = score
        return score

    def score_to_action(self, score: int) -> str:
        if score >= 80:
            return "ALLOW"
        if score >= 50:
            return "CHALLENGE"
        return "DENY"

    def _repeat_extra_penalty(self, ip: str) -> int:
        offenses = self._offenses.get(ip, 0)
        extra = offenses * self.repeat_extra_per_offense
        return min(self.repeat_extra_cap, extra)

    def _mark_alert(self, ip: str, now: Optional[float] = None) -> None:
        now = time.time() if now is None else now
        self._last_alert_ts[ip] = now
        self._offenses[ip] = self._offenses.get(ip, 0) + 1

    def apply_signature_alert(self, ip: str, now: Optional[float] = None) -> TrustResult:
        self.get_score(ip)
        self._mark_alert(ip, now=now)

        current = self._trust[ip]
        extra = self._repeat_extra_penalty(ip)
        new = self._set_score(ip, current - self.sig_penalty - extra)
        return TrustResult(ip=ip, score=new, action=self.score_to_action(new))

    def apply_anomaly_alert(self, ip: str, anomaly_type: str, now: Optional[float] = None) -> TrustResult:
        self.get_score(ip)
        self._mark_alert(ip, now=now)

        current = self._trust[ip]
        extra = self._repeat_extra_penalty(ip)

        if anomaly_type == "RATE_ANOMALY":
            new = self._set_score(ip, current - self.rate_penalty - extra)
        else:
            new = self._set_score(ip, current - self.anomaly_penalty - extra)

        return TrustResult(ip=ip, score=new, action=self.score_to_action(new))

    def evaluate_packet(
        self,
        src_ip: str,
        sig_alerts: Optional[list] = None,
        anom_alerts: Optional[list] = None,
        now: Optional[float] = None,
    ) -> TrustResult:
        """
        Apply at most one signature penalty + one anomaly penalty per packet (simple model).
        """
        self.get_score(src_ip)
        now = time.time() if now is None else now

        sig_alerts = sig_alerts or []
        anom_alerts = anom_alerts or []

        score = self._trust[src_ip]

        # If any signature alerts exist -> apply signature penalty once
        if sig_alerts:
            self._mark_alert(src_ip, now=now)
            extra = self._repeat_extra_penalty(src_ip)
            score = self._set_score(src_ip, score - self.sig_penalty - extra)

        # If anomalies exist -> apply one anomaly penalty (rate has priority)
        anomaly_types = [a.get("type") for a in anom_alerts if isinstance(a, dict)]
        if anomaly_types:
            self._mark_alert(src_ip, now=now)
            extra = self._repeat_extra_penalty(src_ip)

            if "RATE_ANOMALY" in anomaly_types:
                score = self._set_score(src_ip, score - self.rate_penalty - extra)
            else:
                score = self._set_score(src_ip, score - self.anomaly_penalty - extra)

        return TrustResult(ip=src_ip, score=score, action=self.score_to_action(score))

    def tick(self, ip: str, now: Optional[float] = None) -> TrustResult:
        """
        Time-based trust recovery. Call periodically (or in simulation tests).

        Recovery happens only if:
        - elapsed since last alert >= cooldown_sec
        """
        self.get_score(ip)
        now = time.time() if now is None else now

        last_alert = self._last_alert_ts.get(ip, 0.0)
        last_tick = self._last_tick_ts.get(ip, now)

        # Update tick time regardless
        self._last_tick_ts[ip] = now

        # If no alert yet, treat it as idle
        idle_time = now - last_alert if last_alert > 0 else now

        if idle_time < self.cooldown_sec:
            # no recovery yet
            score = self._trust[ip]
            return TrustResult(ip=ip, score=score, action=self.score_to_action(score))

        # Recover based on elapsed time since last tick
        elapsed = max(0.0, now - last_tick)
        recovered = int(elapsed * self.recovery_per_sec)
        if recovered > 0:
            score = self._set_score(ip, self._trust[ip] + recovered)
        else:
            score = self._trust[ip]

        # Optional: offenses could slowly reduce after long idle (keep simple for now)
        return TrustResult(ip=ip, score=score, action=self.score_to_action(score))

    def get_all_scores(self) -> Dict[str, int]:
        return dict(self._trust)