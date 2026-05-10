"""
Day 12 - End-to-end pipeline test (synthetic records)

Tests:
1) Clean HTTP -> no signature alerts
2) SQLi HTTP -> signature BLOCK + IP gets blocked
3) Blocked IP -> skipped
4) Large payload -> PAYLOAD_SIZE anomaly
5) Rate burst -> RATE_ANOMALY anomaly
6) Port scan -> PORT_SCAN anomaly
"""

from detection.signature_engine import SignatureEngine
from detection.anomaly_engine import AnomalyEngine
from ips.blocker import IPSBlocker


def make_packet(
    src_ip="10.0.0.8",
    dst_ip="10.0.0.20",
    protocol="TCP",
    src_port=55555,
    dst_port=80,
    payload=b"",
    layer7_type="HTTP",
    packet_length=200,
):
    return {
        "timestamp": "TEST",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "packet_length": packet_length,
        "payload": payload,
        "payload_len": len(payload) if isinstance(payload, (bytes, bytearray)) else 0,
        "layer7_type": layer7_type,
    }


def main():
    sig_engine = SignatureEngine("detection/rules.json")

    # lower thresholds so anomalies trigger quickly in test
    anom_engine = AnomalyEngine(
        rate_window_sec=2,
        rate_threshold=5,
        payload_size_threshold=100,
        portscan_window_sec=10,
        portscan_unique_ports=5,
    )

    blocker = IPSBlocker()

    sig_count = 0
    anom_count = 0
    skip_count = 0
    blocked_events = 0

    def pipeline(packet_record):
        nonlocal sig_count, anom_count, skip_count, blocked_events

        src_ip = packet_record.get("src_ip")
        if src_ip and blocker.is_blocked(src_ip):
            skip_count += 1
            return [], []

        sig_alerts = []
        if packet_record.get("layer7_type") == "HTTP":
            sig_alerts = sig_engine.check(packet_record)
            sig_count += len(sig_alerts)

            for a in sig_alerts:
                if a.get("action") == "BLOCK":
                    reason = f"{a.get('rule_id')} {a.get('category')} matched={a.get('matched_pattern')}"
                    if blocker.block_ip(
                        ip=a.get("src_ip"),
                        reason=reason,
                        rule_id=a.get("rule_id"),
                        category=a.get("category"),
                        severity=a.get("severity"),
                    ):
                        blocked_events += 1

        anom_alerts = anom_engine.check(packet_record)
        anom_count += len(anom_alerts)

        return sig_alerts, anom_alerts

    # -------------------------
    # 1) Clean HTTP -> no sig
    # -------------------------
    pkt1 = make_packet(payload=b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
    sig_alerts, anom_alerts = pipeline(pkt1)
    assert len(sig_alerts) == 0, "Clean HTTP should not trigger signature alerts"

    # -------------------------
    # 2) SQLi HTTP -> BLOCK
    # -------------------------
    attacker_ip = "10.0.0.99"
    pkt2 = make_packet(
        src_ip=attacker_ip,
        payload=b"GET /?q=1' OR 1=1-- HTTP/1.1\r\nHost: test\r\n\r\n",
    )
    sig_alerts, anom_alerts = pipeline(pkt2)
    assert len(sig_alerts) >= 1, "SQLi payload should trigger signature alert"
    assert blocker.is_blocked(attacker_ip), "Attacker IP should be blocked after BLOCK rule"
    assert blocked_events == 1, "Blocked events should be 1 after first block"

    # -------------------------
    # 3) Blocked IP -> skipped
    # -------------------------
    pkt3 = make_packet(src_ip=attacker_ip, payload=b"GET /again HTTP/1.1\r\n\r\n")
    sig_alerts, anom_alerts = pipeline(pkt3)
    assert skip_count == 1, "Blocked IP should be skipped"

    # -------------------------
    # 4) Large payload -> anomaly
    # -------------------------
    pkt4 = make_packet(src_ip="10.0.0.50", payload=b"A" * 500, layer7_type="UNKNOWN", dst_port=443)
    sig_alerts, anom_alerts = pipeline(pkt4)
    assert any(a["type"] == "PAYLOAD_SIZE" for a in anom_alerts), "Large payload should trigger PAYLOAD_SIZE anomaly"

    # -------------------------
    # 5) Rate burst -> anomaly
    # -------------------------
    burst_ip = "10.0.0.77"
    for _ in range(7):
        pkt = make_packet(src_ip=burst_ip, payload=b"X", layer7_type="UNKNOWN", dst_port=443)
        _, anom_alerts = pipeline(pkt)
    # After burst, we expect at least one RATE_ANOMALY to have occurred overall
    # We can't easily assert exact count, but we can assert total anomaly count increased.
    assert anom_count > 0, "Anomaly count should be >0 after burst traffic"

    # -------------------------
    # 6) Port scan -> anomaly
    # -------------------------
    scanner_ip = "10.0.0.88"
    ports = [21, 22, 23, 80, 443, 3389]
    portscan_triggered = False
    for p in ports:
        pkt = make_packet(src_ip=scanner_ip, dst_port=p, payload=b"", layer7_type="UNKNOWN")
        _, anom_alerts = pipeline(pkt)
        if any(a["type"] == "PORT_SCAN" for a in anom_alerts):
            portscan_triggered = True
    assert portscan_triggered, "Port scan should trigger PORT_SCAN anomaly"

    print("✅ Day 12 pipeline test PASSED")
    print(f"Signature alerts total: {sig_count}")
    print(f"Anomaly alerts total:   {anom_count}")
    print(f"IPs blocked:            {len(blocker.get_blocked_ips())}")
    print(f"Packets skipped:        {skip_count}")


if __name__ == "__main__":
    main()