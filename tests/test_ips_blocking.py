from detection.signature_engine import SignatureEngine
from detection.anomaly_engine import AnomalyEngine
from ips.blocker import IPSBlocker

def print_sig_alert(a):
    print(f"[SIG] {a['severity']} {a['rule_id']} {a['category']} action={a['action']} matched={a['matched_pattern']}")

def print_anom_alert(a):
    print(f"[ANOM] {a['severity']} {a['type']} evidence={a['evidence']}")

def main():
    sig_engine = SignatureEngine("detection/rules.json")
    anom_engine = AnomalyEngine(rate_window_sec=5, rate_threshold=20)
    blocker = IPSBlocker()

    # Simulated HTTP packet containing SQLi (BLOCK rule)
    pkt = {
        "timestamp": "TEST",
        "src_ip": "10.0.0.99",
        "dst_ip": "10.0.0.10",
        "protocol": "TCP",
        "src_port": 55555,
        "dst_port": 80,
        "packet_length": 200,
        "payload": b"GET /?q=1' OR 1=1-- HTTP/1.1\r\nHost: test\r\n\r\n",
        "payload_len": 60,
        "layer7_type": "HTTP",
    }

    # Pipeline simulation
    def pipeline(packet_record):
        src_ip = packet_record.get("src_ip")

        if src_ip and blocker.is_blocked(src_ip):
            print(f"[IPS] SKIP blocked src_ip={src_ip}")
            return

        # signature checks (HTTP only)
        if packet_record.get("layer7_type") == "HTTP":
            for a in sig_engine.check(packet_record):
                print_sig_alert(a)
                if a.get("action") == "BLOCK":
                    reason = f"{a.get('rule_id')} {a.get('category')} matched={a.get('matched_pattern')}"
                    newly = blocker.block_ip(
                        ip=a.get("src_ip"),
                        reason=reason,
                        rule_id=a.get("rule_id"),
                        category=a.get("category"),
                        severity=a.get("severity"),
                    )
                    if newly:
                        print(f"[IPS] BLOCKED ip={a.get('src_ip')} reason={reason}")

        # anomaly checks (always)
        for a in anom_engine.check(packet_record):
            print_anom_alert(a)

    print("=== First packet (should trigger BLOCK) ===")
    pipeline(pkt)

    print("\n=== Second packet from same src_ip (should be skipped) ===")
    pipeline(pkt)

    print("\n=== Block list ===")
    for entry in blocker.get_blocked_ips():
        print(entry)

if __name__ == "__main__":
    main()