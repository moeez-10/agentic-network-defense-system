from detection.signature_engine import SignatureEngine
from detection.anomaly_engine import AnomalyEngine
from ips.blocker import IPSBlocker
from zero_trust.trust_score import TrustScorer
from zero_trust.policy_engine import ZeroTrustPolicyEngine


def make_packet(src_ip, dst_ip, payload=b"", layer7_type="HTTP", dst_port=80):
    return {
        "timestamp": "TEST",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": "TCP",
        "src_port": 55555,
        "dst_port": dst_port,
        "packet_length": 200,
        "payload": payload,
        "payload_len": len(payload),
        "layer7_type": layer7_type,
    }


def main():
    sig_engine = SignatureEngine("detection/rules.json")
    anom_engine = AnomalyEngine(rate_window_sec=2, rate_threshold=5, payload_size_threshold=100, portscan_window_sec=10, portscan_unique_ports=5)
    blocker = IPSBlocker()
    trust = TrustScorer()
    policy = ZeroTrustPolicyEngine()

    def pipeline(packet_record):
        src_ip = packet_record["src_ip"]
        dst_ip = packet_record["dst_ip"]

        if blocker.is_blocked(src_ip):
            print(f"[IPS] SKIP blocked src_ip={src_ip}")
            return

        sig_alerts = []
        if packet_record.get("layer7_type") == "HTTP":
            sig_alerts = sig_engine.check(packet_record)

        anom_alerts = anom_engine.check(packet_record)

        trust_result = trust.evaluate_packet(src_ip, sig_alerts=sig_alerts, anom_alerts=anom_alerts)
        policy_result = policy.enforce(src_ip, dst_ip, trust_result.score)

        if policy_result["decision"] == "DENY" or trust_result.action == "DENY":
            final_action = "DENY"
        elif trust_result.action == "CHALLENGE":
            final_action = "CHALLENGE"
        else:
            final_action = "ALLOW"

        print(
            f"{final_action:<9} | Trust={trust_result.score:3d} ({trust_result.action:<9}) "
            f"| {src_ip} -> {dst_ip} | Policy={policy_result['decision']} | {policy_result['reason']}"
        )

    print("=== Case 1: web -> app (should ALLOW) ===")
    pipeline(make_packet("192.168.1.10", "10.0.0.5"))

    print("\n=== Case 2: web -> db (should DENY: flow not allowed) ===")
    pipeline(make_packet("192.168.1.10", "172.16.0.9"))

    print("\n=== Case 3: app -> db, but trust degraded by SQLi (should become DENY due to trust) ===")
    # Trigger SQLi to drop trust by 30 (from 100 -> 70), but db requires 80 => DENY
    sqli_payload = b"GET /?q=1' OR 1=1-- HTTP/1.1\r\nHost: test\r\n\r\n"
    pipeline(make_packet("10.0.0.25", "172.16.0.9", payload=sqli_payload, layer7_type="HTTP"))

    print("\n✅ Day 15 Zero Trust integration simulation complete")


if __name__ == "__main__":
    main()