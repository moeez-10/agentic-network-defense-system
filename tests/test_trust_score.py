from zero_trust.trust_score import TrustScorer

scorer = TrustScorer()

ip = "10.0.0.99"

print("Initial:", scorer.get_score(ip), scorer.score_to_action(scorer.get_score(ip)))

# Simulate signature alert
r1 = scorer.apply_signature_alert(ip)
print("After signature:", r1)

# Simulate rate anomaly
r2 = scorer.apply_anomaly_alert(ip, "RATE_ANOMALY")
print("After rate anomaly:", r2)

# Simulate port scan anomaly
r3 = scorer.apply_anomaly_alert(ip, "PORT_SCAN")
print("After port scan:", r3)

# Simulate multiple packets evaluation
sig_alerts = [{"rule_id": "SIG-001"}]
anom_alerts = [{"type": "PAYLOAD_SIZE"}]
r4 = scorer.evaluate_packet(ip, sig_alerts=sig_alerts, anom_alerts=anom_alerts)
print("After combined packet:", r4)

print("All scores:", scorer.get_all_scores())