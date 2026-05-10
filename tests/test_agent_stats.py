from agent.decision_agent import SecurityAgent
from zero_trust.trust_score import TrustResult
from zero_trust.policy_engine import ZeroTrustPolicyEngine

agent = SecurityAgent()
policy = ZeroTrustPolicyEngine()

def pkt(src, dst):
    return {"src_ip": src, "dst_ip": dst, "layer7_type": "HTTP"}

def run(src, dst, sig_alerts, anom_alerts, trust_score, trust_action):
    trust = TrustResult(ip=src, score=trust_score, action=trust_action)
    pol = policy.enforce(src, dst, trust.score)
    agent.run(pkt(src, dst), sig_alerts, anom_alerts, trust, pol)

# Generate sample decisions
run("192.168.1.10", "8.8.8.8", [], [], 100, "ALLOW")  # allow
run("192.168.1.10", "8.8.8.8", [], [{"type": "PAYLOAD_SIZE"}], 90, "ALLOW")  # medium -> throttle/block depending agent logic
run("192.168.1.10", "8.8.8.8", [], [{"type": "RATE_ANOMALY"}], 90, "ALLOW")  # high -> block
run("10.0.0.99", "8.8.8.8", [{"severity": "HIGH"}], [], 90, "ALLOW")        # high -> block
run("10.0.0.50", "8.8.8.8", [], [], 70, "CHALLENGE")                       # throttle

print("=== AGENT STATS ===")
print(agent.get_stats())

print("\n=== THREAT SUMMARY ===")
ts = agent.get_threat_summary()
for ip, counts in ts["per_ip"].items():
    print(ip, counts)