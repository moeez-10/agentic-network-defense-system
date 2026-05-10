from agent.decision_agent import SecurityAgent
from zero_trust.trust_score import TrustResult

agent = SecurityAgent()

def pkt(src, dst):
    return {"src_ip": src, "dst_ip": dst, "layer7_type": "HTTP"}

print("=== Scenario 1: Policy DENY => CRITICAL/BLOCK ===")
d1 = agent.run(
    packet_record=pkt("192.168.1.10", "172.16.0.9"),
    sig_alerts=[],
    anom_alerts=[],
    trust_result=TrustResult(ip="192.168.1.10", score=100, action="ALLOW"),
    policy_result={"decision": "DENY", "reason": "Flow not allowed"}
)
print(d1)

print("\n=== Scenario 2: High severity signature => HIGH/BLOCK ===")
d2 = agent.run(
    packet_record=pkt("10.0.0.99", "10.0.0.10"),
    sig_alerts=[{"severity": "HIGH"}],
    anom_alerts=[],
    trust_result=TrustResult(ip="10.0.0.99", score=90, action="ALLOW"),
    policy_result={"decision": "ALLOW", "reason": "Policy OK"}
)
print(d2)

print("\n=== Scenario 3: Rate anomaly => HIGH/BLOCK ===")
d3 = agent.run(
    packet_record=pkt("10.0.0.77", "10.0.0.20"),
    sig_alerts=[],
    anom_alerts=[{"type": "RATE_ANOMALY", "severity": "HIGH"}],
    trust_result=TrustResult(ip="10.0.0.77", score=85, action="ALLOW"),
    policy_result={"decision": "ALLOW", "reason": "Policy OK"}
)
print(d3)

print("\n=== Scenario 4: Trust CHALLENGE => MEDIUM/THROTTLE ===")
d4 = agent.run(
    packet_record=pkt("10.0.0.55", "10.0.0.20"),
    sig_alerts=[],
    anom_alerts=[],
    trust_result=TrustResult(ip="10.0.0.55", score=70, action="CHALLENGE"),
    policy_result={"decision": "ALLOW", "reason": "Policy OK"}
)
print(d4)

print("\nRecent decisions:")
for d in agent.get_recent_decisions(10):
    print(f"- {d['timestamp']} src={d['src_ip']} threat={d['threat_level']} action={d['final_action']} reason={d['reason']}")