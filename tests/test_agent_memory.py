from agent.decision_agent import SecurityAgent
from zero_trust.trust_score import TrustResult

agent = SecurityAgent()

def pkt(src, dst):
    return {"src_ip": src, "dst_ip": dst, "layer7_type": "HTTP"}

print("=== Step 1: Block an IP once ===")
d1 = agent.run(
    packet_record=pkt("10.0.0.99", "10.0.0.10"),
    sig_alerts=[{"severity": "HIGH"}],   # causes HIGH -> BLOCK
    anom_alerts=[],
    trust_result=TrustResult(ip="10.0.0.99", score=90, action="ALLOW"),
    policy_result={"decision": "ALLOW", "reason": "Policy OK"},
)
print(d1["src_ip"], d1["threat_level"], d1["final_action"], d1["reason"])

print("\n=== Step 2: Same IP again with only MEDIUM indicators, should escalate due to history ===")
d2 = agent.run(
    packet_record=pkt("10.0.0.99", "10.0.0.10"),
    sig_alerts=[],
    anom_alerts=[{"type": "PAYLOAD_SIZE", "severity": "MEDIUM"}],  # normally MEDIUM -> THROTTLE
    trust_result=TrustResult(ip="10.0.0.99", score=85, action="ALLOW"),
    policy_result={"decision": "ALLOW", "reason": "Policy OK"},
)
print(d2["src_ip"], d2["threat_level"], d2["final_action"], d2["reason"])

print("\n=== Step 3: Trusted IP simulation (seen=100, clean) ===")
# Simulate 100 clean observations
for _ in range(100):
    agent.run(
        packet_record=pkt("10.0.0.50", "10.0.0.20"),
        sig_alerts=[],
        anom_alerts=[],
        trust_result=TrustResult(ip="10.0.0.50", score=100, action="ALLOW"),
        policy_result={"decision": "ALLOW", "reason": "Policy OK"},
    )

mem = agent.get_memory().get("10.0.0.50")
print("Memory for 10.0.0.50:", mem)

d3 = agent.run(
    packet_record=pkt("10.0.0.50", "10.0.0.20"),
    sig_alerts=[],
    anom_alerts=[],
    trust_result=TrustResult(ip="10.0.0.50", score=100, action="ALLOW"),
    policy_result={"decision": "ALLOW", "reason": "Policy OK"},
)
print(d3["src_ip"], d3["threat_level"], d3["final_action"], d3["reason"])