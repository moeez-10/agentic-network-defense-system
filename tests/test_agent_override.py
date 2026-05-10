from agent.decision_agent import SecurityAgent
from zero_trust.trust_score import TrustResult
from zero_trust.policy_engine import ZeroTrustPolicyEngine

agent = SecurityAgent()
policy = ZeroTrustPolicyEngine()

def pkt(src, dst):
    return {"src_ip": src, "dst_ip": dst, "layer7_type": "HTTP"}

def run_case(title, src, dst, sig_alerts, anom_alerts, trust_score, trust_action):
    print("\n" + "="*70)
    print(title)
    print("="*70)

    trust = TrustResult(ip=src, score=trust_score, action=trust_action)
    policy_result = policy.enforce(src, dst, trust.score)

    decision = agent.run(
        packet_record=pkt(src, dst),
        sig_alerts=sig_alerts,
        anom_alerts=anom_alerts,
        trust_result=trust,
        policy_result=policy_result,
    )

    print("Policy:", policy_result)
    print("Agent decision:", decision)

# Case 1: Policy ALLOW, but trust CHALLENGE => THROTTLE
run_case(
    "Case 1: Policy ALLOW but trust is CHALLENGE => Agent THROTTLE",
    src="192.168.1.10",
    dst="8.8.8.8",
    sig_alerts=[],
    anom_alerts=[],
    trust_score=70,
    trust_action="CHALLENGE",
)

# Case 2: Policy ALLOW but rate anomaly => Agent BLOCK
run_case(
    "Case 2: Policy ALLOW but RATE_ANOMALY => Agent BLOCK",
    src="192.168.1.10",
    dst="8.8.8.8",
    sig_alerts=[],
    anom_alerts=[{"type": "RATE_ANOMALY", "severity": "HIGH"}],
    trust_score=90,
    trust_action="ALLOW",
)

# Case 3: Learned behavior: IP was blocked before, now medium anomaly escalates to BLOCK
# First, create history (block once)
agent.run(
    packet_record=pkt("10.0.0.99", "8.8.8.8"),
    sig_alerts=[{"severity": "HIGH"}],
    anom_alerts=[],
    trust_result=TrustResult(ip="10.0.0.99", score=90, action="ALLOW"),
    policy_result=policy.enforce("10.0.0.99", "8.8.8.8", 90),
)

run_case(
    "Case 3: Policy ALLOW + medium anomaly, but previously blocked => escalate to BLOCK",
    src="10.0.0.99",
    dst="8.8.8.8",
    sig_alerts=[],
    anom_alerts=[{"type": "PAYLOAD_SIZE", "severity": "MEDIUM"}],
    trust_score=90,
    trust_action="ALLOW",
)