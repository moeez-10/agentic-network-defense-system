"""
Day 17 - Zero Trust end-to-end scenarios

Demonstrates:
1) Clean web -> app = ALLOW
2) Clean web -> db = DENY (flow not allowed)
3) Malicious web IP degrades trust -> DENY
4) Trust recovery after cooldown -> CHALLENGE/ALLOW
"""

from zero_trust.trust_score import TrustScorer
from zero_trust.policy_engine import ZeroTrustPolicyEngine


def print_case(title: str):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def final_decision(trust_action: str, policy_decision: str) -> str:
    if policy_decision == "DENY" or trust_action == "DENY":
        return "DENY"
    if trust_action == "CHALLENGE":
        return "CHALLENGE"
    return "ALLOW"


def show_result(src_ip, dst_ip, trust_result, policy_result):
    final = final_decision(trust_result.action, policy_result["decision"])
    print(
        f"FINAL={final:<9} | Trust={trust_result.score:3d} ({trust_result.action:<9}) "
        f"| Policy={policy_result['decision']:<5} | {src_ip} -> {dst_ip} | {policy_result['reason']}"
    )


def main():
    # Tuned for demo speed:
    # - cooldown small
    # - recovery fast so we can show DENY -> CHALLENGE -> ALLOW in seconds
    scorer = TrustScorer(cooldown_sec=3, recovery_per_sec=20.0)
    policy = ZeroTrustPolicyEngine()

    # 1) Clean web -> app
    print_case("Scenario 1: Clean web_tier -> app_tier (EXPECT ALLOW)")
    src = "192.168.1.10"
    dst = "10.0.0.5"
    trust = scorer.evaluate_packet(src_ip=src, sig_alerts=[], anom_alerts=[])
    pol = policy.enforce(src_ip=src, dst_ip=dst, src_trust_score=trust.score)
    show_result(src, dst, trust, pol)

    # 2) Clean web -> db (flow not allowed)
    print_case("Scenario 2: Clean web_tier -> db_tier (EXPECT DENY: flow not allowed)")
    src = "192.168.1.10"
    dst = "172.16.0.9"
    trust = scorer.evaluate_packet(src_ip=src, sig_alerts=[], anom_alerts=[])
    pol = policy.enforce(src_ip=src, dst_ip=dst, src_trust_score=trust.score)
    show_result(src, dst, trust, pol)

    # 3) Malicious IP degrades trust, then web -> app denied due to trust
    print_case("Scenario 3: Malicious web IP degrades -> web->app becomes DENY")
    attacker = "192.168.1.66"
    target_app = "10.0.0.5"

    for i in range(3):
        r = scorer.apply_signature_alert(attacker)
        print(f"Applied signature alert #{i+1}: score={r.score} action={r.action}")

    trust = scorer.evaluate_packet(src_ip=attacker, sig_alerts=[], anom_alerts=[])
    pol = policy.enforce(src_ip=attacker, dst_ip=target_app, src_trust_score=trust.score)
    show_result(attacker, target_app, trust, pol)

    # 4) Recovery after cooldown -> web->app becomes CHALLENGE/ALLOW
    print_case("Scenario 4: Recovery after cooldown -> web->app improves")
    import time
    time.sleep(4)  # beyond cooldown_sec

    # Tick recovery enough times to cross thresholds
    for i in range(6):
        tr = scorer.tick(attacker)
        print(f"Tick #{i+1}: score={tr.score} action={tr.action}")
        time.sleep(1)

    trust = scorer.evaluate_packet(src_ip=attacker, sig_alerts=[], anom_alerts=[])
    pol = policy.enforce(src_ip=attacker, dst_ip=target_app, src_trust_score=trust.score)
    show_result(attacker, target_app, trust, pol)

    print("\n✅ Day 17 Zero Trust end-to-end scenarios complete")


if __name__ == "__main__":
    main()