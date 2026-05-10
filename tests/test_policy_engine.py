from zero_trust.policy_engine import ZeroTrustPolicyEngine

engine = ZeroTrustPolicyEngine()

# Helper to print
def show(result):
    print(f"{result['decision']} | {result['src_ip']} ({result['src_segment']}) -> {result['dst_ip']} ({result['dst_segment']}) | {result['reason']}")

print("=== Test 1: web -> app (allowed, trust OK) ===")
r1 = engine.enforce(src_ip="192.168.1.10", dst_ip="10.0.0.5", src_trust_score=90)
show(r1)
assert r1["decision"] == "ALLOW"

print("\n=== Test 2: web -> db (NOT allowed) ===")
r2 = engine.enforce(src_ip="192.168.1.10", dst_ip="172.16.0.9", src_trust_score=90)
show(r2)
assert r2["decision"] == "DENY"

print("\n=== Test 3: unknown src IP (deny) ===")
r3 = engine.enforce(src_ip="8.8.8.8", dst_ip="10.0.0.5", src_trust_score=100)
show(r3)
assert r3["decision"] == "DENY"

print("\n=== Test 4: app -> db allowed but trust too low ===")
r4 = engine.enforce(src_ip="10.0.0.25", dst_ip="172.16.0.9", src_trust_score=50)
show(r4)
assert r4["decision"] == "DENY"

print("\n✅ Day 14 policy engine tests PASSED")