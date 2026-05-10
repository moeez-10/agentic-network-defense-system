import time
from zero_trust.trust_score import TrustScorer

# Use small cooldown for quick testing (instead of 5 minutes)
scorer = TrustScorer(cooldown_sec=3, recovery_per_sec=2.0)  # +2 trust per second

ip = "10.0.0.99"

print("Initial:", scorer.get_score(ip), scorer.score_to_action(scorer.get_score(ip)))

# Trigger repeated alerts to show accelerated decay
print("\n=== Repeated alerts (accelerated decay) ===")
for i in range(3):
    r = scorer.apply_signature_alert(ip)
    print(f"After signature #{i+1}: {r}")

# Wait for cooldown to pass
print("\nWaiting for cooldown...")
time.sleep(4)

# Call tick a few times to recover
print("\n=== Recovery ===")
for i in range(3):
    r = scorer.tick(ip)
    print(f"Tick #{i+1}: {r}")
    time.sleep(1)

print("\nFinal score:", scorer.get_score(ip))