import json

RULES_PATH = "detection/rules.json"

with open(RULES_PATH, "r", encoding="utf-8") as f:
    data = json.load(f)

rules = data.get("rules", [])
print(f"Loaded {len(rules)} rules from {RULES_PATH}")

# Print a quick preview
for r in rules:
    print(f"- {r['id']} | {r['category']} | severity={r['severity']} | action={r['action']} | patterns={len(r['patterns'])}")