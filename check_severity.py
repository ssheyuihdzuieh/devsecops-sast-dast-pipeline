import json
import sys

with open("semgrep.sarif") as f:
    data = json.load(f)

results = data["runs"][0]["results"]
rules = {r["id"]: r for r in data["runs"][0]["tool"]["driver"]["rules"]}

error_count = 0
warning_count = 0

for finding in results:
    rule_id = finding["ruleId"]
    level = rules.get(rule_id, {}).get("defaultConfiguration", {}).get("level", "warning")
    if level == "error":
        error_count += 1
    else:
        warning_count += 1

print(f"Semgrep findings — Critical (error): {error_count}, Other (warning/note): {warning_count}")

if error_count > 0:
    print(f"❌ Pipeline failed: {error_count} critical finding(s) detected.")
    sys.exit(1)
else:
    print("✅ No critical findings. Pipeline passes.")
    sys.exit(0)
