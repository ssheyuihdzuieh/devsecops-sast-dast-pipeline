import json
from datetime import datetime, timezone


def esc(text):
    """Escape HTML characters so Markdown shows them as plain text."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# --- Lire les résultats Semgrep ---
with open("semgrep.sarif") as f:
    semgrep_data = json.load(f)

semgrep_results = semgrep_data["runs"][0]["results"]
rules = {r["id"]: r for r in semgrep_data["runs"][0]["tool"]["driver"]["rules"]}

semgrep_lines = []
for finding in semgrep_results:
    rule_id = finding["ruleId"]
    level = rules.get(rule_id, {}).get("defaultConfiguration", {}).get("level", "warning")
    location = finding["locations"][0]["physicalLocation"]
    file_path = location["artifactLocation"]["uri"]
    line = location["region"]["startLine"]
    message = esc(finding["message"]["text"])
    semgrep_lines.append(f"- **[{level.upper()}]** `{file_path}:{line}` — {message}")

# --- Lire les résultats ZAP ---
zap_lines = []
zap_summary = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
try:
    with open("report_json.json") as f:
        zap_data = json.load(f)
    for site in zap_data.get("site", []):
        for alert in site.get("alerts", []):
            risk = alert.get("riskdesc", "").split(" ")[0]
            if risk in zap_summary:
                zap_summary[risk] += 1
            name = esc(alert.get("name", "Unknown"))
            count = alert.get("count", "?")
            zap_lines.append(f"- **[{risk}]** {name} ({count} instance(s))")
except FileNotFoundError:
    zap_lines.append("_ZAP report not found._")

# --- Générer le rapport combiné ---
now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
semgrep_block = "\n".join(semgrep_lines) if semgrep_lines else "No findings."
zap_block = "\n".join(zap_lines) if zap_lines else "No alerts."

report = f"""# DevSecOps Security Report

Generated: {now}

## Summary

- **Semgrep (SAST):** {len(semgrep_results)} finding(s)
- **OWASP ZAP (DAST):** {sum(zap_summary.values())} alert(s) — High: {zap_summary['High']}, Medium: {zap_summary['Medium']}, Low: {zap_summary['Low']}, Informational: {zap_summary['Informational']}

## Semgrep Findings (SAST)

{semgrep_block}

## ZAP Alerts (DAST)

{zap_block}
"""

with open("security-report.md", "w") as f:
    f.write(report)

print("Combined report generated: security-report.md")
