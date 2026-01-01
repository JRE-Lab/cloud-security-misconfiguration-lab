diff --git a/lab/scan.py b/lab/scan.py
new file mode 100755
index 0000000000000000000000000000000000000000..3db61f33d577a8df51da34dc90b1326419e6dc45
--- /dev/null
+++ b/lab/scan.py
@@ -0,0 +1,190 @@
+#!/usr/bin/env python3
+"""Simple cloud misconfiguration scanner for the lab."""
+
+from __future__ import annotations
+
+import argparse
+import json
+from dataclasses import dataclass
+from pathlib import Path
+from typing import Iterable, List
+
+
+@dataclass
+class Finding:
+    severity: str
+    resource: str
+    issue: str
+    recommendation: str
+
+    def render(self) -> str:
+        return (
+            f"[{self.severity}] {self.resource}: {self.issue}\n"
+            f"    Recommendation: {self.recommendation}"
+        )
+
+
+def load_config(path: Path) -> dict:
+    try:
+        return json.loads(path.read_text())
+    except json.JSONDecodeError as exc:
+        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc
+
+
+def scan_buckets(buckets: Iterable[dict]) -> List[Finding]:
+    findings: List[Finding] = []
+    for bucket in buckets:
+        name = bucket.get("name", "unknown-bucket")
+        resource = f"bucket/{name}"
+        if bucket.get("public") is True:
+            findings.append(
+                Finding(
+                    "HIGH",
+                    resource,
+                    "Bucket is publicly accessible",
+                    "Disable public access and enforce least privilege.",
+                )
+            )
+        if bucket.get("encryption") is False:
+            findings.append(
+                Finding(
+                    "MEDIUM",
+                    resource,
+                    "Bucket encryption at rest is disabled",
+                    "Enable server-side encryption for all objects.",
+                )
+            )
+    return findings
+
+
+def scan_security_groups(groups: Iterable[dict]) -> List[Finding]:
+    findings: List[Finding] = []
+    allowed_public_ports = {80, 443}
+    for group in groups:
+        name = group.get("name", "unknown-sg")
+        for rule in group.get("ingress", []):
+            cidr = rule.get("cidr", "")
+            port = rule.get("port")
+            protocol = rule.get("protocol", "")
+            if cidr == "0.0.0.0/0":
+                if port in (22, 3389):
+                    findings.append(
+                        Finding(
+                            "HIGH",
+                            f"security-group/{name}",
+                            f"{protocol.upper()} {port} open to the internet",
+                            "Restrict administrative ports to trusted IP ranges.",
+                        )
+                    )
+                elif port in ("all", 0, None):
+                    findings.append(
+                        Finding(
+                            "CRITICAL",
+                            f"security-group/{name}",
+                            "All ports open to the internet",
+                            "Limit ingress to required ports and trusted CIDRs.",
+                        )
+                    )
+                elif port not in allowed_public_ports:
+                    findings.append(
+                        Finding(
+                            "MEDIUM",
+                            f"security-group/{name}",
+                            f"{protocol.upper()} {port} open to the internet",
+                            "Review whether this exposure is required.",
+                        )
+                    )
+    return findings
+
+
+def scan_iam_policies(policies: Iterable[dict]) -> List[Finding]:
+    findings: List[Finding] = []
+    for policy in policies:
+        name = policy.get("name", "unknown-policy")
+        actions = policy.get("actions", [])
+        resources = policy.get("resources", [])
+        if "*" in actions and "*" in resources:
+            findings.append(
+                Finding(
+                    "CRITICAL",
+                    f"iam-policy/{name}",
+                    "Policy grants full administrative access",
+                    "Scope permissions to specific actions and resources.",
+                )
+            )
+    return findings
+
+
+def scan_logging(logging: dict) -> List[Finding]:
+    findings: List[Finding] = []
+    if logging.get("cloudtrail") is False:
+        findings.append(
+            Finding(
+                "HIGH",
+                "logging/cloudtrail",
+                "Audit logging is disabled",
+                "Enable CloudTrail (or equivalent) for governance and detection.",
+            )
+        )
+    return findings
+
+
+def scan_databases(databases: Iterable[dict]) -> List[Finding]:
+    findings: List[Finding] = []
+    for db in databases:
+        name = db.get("name", "unknown-db")
+        resource = f"database/{name}"
+        if db.get("public_access") is True:
+            findings.append(
+                Finding(
+                    "CRITICAL",
+                    resource,
+                    "Database has public network access enabled",
+                    "Move database to private subnets and restrict inbound access.",
+                )
+            )
+        if db.get("encrypted") is False:
+            findings.append(
+                Finding(
+                    "MEDIUM",
+                    resource,
+                    "Database encryption at rest is disabled",
+                    "Enable encryption using a managed key service.",
+                )
+            )
+    return findings
+
+
+def run_scan(config: dict) -> List[Finding]:
+    findings: List[Finding] = []
+    findings.extend(scan_buckets(config.get("buckets", [])))
+    findings.extend(scan_security_groups(config.get("security_groups", [])))
+    findings.extend(scan_iam_policies(config.get("iam_policies", [])))
+    findings.extend(scan_logging(config.get("logging", {})))
+    findings.extend(scan_databases(config.get("databases", [])))
+    return findings
+
+
+def main() -> None:
+    parser = argparse.ArgumentParser(
+        description="Scan a simulated cloud configuration for misconfigurations."
+    )
+    parser.add_argument("config", type=Path, help="Path to JSON configuration")
+    args = parser.parse_args()
+
+    config = load_config(args.config)
+    findings = run_scan(config)
+
+    if not findings:
+        print("No findings detected. ✅")
+        return
+
+    print(f"Findings ({len(findings)}):")
+    for finding in findings:
+        print(finding.render())
+
+    raise SystemExit(1)
+
+
+if __name__ == "__main__":
+    main()
