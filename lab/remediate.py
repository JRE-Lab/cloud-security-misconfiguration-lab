diff --git a/lab/remediate.py b/lab/remediate.py
new file mode 100755
index 0000000000000000000000000000000000000000..aea864c3697c3497ce34396598ae87ec73ddc339
--- /dev/null
+++ b/lab/remediate.py
@@ -0,0 +1,65 @@
+#!/usr/bin/env python3
+"""Remediation helper for the cloud misconfiguration lab."""
+
+from __future__ import annotations
+
+import argparse
+import json
+from copy import deepcopy
+from pathlib import Path
+from typing import Dict
+
+
+TRUSTED_ADMIN_CIDR = "10.0.0.0/16"
+
+
+def load_config(path: Path) -> Dict:
+    try:
+        return json.loads(path.read_text())
+    except json.JSONDecodeError as exc:
+        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc
+
+
+def remediate_config(config: Dict) -> Dict:
+    hardened = deepcopy(config)
+
+    for bucket in hardened.get("buckets", []):
+        bucket["public"] = False
+        bucket["encryption"] = True
+
+    for group in hardened.get("security_groups", []):
+        for rule in group.get("ingress", []):
+            if rule.get("cidr") == "0.0.0.0/0" and rule.get("port") in (22, 3389):
+                rule["cidr"] = TRUSTED_ADMIN_CIDR
+
+    for policy in hardened.get("iam_policies", []):
+        if "*" in policy.get("actions", []) and "*" in policy.get("resources", []):
+            policy["actions"] = ["ec2:Describe*", "s3:GetObject", "s3:ListBucket"]
+            policy["resources"] = ["*"]
+
+    logging_config = hardened.setdefault("logging", {})
+    logging_config["cloudtrail"] = True
+
+    for db in hardened.get("databases", []):
+        db["public_access"] = False
+        db["encrypted"] = True
+
+    return hardened
+
+
+def main() -> None:
+    parser = argparse.ArgumentParser(
+        description="Remediate a simulated cloud configuration."
+    )
+    parser.add_argument("input", type=Path, help="Path to the insecure JSON configuration")
+    parser.add_argument("output", type=Path, help="Path to write the secure configuration")
+    args = parser.parse_args()
+
+    config = load_config(args.input)
+    hardened = remediate_config(config)
+    args.output.write_text(json.dumps(hardened, indent=2))
+    print(f"Wrote remediated configuration to {args.output}")
+
+
+if __name__ == "__main__":
+    main()
