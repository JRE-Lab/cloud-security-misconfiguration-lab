diff --git a/lab/README.md b/lab/README.md
new file mode 100644
index 0000000000000000000000000000000000000000..d681e95c1d2f73aa7fb14352accda7517f7f7fc2
--- /dev/null
+++ b/lab/README.md
@@ -0,0 +1,77 @@
+# Cloud Security Misconfiguration Lab (Local Simulation)
+
+This lab simulates common cloud misconfigurations using a simple JSON configuration file. A lightweight scanner identifies risky settings, and a remediation script hardens them so you can re-scan to validate fixes.
+
+## Prerequisites
+
+- Python 3.9+
+
+## Lab Flow
+
+1. **Scan the insecure configuration**
+   ```bash
+   python3 lab/scan.py lab/configs/insecure.json
+   ```
+   (Scripts are executable; you can also run `./lab/scan.py`.)
+
+2. **Review findings** (identify public access, weak IAM policies, missing encryption, etc.).
+
+3. **Remediate** (create a hardened copy of the configuration)
+   ```bash
+   python3 lab/remediate.py lab/configs/insecure.json lab/configs/secure.json
+   ```
+
+4. **Re-scan the secure configuration**
+   ```bash
+   python3 lab/scan.py lab/configs/secure.json
+   ```
+
+## What This Lab Teaches
+
+- How to spot dangerous misconfigurations:
+  - Publicly accessible storage buckets
+  - Overly permissive IAM policies
+  - Internet-exposed administrative ports
+  - Missing encryption at rest
+  - Disabled audit logging
+  - Public database access
+- How remediation changes reduce risk.
+
+## File Format
+
+The lab uses a JSON file with the following structure (see `lab/configs/insecure.json`):
+
+```json
+{
+  "buckets": [
+    {
+      "name": "public-assets",
+      "public": true,
+      "encryption": false
+    }
+  ],
+  "security_groups": [
+    {
+      "name": "web-sg",
+      "ingress": [
+        {"protocol": "tcp", "port": 22, "cidr": "0.0.0.0/0"}
+      ]
+    }
+  ],
+  "iam_policies": [
+    {
+      "name": "admin",
+      "actions": ["*"],
+      "resources": ["*"]
+    }
+  ],
+  "logging": {"cloudtrail": false},
+  "databases": [
+    {"name": "customers", "public_access": true, "encrypted": false}
+  ]
+}
+```
+
+## Extending the Lab
+
+Add new resources or misconfiguration rules in `lab/scan.py` to simulate other risks (e.g., MFA enforcement, VPC flow logs, key rotation). The scanner intentionally stays simple so it is easy to modify.
