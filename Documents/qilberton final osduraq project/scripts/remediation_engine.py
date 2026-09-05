#!/usr/bin/env python3
"""
=============================================================================
 DevSecOps Remediation & Git Patch Generator
-----------------------------------------------------------------------------
 Müəllif: DevSecOps & VAPT Core Engineering
 Təsvir: Normallaşdırılmış zəifliklərdən deterministik Git `.patch` faylları
         və Rollback (Geri Qaytarma) planı olan addım-addım bərpa
         Playbook-ları generasiya edir.
=============================================================================
"""

import os
import sys
import json
import argparse
from pathlib import Path

# Windows UTF-8 Terminal uyğunluğu
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# Hazır deterministik düzəliş şablonları (Templates for Deterministic Patches)
PATCH_TEMPLATES = {
    "SAST-001": {
        "title": "SQL Injection Düzəlişi (Parameterized Query)",
        "vulnerable": 'query = f"SELECT * FROM users WHERE id = {user_id}"\n    cursor.execute(query)',
        "secure": 'query = "SELECT * FROM users WHERE id = ?"\n    cursor.execute(query, (user_id,))',
        "rollback_command": "git checkout -- demo_vulnerabilities/vulnerable_sample.py"
    },
    "SAST-002": {
        "title": "eval() RCE Düzəlişi (Safe AST Literal Parsing)",
        "vulnerable": 'result = eval(user_math_input)',
        "secure": 'try:\n        result = ast.literal_eval(user_math_input)\n    except (ValueError, SyntaxError):\n        result = 0',
        "rollback_command": "git checkout -- demo_vulnerabilities/vulnerable_sample.py"
    },
    "SAST-003": {
        "title": "Command Injection Düzəlişi (Safe Subprocess Execution)",
        "vulnerable": 'os.system(f"ping -c 1 {hostname}")',
        "secure": 'subprocess.run(["ping", "-n", "1", hostname], check=True, capture_output=True)',
        "rollback_command": "git checkout -- demo_vulnerabilities/vulnerable_sample.py"
    },
    "SEC-001": {
        "title": "AWS Access Key Sızması Düzəlişi",
        "vulnerable": 'AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"',
        "secure": 'AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")',
        "rollback_command": "git checkout -- demo_vulnerabilities/vulnerable_sample.py"
    },
    "SEC-003": {
        "title": "OpenAI API Key Sızması Düzəlişi",
        "vulnerable": 'OPENAI_API_KEY = "sk-proj-9999888877776666555544443333222211110000"',
        "secure": 'OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")',
        "rollback_command": "git checkout -- demo_vulnerabilities/vulnerable_sample.py"
    },
    "SEC-007": {
        "title": "Hardcoded Password Düzəlişi",
        "vulnerable": 'DATABASE_PASSWORD = "SuperSecretPassword123!"',
        "secure": 'DATABASE_PASSWORD = os.getenv("DB_PASSWORD")',
        "rollback_command": "git checkout -- demo_vulnerabilities/vulnerable_sample.py"
    }
}

class RemediationEngine:
    def __init__(self, report_file='normalized_report.json', output_dir='playbooks'):
        self.report_file = report_file
        self.output_dir = Path(output_dir)
        self.patches_dir = self.output_dir / 'patches'

    def generate(self):
        if not os.path.exists(self.report_file):
            print(f"[-] Hesabat tapılmadı: {self.report_file}")
            return

        with open(self.report_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        findings = data.get('findings', [])
        os.makedirs(self.patches_dir, exist_ok=True)

        # 1. Bütöv Git Patch Faylının Tərtibi
        patch_file_path = self.patches_dir / 'security_autofix.patch'
        patch_content = self.create_git_patch_content()
        with open(patch_file_path, 'w', encoding='utf-8') as f:
            f.write(patch_content)

        # 2. Markdown Playbook Tərtibi
        playbook_path = self.output_dir / 'REMEDIATION_PLAYBOOK.md'
        playbook_content = self.create_markdown_playbook(data)
        with open(playbook_path, 'w', encoding='utf-8') as f:
            f.write(playbook_content)

        print("\n" + "="*70)
        print(" [DevSecOps Remediation & Patch Generator]")
        print("="*70)
        print(f"  • Deterministik Git Patch:   {patch_file_path}")
        print(f"  • Bərpa Playbook-u:         {playbook_path}")
        print(f"  • Təhlükəsiz Tətbiq Əmri:    git apply {patch_file_path}")
        print("="*70 + "\n")

    def create_git_patch_content(self) -> str:
        """Deterministik Git Diff Patch hazırlayır."""
        patch_text = """--- a/demo_vulnerabilities/vulnerable_sample.py
+++ b/demo_vulnerabilities/vulnerable_sample.py
@@ -8,11 +8,13 @@
-import os
-import sqlite3
+import os
+import sqlite3
+import ast
+import subprocess

-# 1. SIZMIS GIZLI ACARLAR
-OPENAI_API_KEY = "sk-proj-9999888877776666555544443333222211110000"
-AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
-DATABASE_PASSWORD = "SuperSecretPassword123!"
+OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
+AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
+DATABASE_PASSWORD = os.getenv("DB_PASSWORD")

 def get_user_profile(user_id):
-    query = f"SELECT * FROM users WHERE id = {user_id}"
-    cursor.execute(query)
+    query = "SELECT * FROM users WHERE id = ?"
+    cursor.execute(query, (user_id,))

 def calculate_expression(user_math_input):
-    result = eval(user_math_input)
+    try:
+        result = ast.literal_eval(user_math_input)
+    except (ValueError, SyntaxError):
+        result = 0

 def ping_server(hostname):
-    os.system(f"ping -c 1 {hostname}")
+    subprocess.run(["ping", "-n", "1", hostname], check=True, capture_output=True)
"""
        return patch_text

    def create_markdown_playbook(self, data: dict) -> str:
        """Addım-addım icra və Rollback planı olan Playbook Markdown mətni."""
        findings = data.get('findings', [])
        lines = [
            "# 📘 DevSecOps & VAPT Remediation Playbook",
            "",
            f"**Hesabat ID:** `{data.get('scan_id')}`  ",
            f"**Tarix:** `{data.get('generated_at')}`  ",
            f"**Ümumi Risk Skoru:** `{data.get('overall_risk_score')}/10.0` ({data.get('risk_level')})",
            "",
            "> ⚠️ **MÜHƏNDİSLİK QAYDASI:** Canlı mühitə (prodakşn) kor-koranə avtomatik düzəliş edilmir. Bütün düzəlişlər aşağıdakı 4 mərhələli süzgəcdən keçirilir.",
            "",
            "---",
            "",
            "## 🔄 4 Mərhələli Təhlükəsiz Bərpa Siyasəti (Safe Remediation Lifecycle)",
            "",
            "```text",
            "1. Yoxlama (Verify) ──> 2. Patch Tətbiqi (Apply Diff) ──> 3. Unit Test ──> 4. Rollback Planı",
            "```",
            "",
            "---",
            "",
            "## 🛠️ Aşkarlanan Xətaların Detallı Bərpa Təlimatları",
            ""
        ]

        for idx, item in enumerate(findings, 1):
            rule_id = item.get('id')
            template = PATCH_TEMPLATES.get(rule_id, {
                "title": item.get('name'),
                "vulnerable": item.get('code_snippet'),
                "secure": "# Təhlükəsiz həll tətbiq edin: " + item.get('remediation'),
                "rollback_command": f"git checkout -- {item.get('file')}"
            })

            lines.extend([
                f"### {idx}. [{item.get('severity')}] {item.get('name')}",
                f"- **CWE:** `{item.get('cwe')}`",
                f"- **CVSS v3.1 Skor:** `{item.get('cvss_v3_score')}/10.0`",
                f"- **Fayl:** `{item.get('file')}:{item.get('line')}`",
                f"- **Barmaq İzi (Fingerprint):** `{item.get('fingerprint')}`",
                "",
                "#### ❌ Mövcud Zəif Kod Parçası:",
                "```python",
                template["vulnerable"],
                "```",
                "",
                "#### ✅ Təhlükəsiz Düzəliş (Remediated Code):",
                "```python",
                template["secure"],
                "```",
                "",
                "#### ↩️ Rollback (Geri Qaytarma) Proseduru:",
                "> Əgər bu dəyişiklik hər hansı asılılığı pozarsa, aşağıdakı əmrlə dərhal əvvəlki stabil versiyaya qayıdın:",
                "```bash",
                template["rollback_command"],
                "```",
                "",
                "---",
                ""
            ])

        lines.extend([
            "## 🚀 Bir Toxunuşla Avtomatik Bərpa Əmri (Developer Quick Patch)",
            "",
            "Bütün təhlükəsizlik xətalarını bir saniyədə lokal rejimdə həll etmək üçün:",
            "```bash",
            "git apply playbooks/patches/security_autofix.patch",
            "```",
            ""
        ])

        return "\n".join(lines)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="DevSecOps Remediation Generator")
    parser.add_argument("--report", default="normalized_report.json", help="Normallaşdırılmış hesabat faylı")
    parser.add_argument("--output-dir", default="playbooks", help="Playbook və patch qovluğu")
    args = parser.parse_args()

    engine = RemediationEngine(report_file=args.report, output_dir=args.output_dir)
    engine.generate()
