#!/usr/bin/env python3
"""
=============================================================================
 DevSecOps Security Gate: Automated Code & Secret Scanner
-----------------------------------------------------------------------------
 Müəllif: DevSecOps Automation Team
 Təsvir: Kod bazasındakı təhlükəsizlik boşluqlarını (SAST) və sızmış
         gizli açarları (Secret Leak) aşkarlayır, strukturlaşdırılmış
         hesabat hazırlayır və risk aşkarlandıqda çıxış kodu 1 qaytarır.
=============================================================================
"""

import os
import sys
import re
import json
import argparse
from datetime import datetime, timezone
from pathlib import Path

# Windows UTF-8 Terminal uyğunluğu
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# Gizli açarlar üçün Regex Qaydaları (Secret Patterns)
SECRET_PATTERNS = [
    {
        "id": "SEC-001",
        "name": "AWS Access Key ID",
        "severity": "CRITICAL",
        "regex": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "remediation": "AWS açarlarını koddan silin və AWS Secrets Manager və ya Environment Variables istifadə edin."
    },
    {
        "id": "SEC-002",
        "name": "AWS Secret Access Key",
        "severity": "CRITICAL",
        "regex": r"(?i)aws_secret_access_key\s*=\s*['\"][A-Za-z0-9\/+=]{40}['\"]",
        "remediation": "AWS Secret açarını dərhal dəyişin (rotate) və mühit dəyişənlərinə keçirin."
    },
    {
        "id": "SEC-003",
        "name": "OpenAI / LLM API Key",
        "severity": "CRITICAL",
        "regex": r"sk-(?:proj-|none-)?[a-zA-Z0-9_-]{32,}",
        "remediation": "OpenAI API açarlarını heç vaxt repozitoriyaya göndərməyin (.env faylından oxuyun)."
    },
    {
        "id": "SEC-004",
        "name": "GitHub Personal Access Token",
        "severity": "CRITICAL",
        "regex": r"gh[pous]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82}",
        "remediation": "GitHub tokenini dərhal ləğv edin (Revoke) və GitHub Secrets-dən istifadə edin."
    },
    {
        "id": "SEC-005",
        "name": "Telegram Bot Token",
        "severity": "HIGH",
        "regex": r"\b[0-9]{8,10}:[a-zA-Z0-9_-]{35}\b",
        "remediation": "Telegram bot tokenini .env faylında saxlayın və @BotFather ilə yeniləyin."
    },
    {
        "id": "SEC-006",
        "name": "RSA / Private Key Block",
        "severity": "CRITICAL",
        "regex": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "remediation": "Şəxsi kriptoqrafik açarları heç bir halda koda daxil etməyin."
    },
    {
        "id": "SEC-007",
        "name": "Hardcoded Password / Credential",
        "severity": "HIGH",
        "regex": r"(?i)(?:password|passwd|pwd|secret_key|db_pass)\s*=\s*['\"][^'\"]{6,}['\"]",
        "remediation": "Statik şifrələri konfiqurasiya fayllarından çıxarıb təhlükəsiz Vault-a yerləşdirin."
    },
    {
        "id": "SEC-008",
        "name": "Slack Webhook / Bot Token",
        "severity": "HIGH",
        "regex": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*|https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        "remediation": "Slack tokenlərini və webhook URL-lərini təhlükəsiz mühit dəyişənləri ilə əvəzləyin."
    }
]

# SAST Qaydaları (Statik Kod Təhlükəsizliyi)
SAST_PATTERNS = [
    {
        "id": "SAST-001",
        "name": "SQL Injection Riski (String Interpolation in Query)",
        "severity": "CRITICAL",
        "regex": r"(?i)(?:f[\"'].*?(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*?\{.*?\}|(?:execute|cursor\.execute|raw_query)\s*\(\s*f[\"'].*?(?:SELECT|INSERT|UPDATE|DELETE|DROP).*?\{|[\"'].*?(?:SELECT|INSERT|UPDATE|DELETE|DROP).*?\+\s*(?:\w+|[\"']))",
        "remediation": "Parametrləşdirilmiş sorğulardan (Parameterized Queries / ORM: cursor.execute('SELECT...', (val,))) istifadə edin."
    },
    {
        "id": "SAST-002",
        "name": "Təhlükəli eval() / exec() Çağırışı",
        "severity": "CRITICAL",
        "regex": r"\b(?:eval|exec)\s*\(",
        "remediation": "Dinamik kod icra edən eval()/exec() funksiyalarından çəkinin, ast.literal_eval və ya json.loads istifadə edin."
    },
    {
        "id": "SAST-003",
        "name": "Komanda İnyeksiyası (Command Injection / os.system)",
        "severity": "HIGH",
        "regex": r"\bos\.system\s*\(|\bsubprocess\.(?:Popen|call|run)\s*\(.*?shell\s*=\s*True",
        "remediation": "subprocess modulunda `shell=False` istifadə edin və parametrləri massiv şəklində ötürün."
    },
    {
        "id": "SAST-004",
        "name": "Təhlükəsiz Olmayan Deserializasiya (Pickle RCE)",
        "severity": "HIGH",
        "regex": r"\bpickle\.(?:loads|load)\s*\(",
        "remediation": "Pickle əvəzinə təhlükəsiz məlumat formatları (JSON, Protocol Buffers) tətbiq edin."
    },
    {
        "id": "SAST-005",
        "name": "Zəif Həş Alqoritmi (MD5/SHA1)",
        "severity": "MEDIUM",
        "regex": r"\bhashlib\.(?:md5|sha1)\s*\(",
        "remediation": "Şifrələmə və həş üçün SHA-256, bcrypt və ya Argon2 istifadə edin."
    },
    {
        "id": "SAST-006",
        "name": "Təhlükəli Bütün İnterfeyslərə Bağlanma (0.0.0.0)",
        "severity": "LOW",
        "regex": r"host\s*=\s*['\"]0\.0\.0\.0['\"]",
        "remediation": "Production-da yalnız icazə verilən IP ünvanlarına və ya 127.0.0.1 ünvanına bağlayın."
    }
]

IGNORED_DIRS = {'.git', '.github', '__pycache__', 'node_modules', '.venv', 'venv', '.agents', 'env', 'presentation', 'playbooks', 'dashboard', 'demo_vulnerabilities'}
IGNORED_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.pyc', '.zip', '.tar', '.gz', '.pdf', '.html', '.md', '.patch', '.json', '.txt'}

class SecurityScanner:
    def __init__(self, target_dir='.', output_file='security_report.json'):
        self.target_path = Path(target_dir).resolve()
        self.output_file = output_file
        self.findings = []
        self.files_scanned = 0

    def scan_file_content(self, file_path: Path):
        """Faylın daxilindəki sətirləri süzərək Secret və SAST qaydalarını yoxlayır."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception:
            return

        self.files_scanned += 1
        rel_path = str(file_path.name)
        if self.target_path.is_dir():
            try:
                rel_path = str(file_path.relative_to(self.target_path)).replace('\\', '/')
            except ValueError:
                pass

        # Skanerin öz alətlərini və hesabat fayllarını yoxlamadan çıxarırıq
        if file_path.name in ['security_scanner.py', 'remediation_engine.py', 'vapt_normalizer.py', 'generate_dashboard.py', 'telegram_notifier.py', 'security_report.json', 'normalized_report.json']:
            return

        for line_no, line in enumerate(lines, 1):
            stripped_line = line.strip()
            if not stripped_line:
                continue

            is_comment = stripped_line.startswith('#') or stripped_line.startswith('//') or stripped_line.startswith('/*')

            # 1. Secret Scanning (Hətta şərhlərdə də açar olarsa yoxlayırıq)
            for rule in SECRET_PATTERNS:
                if re.search(rule["regex"], line):
                    self.findings.append({
                        "id": rule["id"],
                        "name": rule["name"],
                        "category": "Secret Leak",
                        "severity": rule["severity"],
                        "file": rel_path,
                        "line": line_no,
                        "code_snippet": stripped_line[:120],
                        "remediation": rule["remediation"]
                    })

            # 2. SAST Scanning (Yalnız real kod sətirləri üçün yoxlanılır)
            if not is_comment:
                for rule in SAST_PATTERNS:
                    if re.search(rule["regex"], line):
                        self.findings.append({
                            "id": rule["id"],
                            "name": rule["name"],
                            "category": "SAST Vulnerability",
                            "severity": rule["severity"],
                            "file": rel_path,
                            "line": line_no,
                            "code_snippet": stripped_line[:120],
                            "remediation": rule["remediation"]
                        })

    def run_scan(self):
        """Hədəf qovluq və ya faylı gəzərək skan edir."""
        print("\n" + "="*70)
        print(" [DevSecOps Automated Pipeline Security Gate Scanner]")
        print("="*70)
        print(f" Target: {self.target_path}\n")

        if self.target_path.is_file():
            self.scan_file_content(self.target_path)
        elif self.target_path.is_dir():
            for root, dirs, files in os.walk(self.target_path):
                dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
                for file in files:
                    file_path = Path(root) / file
                    if file_path.suffix in IGNORED_EXTENSIONS:
                        continue
                    self.scan_file_content(file_path)

        self.generate_report()
        return self.evaluate_results()

    def generate_report(self):
        """Tapılan nəticələri JSON formatında qeyd edir və terminala çıxarır."""
        critical_count = sum(1 for f in self.findings if f['severity'] == 'CRITICAL')
        high_count = sum(1 for f in self.findings if f['severity'] == 'HIGH')
        medium_count = sum(1 for f in self.findings if f['severity'] == 'MEDIUM')
        low_count = sum(1 for f in self.findings if f['severity'] == 'LOW')

        status = "FAILED" if (critical_count > 0 or high_count > 0) else "PASSED"

        report_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scanner_version": "1.0.0",
            "status": status,
            "summary": {
                "files_scanned": self.files_scanned,
                "total_findings": len(self.findings),
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count
            },
            "findings": self.findings
        }

        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

        # Terminal Çıxışı
        if self.findings:
            print(f"\n[!] TƏHLÜKƏSİZLİK XƏTALARI VƏ SIZMALAR AŞKARLANDI! ({len(self.findings)} insident)\n")
            for idx, item in enumerate(self.findings, 1):
                print(f"[{idx}] [{item['severity']}] {item['name']} ({item['category']})")
                print(f"    File: {item['file']}:{item['line']}")
                print(f"    Code: `{item['code_snippet']}`")
                print(f"    Fix:  {item['remediation']}")
                print("    " + "-" * 60)
        else:
            print("\n[+] Heç bir təhlükəsizlik boşluğu və ya sızmış gizli açar aşkarlanmadı!\n")

        print(f"\n[i] Skan Statistikası:")
        print(f"  - Yoxlanılan fayl sayı: {self.files_scanned}")
        print(f"  - Ümumi tapıntılar:     {len(self.findings)}")
        print(f"  - Hesabat faylı:        {self.output_file}")

        # Dashboard-u və normallaşdırılmış hesabatı avtomatik yeniləyirik
        try:
            scripts_dir = Path(__file__).resolve().parent
            if str(scripts_dir) not in sys.path:
                sys.path.insert(0, str(scripts_dir))
            from vapt_normalizer import VAPTDataNormalizer
            from generate_dashboard import generate_dashboard
            normalizer = VAPTDataNormalizer(input_file=self.output_file, output_file='normalized_report.json')
            normalizer.normalize_and_deduplicate()
            generate_dashboard(report_path='normalized_report.json', output_path='dashboard/index.html')
            print("  - VAPT Dashboard:       dashboard/index.html [Avtomatik Yeniləndi]")
        except Exception:
            pass

    def evaluate_results(self) -> int:
        """Kritik və ya Yüksək riskli xətalar olduqda 1 (Fail), əks halda 0 (Pass) qaytarır."""
        has_blocking_issues = any(f['severity'] in ['CRITICAL', 'HIGH'] for f in self.findings)
        if has_blocking_issues:
            print("\n[X] [DEVSECOPS GATE BLOCKED]: Kritik/Yüksək riskli boşluqlara görə CI/CD dayandırıldı!\n")
            return 1
        else:
            print("\n[V] [DEVSECOPS GATE PASSED]: Bütün təhlükəsizlik yoxlamaları uğurla tamamlandı!\n")
            return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="DevSecOps Code & Secret Scanner")
    parser.add_argument("--target", default=".", help="Skan ediləcək qovluq və ya fayl (Default: .)")
    parser.add_argument("--output", default="security_report.json", help="Hesabat faylının adı (Default: security_report.json)")
    args = parser.parse_args()

    scanner = SecurityScanner(target_dir=args.target, output_file=args.output)
    exit_code = scanner.run_scan()
    sys.exit(exit_code)
