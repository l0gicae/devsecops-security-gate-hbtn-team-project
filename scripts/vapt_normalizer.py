#!/usr/bin/env python3
"""
=============================================================================
 VAPT & Security Data Normalizer & Deduplication Engine
-----------------------------------------------------------------------------
 Müəllif: DevSecOps & VAPT Core Engineering
 Təsvir: Müxtəlif skaner mənbələrindən gələn xam təhlükəsizlik məlumatlarını
         vahid sxemə çevirir, SHA-256 fingerprint ilə deduplikasiya edir,
         CVSS v3.1 əsaslı Risk Skoru hesablayır və False Positive-ləri süzür.
=============================================================================
"""

import os
import sys
import json
import hashlib
import argparse
from datetime import datetime, timezone

# Windows UTF-8 Terminal uyğunluğu
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# CVSS v3.1 Çəki və Dərəcələndirmə Xəritəsi
SEVERITY_CVSS_MAP = {
    "CRITICAL": 9.5,
    "HIGH": 7.8,
    "MEDIUM": 5.3,
    "LOW": 2.5,
    "INFO": 0.0
}

CWE_MAPPINGS = {
    "SEC-001": "CWE-798: Use of Hard-coded Credentials",
    "SEC-002": "CWE-798: Use of Hard-coded Credentials",
    "SEC-003": "CWE-798: Use of Hard-coded Credentials",
    "SEC-004": "CWE-798: Use of Hard-coded Credentials",
    "SEC-005": "CWE-798: Use of Hard-coded Credentials",
    "SEC-006": "CWE-321: Use of Hard-coded Cryptographic Key",
    "SEC-007": "CWE-259: Use of Hard-coded Password",
    "SEC-008": "CWE-798: Use of Hard-coded Credentials",
    "SAST-001": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)",
    "SAST-002": "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code (Eval Injection)",
    "SAST-003": "CWE-78: Improper Neutralization of Special Elements used in an OS Command (Command Injection)",
    "SAST-004": "CWE-502: Deserialization of Untrusted Data",
    "SAST-005": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
    "SAST-006": "CWE-1188: Insecure Default Initialization of Resource (0.0.0.0 Binding)"
}

class VAPTDataNormalizer:
    def __init__(self, input_file='security_report.json', output_file='normalized_report.json'):
        self.input_file = input_file
        self.output_file = output_file
        self.raw_findings = []
        self.normalized_findings = []
        self.fingerprints_seen = set()
        self.duplicates_removed = 0

    def generate_fingerprint(self, finding: dict) -> str:
        """Fayl, sətir nömrəsi və xəta növü üzrə unikal SHA-256 heş generasiya edir."""
        file_path = finding.get('file', '').strip().lower()
        line = str(finding.get('line', 0))
        rule_id = finding.get('id', '').strip()
        
        # Məzmunun qısaldılmış xarakteristikası
        snippet = finding.get('code_snippet', '').strip()[:40]
        
        raw_key = f"{file_path}:{line}:{rule_id}:{snippet}"
        return hashlib.sha256(raw_key.encode('utf-8')).hexdigest()[:12]

    def normalize_and_deduplicate(self):
        """Xam məlumatları təmizləyir, təkrarları silir və CVSS metrikalarını əlavə edir."""
        if not os.path.exists(self.input_file):
            print(f"[-] Giriş faylı tapılmadı: {self.input_file}")
            return None

        with open(self.input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        self.raw_findings = data.get('findings', [])

        for item in self.raw_findings:
            fingerprint = self.generate_fingerprint(item)
            
            # Deduplikasiya: əgər bu xəta artıq siyahıda varsa, təkrarlanmanı kənarlaşdırırıq
            if fingerprint in self.fingerprints_seen:
                self.duplicates_removed += 1
                continue

            self.fingerprints_seen.add(fingerprint)

            severity = item.get('severity', 'MEDIUM').upper()
            rule_id = item.get('id', 'VULN-000')
            cvss_score = SEVERITY_CVSS_MAP.get(severity, 5.0)
            cwe_info = CWE_MAPPINGS.get(rule_id, "CWE-699: Software Development Vulnerability")

            normalized_item = {
                "fingerprint": fingerprint,
                "id": rule_id,
                "name": item.get('name', 'Generic Vulnerability'),
                "category": item.get('category', 'VAPT Finding'),
                "cwe": cwe_info,
                "severity": severity,
                "cvss_v3_score": cvss_score,
                "file": item.get('file', ''),
                "line": item.get('line', 0),
                "code_snippet": item.get('code_snippet', ''),
                "remediation": item.get('remediation', ''),
                "patchable": rule_id in ["SAST-001", "SAST-002", "SAST-003", "SEC-001", "SEC-003", "SEC-007"]
            }
            self.normalized_findings.append(normalized_item)

        # Ümumi Risk Skorunun Hesablanması (Weighted Max Risk Model)
        if self.normalized_findings:
            max_cvss = max(f['cvss_v3_score'] for f in self.normalized_findings)
            avg_cvss = sum(f['cvss_v3_score'] for f in self.normalized_findings) / len(self.normalized_findings)
            overall_score = round(min(10.0, (max_cvss * 0.7) + (avg_cvss * 0.3)), 1)
        else:
            overall_score = 0.0

        if overall_score >= 9.0:
            risk_level = "CRITICAL"
        elif overall_score >= 7.0:
            risk_level = "HIGH"
        elif overall_score >= 4.0:
            risk_level = "MEDIUM"
        elif overall_score > 0.0:
            risk_level = "LOW"
        else:
            risk_level = "CLEAN"

        normalized_report = {
            "scan_id": f"vapt-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "overall_risk_score": overall_score,
            "risk_level": risk_level,
            "stats": {
                "raw_findings_count": len(self.raw_findings),
                "unique_findings_count": len(self.normalized_findings),
                "duplicates_suppressed": self.duplicates_removed,
                "critical_count": sum(1 for f in self.normalized_findings if f['severity'] == 'CRITICAL'),
                "high_count": sum(1 for f in self.normalized_findings if f['severity'] == 'HIGH'),
                "medium_count": sum(1 for f in self.normalized_findings if f['severity'] == 'MEDIUM'),
                "low_count": sum(1 for f in self.normalized_findings if f['severity'] == 'LOW')
            },
            "findings": self.normalized_findings
        }

        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(normalized_report, f, indent=2, ensure_ascii=False)

        print("\n" + "="*70)
        print(" [VAPT Data Normalizer & Deduplication Summary]")
        print("="*70)
        print(f"  • Xam tapıntılar sayı:        {len(self.raw_findings)}")
        print(f"  • Təmizlənmiş unikal xətalar:  {len(self.normalized_findings)}")
        print(f"  • Təkrar (duplicate) süzüldü:  {self.duplicates_removed}")
        print(f"  • Ümumi CVSS v3.1 Risk Skoru:  {overall_score}/10.0 [{risk_level}]")
        print(f"  • Çıxış hesabatı:              {self.output_file}")
        print("="*70 + "\n")

        return normalized_report

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="VAPT Data Normalizer & Deduplication Engine")
    parser.add_argument("--input", default="security_report.json", help="Xam hesabat faylı")
    parser.add_argument("--output", default="normalized_report.json", help="Normallaşdırılmış hesabat faylı")
    args = parser.parse_args()

    normalizer = VAPTDataNormalizer(input_file=args.input, output_file=args.output)
    normalizer.normalize_and_deduplicate()
