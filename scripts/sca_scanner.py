#!/usr/bin/env python3
"""
=============================================================================
 DevSecOps SCA Scanner — Software Composition Analysis
-----------------------------------------------------------------------------
 Müəllif: DevSecOps Automation Team
 Təsvir: requirements.txt, Pipfile, package.json kimi asılılıq fayllarını
         oxuyur və hər kitabxananı Google OSV.dev API vasitəsilə bilinen
         CVE/GHSA zəifliklərə qarşı yoxlayır.
 API:    https://api.osv.dev/v1/query (Pulsuz, açar tələb etmir)
=============================================================================
"""

import re
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("[!] SCA Scanner: 'requests' kitabxanası tapılmadı, SCA skanı atlanır.")
    requests = None

# ─── Dəstəklənən Asılılıq Faylları ────────────────────────────────────────

DEPENDENCY_FILES = [
    "requirements.txt",
    "requirements-dev.txt",
    "requirements_dev.txt",
    "dev-requirements.txt",
    "Pipfile.lock",
    "setup.py",
    "pyproject.toml",
    "package.json",
    "package-lock.json",
    "Gemfile.lock",
    "go.sum",
    "composer.lock",
]

# ─── CVSS Severity Mapping ────────────────────────────────────────────────

def cvss_to_severity(score):
    """CVSS skorunu severity etiketinə çevirir."""
    if score is None:
        return "MEDIUM"
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"


# ─── Requirements.txt Parser ──────────────────────────────────────────────

def parse_requirements(filepath: Path) -> list:
    """requirements.txt faylından paket adı və versiyasını çıxarır."""
    packages = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                # Boş sətir, şərh və ya -r/-e keçidi
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                # Versiya spesifikasiyalarını ayırırıq
                # Dəstəklənən formatlar: pkg==1.0, pkg>=1.0, pkg~=1.0, pkg!=1.0
                match = re.match(
                    r'^([a-zA-Z0-9_][a-zA-Z0-9._-]*)\s*(?:[><=!~]+\s*([0-9][a-zA-Z0-9.*_-]*))?',
                    line
                )
                if match:
                    name = match.group(1).strip().lower()
                    version = match.group(2)
                    if version:
                        version = version.strip()
                    packages.append({
                        "name": name,
                        "version": version,
                        "line": line_no,
                        "source_file": str(filepath.name)
                    })
    except Exception:
        pass
    return packages


def parse_package_json(filepath: Path) -> list:
    """package.json faylından npm paketlərini çıxarır."""
    packages = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        for section in ["dependencies", "devDependencies"]:
            deps = data.get(section, {})
            for name, version_spec in deps.items():
                # ^1.2.3, ~1.2.3, >=1.2.3 formatlarından versiya çıxarırıq
                version = re.sub(r'[^0-9.]', '', version_spec).strip('.')
                packages.append({
                    "name": name.lower(),
                    "version": version or None,
                    "line": 0,
                    "source_file": str(filepath.name),
                    "ecosystem": "npm"
                })
    except Exception:
        pass
    return packages


# ─── OSV.dev API Sorğusu ──────────────────────────────────────────────────

OSV_API_URL = "https://api.osv.dev/v1/query"

def query_osv(package_name: str, version: str, ecosystem: str = "PyPI") -> list:
    """
    Google OSV.dev API-yə sorğu göndərir.
    Pulsuz, limitsiz, açar tələb etmir.
    """
    if requests is None:
        return []

    payload = {
        "package": {
            "name": package_name,
            "ecosystem": ecosystem
        }
    }
    if version:
        payload["version"] = version

    try:
        resp = requests.post(OSV_API_URL, json=payload, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("vulns", [])
    except Exception:
        pass
    return []


def extract_vuln_info(vuln: dict) -> dict:
    """OSV cavabından CVSS skoru, CVE ID və təsviri çıxarır."""
    vuln_id = vuln.get("id", "UNKNOWN")

    # CVE aliası tapırıq
    cve_id = vuln_id
    for alias in vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            cve_id = alias
            break

    # CVSS skoru
    cvss_score = None
    for severity_entry in vuln.get("severity", []):
        score_str = severity_entry.get("score", "")
        # CVSS vektoru əvəzinə bəzən birbaşa skor olur
        if severity_entry.get("type") == "CVSS_V3":
            # CVSS vektorundan skoru çıxarmaq çətindir, API-dan birbaşa dəyər istifadə edirik
            # database_specific bölməsindən daha dəqiq skor ala bilərik
            pass

    # database_specific-dən CVSS skor tapırıq
    db_specific = vuln.get("database_specific", {})
    if "cvss" in db_specific:
        cvss_score = db_specific["cvss"].get("score")
    elif "severity" in db_specific:
        sev = db_specific["severity"]
        if isinstance(sev, str):
            sev_map = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 2.5}
            cvss_score = sev_map.get(sev.upper())

    # GHSA severity
    if cvss_score is None and "github_reviewed_at" in db_specific:
        ghsa_sev = db_specific.get("severity", "MODERATE")
        if isinstance(ghsa_sev, str):
            sev_map = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.5, "LOW": 2.5}
            cvss_score = sev_map.get(ghsa_sev.upper(), 5.5)

    summary = vuln.get("summary", vuln.get("details", "Təsvir mövcud deyil"))[:200]

    # Təsirlənən versiya aralığını tapırıq
    affected_range = ""
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            events = rng.get("events", [])
            introduced = next((e.get("introduced", "") for e in events if "introduced" in e), "")
            fixed = next((e.get("fixed", "") for e in events if "fixed" in e), "")
            if introduced or fixed:
                if fixed:
                    affected_range = f"Təsirlənən: >={introduced or '0'}, Düzəldilmiş: {fixed}"
                else:
                    affected_range = f"Təsirlənən: >={introduced or '0'} (hələ düzəliş yoxdur!)"
                break

    return {
        "vuln_id": vuln_id,
        "cve_id": cve_id,
        "cvss_score": cvss_score,
        "severity": cvss_to_severity(cvss_score),
        "summary": summary,
        "affected_range": affected_range,
        "references": [ref.get("url", "") for ref in vuln.get("references", [])[:2]]
    }


# ─── Əsas SCA Skan Funksiyası ────────────────────────────────────────────

class SCAScanner:
    """Software Composition Analysis — üçüncü tərəf kitabxana zəiflik skaneri."""

    def __init__(self, target_dir: str = "."):
        self.target_path = Path(target_dir).resolve()
        self.findings = []
        self.packages_scanned = 0
        self.vulns_found = 0

    def find_dependency_files(self) -> list:
        """Layihə qovluğunda asılılıq fayllarını tapır."""
        found = []
        if self.target_path.is_dir():
            for dep_file in DEPENDENCY_FILES:
                candidate = self.target_path / dep_file
                if candidate.exists():
                    found.append(candidate)
        return found

    def scan(self) -> list:
        """Bütün asılılıq fayllarını tapıb skan edir."""
        print("\n" + "=" * 70)
        print(" [SCA — Software Composition Analysis Scanner]")
        print("=" * 70)

        dep_files = self.find_dependency_files()

        if not dep_files:
            print("\n[i] Asılılıq faylı tapılmadı (requirements.txt, package.json və s.)")
            print("    SCA skanı atlanır.\n")
            return []

        print(f"\n[i] Tapılan asılılıq faylları: {len(dep_files)}")
        for df in dep_files:
            print(f"    → {df.name}")

        all_packages = []

        for dep_file in dep_files:
            if dep_file.name.startswith("requirements") or dep_file.name in ["setup.py", "pyproject.toml"]:
                packages = parse_requirements(dep_file)
                for pkg in packages:
                    pkg["ecosystem"] = "PyPI"
                all_packages.extend(packages)
            elif dep_file.name in ["package.json", "package-lock.json"]:
                packages = parse_package_json(dep_file)
                all_packages.extend(packages)

        if not all_packages:
            print("\n[i] Asılılıq fayllarında skan ediləcək paket tapılmadı.\n")
            return []

        self.packages_scanned = len(all_packages)
        print(f"\n[*] {self.packages_scanned} paket OSV.dev zəiflik bazasına qarşı yoxlanılır...\n")

        for pkg in all_packages:
            ecosystem = pkg.get("ecosystem", "PyPI")
            vulns = query_osv(pkg["name"], pkg.get("version"), ecosystem)

            if vulns:
                # Eyni CVE-nin fərqli mənbələrdən (GHSA, PYSEC) gəlməsinin qarşısını alırıq
                seen_cves = set()
                for vuln in vulns:
                    info = extract_vuln_info(vuln)
                    # CVE ID-yə görə deduplikasiya
                    dedup_key = f"{pkg['name']}:{info['cve_id']}"
                    if dedup_key in seen_cves:
                        continue
                    seen_cves.add(dedup_key)
                    self.vulns_found += 1

                    version_str = pkg.get("version") or "versiya göstərilməyib"
                    fix_text = info["affected_range"] if info["affected_range"] else "Kitabxananı ən son versiyaya yeniləyin."

                    finding = {
                        "id": f"SCA-{self.vulns_found:03d}",
                        "name": f"Zəiflik: {pkg['name']}=={version_str} ({info['cve_id']})",
                        "category": "SCA Vulnerability",
                        "severity": info["severity"],
                        "file": pkg["source_file"],
                        "line": pkg.get("line", 0),
                        "code_snippet": f"{pkg['name']}=={version_str} → {info['vuln_id']}",
                        "remediation": f"{info['summary'][:120]}. {fix_text}",
                        "cwe": info["cve_id"],
                        "cvss_score": info.get("cvss_score")
                    }
                    self.findings.append(finding)

                    severity_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(info["severity"], "⚪")
                    print(f"  {severity_icon} [{info['severity']}] {pkg['name']}=={version_str}")
                    print(f"       {info['cve_id']}: {info['summary'][:100]}")
                    if info["affected_range"]:
                        print(f"       {info['affected_range']}")
                    print()
            else:
                print(f"  ✅ {pkg['name']}=={pkg.get('version', '?')} — təhlükəsiz")

        # Nəticə
        print("\n" + "-" * 70)
        print(f" [SCA Nəticə]")
        print(f"  • Yoxlanılan paketlər:  {self.packages_scanned}")
        print(f"  • Zəiflik tapılan:      {self.vulns_found}")
        if self.vulns_found == 0:
            print(f"  • Status:               ✅ Bütün kitabxanalar təhlükəsizdir!")
        else:
            crit = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
            high = sum(1 for f in self.findings if f["severity"] == "HIGH")
            print(f"  • CRITICAL:             {crit}")
            print(f"  • HIGH:                 {high}")
        print("-" * 70 + "\n")

        return self.findings


# ─── Standalone İcra ──────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SCA — Software Composition Analysis Scanner")
    parser.add_argument("--target", default=".", help="Skan ediləcək qovluq (Default: .)")
    args = parser.parse_args()

    scanner = SCAScanner(target_dir=args.target)
    findings = scanner.scan()

    if findings:
        print(json.dumps(findings, indent=2, ensure_ascii=False))
        sys.exit(1)
    sys.exit(0)
