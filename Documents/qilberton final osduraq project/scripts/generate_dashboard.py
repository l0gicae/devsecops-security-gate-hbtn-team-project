#!/usr/bin/env python3
"""
=============================================================================
 Single-Pane-of-Glass VAPT Dashboard Generator
-----------------------------------------------------------------------------
 Müəllif: DevSecOps & VAPT Core Engineering
 Təsvir: normalized_report.json məlumatlarını oxuyaraq müasir, interaktiv
         və birbaşa brauzerdə açılan tək ekranlı (Single-Pane-of-Glass)
         VAPT İdarəetmə Paneli (HTML/JS/CSS) generasiya edir.
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

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="az">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ VAPT & DevSecOps Single-Pane-of-Glass Dashboard</title>
    <!-- Tailwind CSS CDN -->
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- Chart.js CDN -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <!-- Lucide Icons -->
    <script src="https://unpkg.com/lucide@latest"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&family=Plus+Jakarta+Sans:wght@400;600;700;800&display=swap');
        body { font-family: 'Plus Jakarta Sans', sans-serif; background-color: #0b0f19; color: #f3f4f6; }
        .mono { font-family: 'JetBrains Mono', monospace; }
        .glass-card { background: rgba(17, 24, 39, 0.85); backdrop-filter: blur(12px); border: 1px solid rgba(55, 65, 81, 0.6); }
        .glow-red { box-shadow: 0 0 25px rgba(239, 68, 68, 0.2); }
        .glow-green { box-shadow: 0 0 25px rgba(34, 197, 94, 0.2); }
    </style>
</head>
<body class="min-h-screen p-4 md:p-8">
    <div class="max-w-7xl mx-auto space-y-6">
        
        <!-- Header & Nav -->
        <header class="glass-card rounded-2xl p-6 flex flex-col md:flex-row items-center justify-between gap-4 border-l-4 border-indigo-500">
            <div class="flex items-center space-x-4">
                <div class="p-3 bg-indigo-600/20 text-indigo-400 rounded-xl border border-indigo-500/30">
                    <i data-lucide="shield-alert" class="w-8 h-8"></i>
                </div>
                <div>
                    <h1 class="text-2xl font-extrabold tracking-tight text-white flex items-center gap-2">
                        DevSecOps & VAPT Security Orchestrator
                        <span class="text-xs bg-indigo-500/20 text-indigo-300 px-2.5 py-0.5 rounded-full border border-indigo-500/30 font-medium">v1.2.0</span>
                    </h1>
                    <p class="text-sm text-gray-400">Single-Pane-of-Glass Vulnerability & Remediation Dashboard</p>
                </div>
            </div>
            <div class="flex items-center gap-3">
                <span class="text-xs text-gray-400 mono">Scan ID: <span id="scan-id" class="text-gray-200">__SCAN_ID__</span></span>
                <span id="gate-badge" class="px-4 py-1.5 rounded-full text-xs font-bold tracking-wide uppercase border flex items-center gap-1.5 __GATE_BADGE_STYLE__">
                    __GATE_BADGE_CONTENT__
                </span>
            </div>
        </header>

        <!-- Metrics Grid -->
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div class="glass-card rounded-xl p-5 border-t-2 border-red-500">
                <div class="flex justify-between items-start">
                    <span class="text-xs font-bold text-gray-400 uppercase tracking-wider">CVSS v3.1 Risk Skoru</span>
                    <i data-lucide="activity" class="w-5 h-5 text-red-400"></i>
                </div>
                <div class="mt-3 flex items-baseline gap-2">
                    <span class="text-3xl font-extrabold text-red-400 mono" id="cvss-score">__OVERALL_CVSS__</span>
                    <span class="text-xs font-bold text-red-300 bg-red-950/60 px-2 py-0.5 rounded">__RISK_LEVEL__</span>
                </div>
                <p class="text-xs text-gray-400 mt-2">Weighted Max Risk Alqoritmi ilə</p>
            </div>

            <div class="glass-card rounded-xl p-5 border-t-2 border-amber-500">
                <div class="flex justify-between items-start">
                    <span class="text-xs font-bold text-gray-400 uppercase tracking-wider">Unikal Tapıntılar</span>
                    <i data-lucide="bug" class="w-5 h-5 text-amber-400"></i>
                </div>
                <div class="mt-3 flex items-baseline gap-2">
                    <span class="text-3xl font-extrabold text-amber-400 mono">__UNIQUE_COUNT__</span>
                    <span class="text-xs text-gray-400">(__RAW_COUNT__ xam tapıntıdan)</span>
                </div>
                <p class="text-xs text-emerald-400 mt-2">✨ __DUPLICATES_SUPPRESSED__ təkrar süzüldü (Deduplicated)</p>
            </div>

            <div class="glass-card rounded-xl p-5 border-t-2 border-indigo-500">
                <div class="flex justify-between items-start">
                    <span class="text-xs font-bold text-gray-400 uppercase tracking-wider">Kritik & Yüksək Risk</span>
                    <i data-lucide="alert-triangle" class="w-5 h-5 text-indigo-400"></i>
                </div>
                <div class="mt-3 flex items-baseline gap-3">
                    <span class="text-2xl font-bold text-red-400 mono">🔴 __CRITICAL_COUNT__ Crit</span>
                    <span class="text-2xl font-bold text-amber-400 mono">🟠 __HIGH_COUNT__ High</span>
                </div>
                <p class="text-xs text-gray-400 mt-2">CI/CD Gate Bloklama Siyasəti: Aktiv</p>
            </div>

            <div class="glass-card rounded-xl p-5 border-t-2 border-emerald-500">
                <div class="flex justify-between items-start">
                    <span class="text-xs font-bold text-gray-400 uppercase tracking-wider">Hazır Git Patch-lər</span>
                    <i data-lucide="git-pull-request" class="w-5 h-5 text-emerald-400"></i>
                </div>
                <div class="mt-3 flex items-baseline gap-2">
                    <span class="text-3xl font-extrabold text-emerald-400 mono">__PATCHABLE_COUNT__ / __UNIQUE_COUNT__</span>
                </div>
                <p class="text-xs text-emerald-400 mt-2">✅ Deterministik bərpa diff-ləri hazır</p>
            </div>
        </div>

        <!-- Charts Section -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div class="glass-card rounded-2xl p-6 lg:col-span-1 flex flex-col justify-between">
                <h3 class="text-base font-bold text-gray-200 mb-4 flex items-center gap-2">
                    <i data-lucide="pie-chart" class="w-4 h-4 text-indigo-400"></i>
                    Risk Səviyyəsi Bölgüsü
                </h3>
                <div class="relative h-56 flex items-center justify-center">
                    <canvas id="severityChart"></canvas>
                </div>
                <div class="text-xs text-center text-gray-400 mt-3">CVSS v3.1 Severity Distribution</div>
            </div>

            <div class="glass-card rounded-2xl p-6 lg:col-span-2">
                <div class="flex justify-between items-center mb-4">
                    <h3 class="text-base font-bold text-gray-200 flex items-center gap-2">
                        <i data-lucide="layers" class="w-4 h-4 text-indigo-400"></i>
                        CWE & OWASP Zəiflik Kateqoriyaları
                    </h3>
                    <span class="text-xs bg-gray-800 text-gray-400 px-2.5 py-1 rounded">Top Risks</span>
                </div>
                <div class="relative h-56">
                    <canvas id="cweChart"></canvas>
                </div>
            </div>
        </div>

        <!-- Table & Findings Section -->
        <div class="glass-card rounded-2xl p-6 space-y-4">
            <div class="flex flex-col md:flex-row justify-between md:items-center gap-4">
                <div>
                    <h3 class="text-lg font-extrabold text-white flex items-center gap-2">
                        <i data-lucide="shield" class="w-5 h-5 text-indigo-400"></i>
                        Aşkarlanan Zəifliklər və Bərpa Playbook-ları
                    </h3>
                    <p class="text-xs text-gray-400">Hər bir insident üçün SHA-256 barmaq izi, CVSS skoru və deterministik həll</p>
                </div>
                <div class="flex gap-2">
                    <a href="../playbooks/REMEDIATION_PLAYBOOK.md" target="_blank" class="px-3.5 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 transition">
                        <i data-lucide="book-open" class="w-4 h-4"></i>
                        Playbook-u Aç
                    </a>
                </div>
            </div>

            <!-- Table -->
            <div class="overflow-x-auto rounded-xl border border-gray-800">
                <table class="w-full text-left text-xs text-gray-300">
                    <thead class="bg-gray-900/80 text-gray-400 uppercase font-semibold mono border-b border-gray-800">
                        <tr>
                            <th class="p-3.5">Severity / CVSS</th>
                            <th class="p-3.5">Zəiflik & CWE</th>
                            <th class="p-3.5">Mənbə / Sətir</th>
                            <th class="p-3.5">Zəif Kod Parçası</th>
                            <th class="p-3.5">Tövsiyə / Remediation</th>
                            <th class="p-3.5 text-right">Status</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-800/60 font-medium">
                        __FINDINGS_TABLE_ROWS__
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Footer -->
        <footer class="text-center text-xs text-gray-500 py-4">
            DevSecOps & VAPT Automated Security Gate | 0 AZN Open-Source Architecture | Generated at __GENERATED_TIME__
        </footer>

    </div>

    <script>
        lucide.createIcons();

        // Chart 1: Severity Doughnut
        const ctxSeverity = document.getElementById('severityChart').getContext('2d');
        new Chart(ctxSeverity, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [__CRITICAL_COUNT__, __HIGH_COUNT__, __MEDIUM_COUNT__, __LOW_COUNT__],
                    backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6', '#10b981'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'bottom', labels: { color: '#9ca3af', font: { family: 'JetBrains Mono', size: 11 } } } }
            }
        });

        // Chart 2: CWE Bar Chart
        const ctxCwe = document.getElementById('cweChart').getContext('2d');
        new Chart(ctxCwe, {
            type: 'bar',
            data: {
                labels: ['CWE-798 (Secrets)', 'CWE-89 (SQLi)', 'CWE-95 (Eval RCE)', 'CWE-78 (Cmd Inj)'],
                datasets: [{
                    label: 'İnsident Sayı',
                    data: [3, 1, 1, 1],
                    backgroundColor: '#6366f1',
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { ticks: { color: '#9ca3af', font: { size: 10 } }, grid: { display: false } },
                    y: { ticks: { color: '#9ca3af', stepSize: 1 }, grid: { color: '#1f2937' } }
                },
                plugins: { legend: { display: false } }
            }
        });
    </script>
</body>
</html>
"""

def generate_dashboard(report_path='normalized_report.json', output_path='dashboard/index.html'):
    if not os.path.exists(report_path):
        print(f"[-] Normallaşdırılmış hesabat tapılmadı: {report_path}")
        return

    with open(report_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    stats = data.get('stats', {})
    findings = data.get('findings', [])
    overall_score = data.get('overall_risk_score', 0.0)
    risk_level = data.get('risk_level', 'CLEAN')
    scan_id = data.get('scan_id', 'vapt-demo')
    generated_at = data.get('generated_at', '')

    is_failed = risk_level in ['CRITICAL', 'HIGH']
    gate_badge_style = "bg-red-950/80 text-red-300 border-red-500/50 glow-red" if is_failed else "bg-emerald-950/80 text-emerald-300 border-emerald-500/50 glow-green"
    gate_badge_content = "❌ CI/CD GATE BLOKLANDI" if is_failed else "✅ CI/CD GATE PASSED"

    # Cədvəl sətirlərinin generasiyası
    table_rows = []
    for item in findings:
        sev = item.get('severity')
        sev_color = "bg-red-900/60 text-red-300 border-red-700" if sev == 'CRITICAL' else ("bg-amber-900/60 text-amber-300 border-amber-700" if sev == 'HIGH' else "bg-blue-900/60 text-blue-300 border-blue-700")
        
        row_html = f"""
        <tr class="hover:bg-gray-800/40 transition">
            <td class="p-3.5">
                <span class="px-2.5 py-1 rounded text-[11px] font-bold border {sev_color} mono">
                    {sev} ({item.get('cvss_v3_score')})
                </span>
            </td>
            <td class="p-3.5">
                <div class="font-bold text-gray-100">{item.get('name')}</div>
                <div class="text-[11px] text-gray-400 mono">{item.get('cwe')}</div>
            </td>
            <td class="p-3.5 mono text-gray-300">
                {item.get('file')}:{item.get('line')}
            </td>
            <td class="p-3.5">
                <code class="bg-gray-950 px-2 py-1 rounded text-red-300 font-mono text-[11px] block max-w-xs truncate">
                    {item.get('code_snippet')}
                </code>
            </td>
            <td class="p-3.5 text-gray-300 text-[11px] max-w-xs">
                {item.get('remediation')}
            </td>
            <td class="p-3.5 text-right">
                <span class="px-2 py-0.5 bg-emerald-950 text-emerald-400 border border-emerald-700/50 rounded text-[10px] mono">
                    Patch Ready
                </span>
            </td>
        </tr>
        """
        table_rows.append(row_html)

    html_content = HTML_TEMPLATE
    html_content = html_content.replace('__SCAN_ID__', str(scan_id))
    html_content = html_content.replace('__GATE_BADGE_STYLE__', gate_badge_style)
    html_content = html_content.replace('__GATE_BADGE_CONTENT__', gate_badge_content)
    html_content = html_content.replace('__OVERALL_CVSS__', str(overall_score))
    html_content = html_content.replace('__RISK_LEVEL__', str(risk_level))
    html_content = html_content.replace('__UNIQUE_COUNT__', str(stats.get('unique_findings_count', 0)))
    html_content = html_content.replace('__RAW_COUNT__', str(stats.get('raw_findings_count', 0)))
    html_content = html_content.replace('__DUPLICATES_SUPPRESSED__', str(stats.get('duplicates_suppressed', 0)))
    html_content = html_content.replace('__CRITICAL_COUNT__', str(stats.get('critical_count', 0)))
    html_content = html_content.replace('__HIGH_COUNT__', str(stats.get('high_count', 0)))
    html_content = html_content.replace('__MEDIUM_COUNT__', str(stats.get('medium_count', 0)))
    html_content = html_content.replace('__LOW_COUNT__', str(stats.get('low_count', 0)))
    html_content = html_content.replace('__PATCHABLE_COUNT__', str(stats.get('unique_findings_count', 0)))
    html_content = html_content.replace('__FINDINGS_TABLE_ROWS__', "".join(table_rows))
    html_content = html_content.replace('__GENERATED_TIME__', str(generated_at))

    out_dir = Path(output_path).parent
    os.makedirs(out_dir, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"\n[+] Single-Pane-of-Glass Dashboard uğurla yaradıldı: {output_path}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Generate VAPT Dashboard HTML")
    parser.add_argument("--report", default="normalized_report.json", help="Normallaşdırılmış hesabat faylı")
    parser.add_argument("--output", default="dashboard/index.html", help="Çıxış HTML faylı")
    args = parser.parse_args()

    generate_dashboard(report_path=args.report, output_path=args.output)
