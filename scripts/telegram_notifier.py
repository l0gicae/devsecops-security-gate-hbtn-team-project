#!/usr/bin/env python3
"""
=============================================================================
 DevSecOps Telegram Alert Bot
-----------------------------------------------------------------------------
 Müəllif: DevSecOps Automation Team
 Təsvir: security_report.json faylındakı təhlükəsizlik hesabatını oxuyur və
         GitHub Actions mühit məlumatları ilə birlikdə Telegram kanalına/qrupuna
         zəngin formatlı (HTML) xəbərdarlıq bildirişi göndərir.
=============================================================================
"""

import os
import sys
import json
import argparse
import requests

# Windows UTF-8 Terminal uyğunluğu
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

def escape_html(text: str) -> str:
    """Telegram HTML formatı üçün xüsusi simvolları təmizləyir."""
    if not text:
        return ""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def build_telegram_message(report_data: dict) -> str:
    """Təhlükəsizlik hesabatı əsasında Telegram HTML mesajı formalaşdırır."""
    repo = os.getenv("GITHUB_REPOSITORY", "Local/DevSecOps-Demo")
    actor = os.getenv("GITHUB_ACTOR", "Aphentes")
    branch = os.getenv("GITHUB_REF_NAME", "main")
    commit_sha = os.getenv("GITHUB_SHA", "local-test-sha")[:7]
    server_url = os.getenv("GITHUB_SERVER_URL", "https://github.com")
    run_id = os.getenv("GITHUB_RUN_ID", "")
    run_url = f"{server_url}/{repo}/actions/runs/{run_id}" if run_id else f"{server_url}/{repo}"

    summary = report_data.get("summary", {})
    status = report_data.get("status", "FAILED")
    findings = report_data.get("findings", [])

    if status == "FAILED":
        header_emoji = "🚨"
        status_text = "<b>❌ BLOKLANDI (CI/CD Pipeline Stopped)</b>"
    else:
        header_emoji = "🛡️"
        status_text = "<b>✅ UĞURLA KEÇDİ (Pipeline Passed)</b>"

    message_lines = [
        f"{header_emoji} <b>[DEVSECOPS SECURITY GATE ALERT]</b>",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"📂 <b>Repozitoriya:</b> <code>{escape_html(repo)}</code>",
        f"👤 <b>Müəllif:</b> @{escape_html(actor)}",
        f"🌿 <b>Branch:</b> <code>{escape_html(branch)}</code> ({commit_sha})",
        f"📊 <b>Status:</b> {status_text}",
        "",
        f"📈 <b>Xülasə:</b>",
        f"  • Yoxlanılan fayllar: {summary.get('files_scanned', 0)}",
        f"  • 🔴 <b>Critical:</b> {summary.get('critical', 0)}",
        f"  • 🟠 <b>High:</b> {summary.get('high', 0)}",
        f"  • 🟡 <b>Medium:</b> {summary.get('medium', 0)}",
        f"  • 🔵 <b>Low:</b> {summary.get('low', 0)}",
    ]

    if findings:
        message_lines.append("\n⚠️ <b>Aşkarlanan Təhlükəli İnsidentlər (Top 5):</b>")
        for i, item in enumerate(findings[:5], 1):
            sev_badge = "🔴" if item['severity'] == "CRITICAL" else ("🟠" if item['severity'] == "HIGH" else "🟡")
            message_lines.append(
                f"\n<b>{i}. {sev_badge} [{item['severity']}] {escape_html(item['name'])}</b>\n"
                f"   📁 <code>{escape_html(item['file'])}:{item['line']}</code>\n"
                f"   🔎 <code>{escape_html(item['code_snippet'][:60])}</code>\n"
                f"   💡 <i>{escape_html(item['remediation'])}</i>"
            )
        
        if len(findings) > 5:
            message_lines.append(f"\n<i>... və daha {len(findings) - 5} təhlükəsizlik xətası.</i>")

    message_lines.append("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    message_lines.append(f"🔗 <a href=\"{run_url}\">GitHub Actions İcra Jurnalına Bax</a>")
    
    return "\n".join(message_lines)

def send_telegram_notification(report_path: str, mock: bool = False):
    """Hesabatı oxuyur və Telegram API vasitəsilə bildiriş göndərir."""
    if not os.path.exists(report_path):
        print(f"⚠️ Hesabat faylı tapılmadı: {report_path}")
        return

    with open(report_path, 'r', encoding='utf-8') as f:
        report_data = json.load(f)

    bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    message = build_telegram_message(report_data)

    print("\n" + "="*50)
    print("📱 Telegram Bildiriş Mesajının Formatı:")
    print("="*50)
    print(message.replace("<b>", "").replace("</b>", "").replace("<code>", "").replace("</code>", "").replace("<i>", "").replace("</i>", ""))
    print("="*50 + "\n")

    if mock or not bot_token or not chat_id:
        if not bot_token or not chat_id:
            print("ℹ️ TELEGRAM_BOT_TOKEN və ya TELEGRAM_CHAT_ID təyin edilməyib. Mock rejimində icra edildi.")
        else:
            print("✅ Mock rejimi aktivdir: Mesaj Telegram-a real göndərilmədi.")
        return

    # Real Telegram API çağırışı
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": True
    }

    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            print("🚀 Telegram xəbərdarlıq bildirişi uğurla çatdırıldı!")
        else:
            print(f"❌ Telegram API Xətası ({response.status_code}): {response.text}")
    except Exception as e:
        print(f"❌ Telegram-a qoşulma xətası: {str(e)}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="DevSecOps Telegram Notifier")
    parser.add_argument("--report", default="security_report.json", help="Hesabat faylının yolu")
    parser.add_argument("--mock", action="store_true", help="Real API olmadan terminalda simulyasiya et")
    args = parser.parse_args()

    send_telegram_notification(report_path=args.report, mock=args.mock)
