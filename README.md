# 🛡️ Avtomatlaşdırılmış DevSecOps Təhlükəsizlik Qapısı (CI/CD Pipeline Security)

[![DevSecOps Security Gate](https://img.shields.io/badge/Security-Automated_Gate-brightgreen.svg)]()
[![Cost](https://img.shields.io/badge/Cost-0_AZN-blue.svg)]()
[![Telegram Alerts](https://img.shields.io/badge/Telegram-Instant_Alerts-2CA5E0.svg)]()
[![Python](https://img.shields.io/badge/Python-3.11+-yellow.svg)]()

Avtomatlaşdırılmış DevSecOps Təhlükəsizlik Qapısı layihəyə bilərəkdən və ya təsadüfən zəif kod (məsələn: SQL Injection, Command Injection, RCE) və ya sızmış məxfi açarlar (OpenAI API key, AWS Token, DB Password) əlavə edildikdə işə düşən, **0 AZN xərcli** və **tam avtomatlaşdırılmış** mühafizə sistemidir.

---

## 🌟 Əsas Xüsusiyyətlər

1. **Gizli Açarların və Sızmaların Aşkarlanması (Secret Leak Detection):**
   - AWS Keys, OpenAI / LLM Keys, GitHub Tokens, Telegram Bot Tokens, RSA Keys, Hardcoded Passwords.
2. **Statik Kod Təhlükəsizliyi (SAST Code Vulnerability Analysis):**
   - SQL Injection (Dynamic query formatting)
   - Remote Code Execution (`eval()`, `exec()`)
   - Command Injection (`os.system()`, `subprocess shell=True`)
   - Təhlükəli deserializasiya (`pickle`)
3. **CI/CD Boru Xətti və Avtomatik Bloklama (GitHub Actions Security Gate):**
   - Təhlükəli PR və ya commit daxil olduqda iş avtomatik dayanır (`exit 1`) və birləşdirmə (Merge) bloklanır.
4. **Real-vaxtda Telegram Alert Botu:**
   - İnsident baş verən anda layihə adı, commit müəllifi, aşkar olunan xətanın növü, sətir nömrəsi və həll təlimatı Telegram kanalına/qrupuna göndərilir.
5. **0 AZN Xərc:**
   - Heç bir ödənişli lisenziya və ya server tələb olunmur (GitHub Actions pulsuz kvotası + Telegram Bot API).

---

## 📁 Layihə Strukturu

```text
├── .github/
│   └── workflows/
│       └── security-gate.yml          # GitHub Actions Təhlükəsizlik Qapısı workflow-u
├── scripts/
│   ├── security_scanner.py            # SAST və Secret Leak skaneri mühərriki
│   └── telegram_notifier.py           # Telegram xəbərdarlıq və hesabat botu
├── demo_vulnerabilities/
│   ├── vulnerable_sample.py           # Qəsdən zəiflik daxil edilmiş nümunə (Demo üçün)
│   └── clean_sample.py                # Təhlükəsiz və təmizlənmiş nümunə
├── DEMO_GUIDE.md                      # Münsiflər üçün 3 dəqiqəlik canlı təqdimat ssenarisi
├── requirements.txt                   # Asılılıqlar
└── README.md                          # Layihə sənədləşməsi
```

---

## 👥 Komanda Bölgüsü

| Rol | Cavabdehlik | Əsas Fayllar |
| :--- | :--- | :--- |
| **🛡️ Təhlükəsizlik Analitiki (Python)** | Regex və SAST qaydalarının yazılması, xəta aşkarlama mühərriki | `scripts/security_scanner.py` |
| **⚙️ DevOps Mühəndisi (CI/CD)** | GitHub Actions boru xəttinin qurulması, PR bloklama siyasəti | `.github/workflows/security-gate.yml` |
| **📱 İnteqrasiya Tərtibatçısı (Bot)** | Telegram Bot inteqrasiyası, zəngin HTML xəbərdarlıq şablonları | `scripts/telegram_notifier.py` |
| **🎯 Demo & QA Rəhbəri** | Canlı nümayiş ssenarisi, test sandbox faylları | `demo_vulnerabilities/`, `DEMO_GUIDE.md` |

---

## 🚀 Quraşdırma və İstifadə

### 1. Asılılıqları yükləyin:
```bash
pip install -r requirements.txt
```

### 2. Skaneri lokal icra edin:
```bash
# Bütün layihəni skan et
python scripts/security_scanner.py --target .

# Yalnız müəyyən faylı skan et
python scripts/security_scanner.py --target demo_vulnerabilities/vulnerable_sample.py
```

### 3. Telegram Bildirişini test edin:
```bash
python scripts/telegram_notifier.py --report security_report.json --mock
```

---

## 🔒 GitHub Repozitoriyasında Quraşdırma

1. Bu repozitoriyanı GitHub-a `push` edin.
2. Repozitoriyanın **Settings** ➡️ **Secrets and variables** ➡️ **Actions** bölməsinə keçin.
3. 2 sirri əlavə edin:
   - `TELEGRAM_BOT_TOKEN`: @BotFather-dən aldığınız token.
   - `TELEGRAM_CHAT_ID`: Şəxsi və ya qrup Chat ID-niz.
4. Yeni bir branch yaradıb zəif kod əlavə edin və Pull Request açın — sistemin avtomatik işə düşməsini canlı izləyin!

---

Təqdimat və canlı demo üçün addım-addım təlimat [`DEMO_GUIDE.md`](DEMO_GUIDE.md) faylında verilmişdir.
