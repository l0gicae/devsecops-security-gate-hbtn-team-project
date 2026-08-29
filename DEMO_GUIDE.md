# 🎬 DevSecOps Təhlükəsizlik Qapısı: Canlı Demo və Təqdimat Bələdçisi

Bu bələdçi münsiflər, komanda yoldaşları və ya auditoriya qarşısında ekranı paylaşıb **3 dəqiqəlik canlı nümayiş (Live Demo)** keçirmək üçün hazırlanmışdır.

---

## 🎯 Layihənin Əsas Tezisi (Pitch)

> *"Biz kodun təhlükəsizliyini istehsaldan sonra deyil, **birbaşa kod yazılan və GitHub-a göndərilən anda (Shift-Left Security)** təmin edirik. Proqramçı bilərəkdən və ya səhvən sistemə zəif kod və ya sızmış API açarı əlavə edərsə, sistem 0 AZN xərclə anında xətanı tutur, Pull Request-i bloklayır və Telegram-a detallı xəbərdarlıq göndərir."*

---

## 🚀 3 Dəqiqəlik Canlı Nümayiş Ssenarisi

### 1-ci Dəqiqə: Problem və Zəif Kodun Göndərilməsi (Attack / Vulnerability Injection)
1. **Ekranı Paylaşın:** GitHub repozitoriyasını və ya VS Code redaktorunu açın.
2. **Auditoriyaya İzah Edin:** 
   > *"Təsəvvür edin ki, şirkətimizin junior developer-i tələsik kod yazır və koda təhlükəli OpenAI API açarı, SQL Injection və `eval()` daxil edir."*
3. **Əməliyyat:**
   - `demo_vulnerabilities/vulnerable_sample.py` faylını dəyişib yeni branch-ə commit və `Push` edin.
   - GitHub-da yeni **Pull Request (PR)** açın.

---

### 2-ci Dəqiqə: CI/CD Təhlükəsizlik Qapısının İşi (Automated Detection & Blocking)
1. **GitHub Actions Bölməsinə Keçin:**
   - `🛡️ DevSecOps Automated Security Gate` işinin anında başladığını göstərin.
2. **Nəticə:**
   - Təhlükəsizlik skaneri saniyələr içində xətaları aşkarlayır.
   - GitHub Actions workflow-u **🔴 QIRMIZI (Failed)** statusu alır.
   - Pull Request-in birləşdirilməsi (Merge) **avtomatik bloklanır** (`Merging is blocked`).

---

### 3-cü Dəqiqə: Telegram Alert və Xətanın Həlli (Instant Alert & Remediation)
1. **Telegram Kanalını Göstərin:**
   - Botun saniyələr içində göndərdiyi xəbərdarlıq mesajını göstərin:
     - 🔴 `[CRITICAL] OpenAI API Key`
     - 🔴 `[CRITICAL] SQL Injection Riski`
     - 🟠 `[HIGH] Command Injection`
     - Fayl adı, sətir nömrəsi və **həll tövsiyəsi (Fix guide)**.
2. **Kodu Təmizləyin:**
   - Kodu `demo_vulnerabilities/clean_sample.py` ilə əvəz edin və yenidən `git push` edin.
3. **Final Zəfər:**
   - GitHub Actions **🟢 YAŞIL (Passed)** olur, PR-ın birləşdirilməsinə icazə verilir.
   - Telegram-a `✅ UĞURLA KEÇDİ` bildirişi gəlir.

---

## ⚙️ Telegram Botunun Qurulması (1 Dəqiqəlik Quraşdırma)

1. **Telegram-da Bot Yaradın:**
   - `@BotFather`-ə daxil olub `/newbot` əmri ilə yeni bot açın və **API Token**-i kopyalayın.
2. **Chat ID-nizi Əldə Edin:**
   - `@userinfobot`-a daxil olub şəxsi və ya qrup `Chat ID`-nizi öyrənin.
3. **GitHub Secrets-ə Əlavə Edin:**
   - GitHub repozitoriyanızda: `Settings` ➡️ `Secrets and variables` ➡️ `Actions` ➡️ `New repository secret`:
     - `TELEGRAM_BOT_TOKEN`: Bot tokeniniz
     - `TELEGRAM_CHAT_ID`: Chat ID-niz

---

## 💻 Lokal Test Əmrləri (Terminalda Yoxlama)

```powershell
# 1. Zəif nümunəni yoxla (Bloklanmalıdır - Exit Code 1)
python scripts/security_scanner.py --target demo_vulnerabilities/vulnerable_sample.py

# 2. Telegram bildirişini simulyasiya et (Mock rejim)
python scripts/telegram_notifier.py --report security_report.json --mock

# 3. Təmiz kodu yoxla (Keçməlidir - Exit Code 0)
python scripts/security_scanner.py --target demo_vulnerabilities/clean_sample.py
```
