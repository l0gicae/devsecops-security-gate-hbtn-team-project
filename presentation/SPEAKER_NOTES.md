# 🎙️ DevSecOps Təhlükəsizlik Qapısı: Spiker Çıxış Mətni və Slayd Təlimatı

Bu sənəd slaydları (`presentation/slides.html`) nümayiş etdirərkən hər bir slaydda **nə danışmalı olduğunuzu** cümləbəcümlə göstərir.

---

### 🖥️ Slaydı Necə Açmalı və İdarə Etməli?
1. [`presentation/slides.html`](slides.html) faylını brauzerdə açın.
2. **Klaviatura Düymələri:**
   - **`Sağ Ox` və ya `Space`:** Növbəti slayda keçid
   - **`Sol Ox`:** Əvvəlki slayda qayıdış
   - **`F`:** Tam ekran (Fullscreen) rejimi
   - **`S`:** Spiker qeydlərini ekranda açıb-bağlamaq

---

## 🗣️ Slayd-ba-Slayd Çıxış Mətni (3-4 Dəqiqəlik Nitq)

### Slayd 1: Cover Slide
> *"Hörmətli münsiflər və dinləyicilər, hər birinizi salamlayırıq!*
> *Bu gün sizə müasir proqram təminatı mühəndisliyində ən kritik məsələlərdən birini həll edən **'Avtomatlaşdırılmış DevSecOps Təhlükəsizlik Qapısı'** layihəmizi təqdim edirik.*
> *Layihəmizin əsas məqsədi — kod bazasına bilərəkdən və ya səhvən sızmış API açarlarını və kritik zəiflikləri **0 AZN xərclə**, GitHub səviyyəsində anında bloklamaq və komandaya real-time Telegram alert göndərməkdir."*

---

### Slayd 2: Threat Landscape & Risk
> *"Gəlin problemin mahiyyətinə baxaq. Ənənəvi kiber təhlükəsizlikdə şirkətlər proqramı yazıb bitirəndən sonra və ya ayda bir dəfə audit edirlər. Lakin təhlükəsizliyi production-da yoxlamaq artıq çox gecdir!*
> *Təcrübəsiz və ya tələsən proqramçı koda OpenAI API key, AWS Token və ya SQL Injection zəifliyi qoyub GitHub-a push etdiyi anda botlar həmin açarları saniyələr içində ələ keçirir və şirkətə minlərlə dollar ziyan vurur."*

---

### Slayd 3: Shift-Left Architecture & Pipeline Flow
> *"Biz təhlükəsizliyi ən başa — proqramçının kod yazdığı ana gətiririk (yəni Shift-Left Security).*
> *Sistem necə işləyir?*
> 1. *Proqramçı kodu GitHub-a push edir və ya Pull Request açır.*
> 2. *GitHub Actions pipeline-ı 3 saniyə ərzində avtomatik işə düşür.*
> 3. *Əgər kodda təhlükə varsa, sistem PR-ı anında qırmızı xəta ilə bloklayır (PR Merge dayandırılır).*
> 4. *Saniyələr içində təhlükəsizlik komandasına və müəllifə Telegram alert çatır: 'Filan faylın 14-cü sətrində açar sızıb, düzəldin!'."*

---

### Slayd 4: Under the Hood (Core Engineering)
> *"Bəs sistemin daxilində (Under the Hood) hansı mühəndislik işi yatır?*
> *Biz sadəcə hazır alətləri çağıran wrapper deyilik. Biz sıfırdan 3 əsas modul yazmışıq:*
> 1. ***Custom AST & Regex Engine:** Python sintaktik ağacını analiz edərək SQL Injection, eval() və 8 növ gizli açarı tutur.*
> 2. ***Deduplication Engine:** SHA-256 heşləmə ilə təkrarlanan xətaları təmizləyir və səs-küyü (noise) azaldır.*
> 3. ***CVSS Risk Scoring:** Riyazi çəki formulu ilə layihənin real risk dərəcəsini hesablayır."*

---

### Slayd 5: Deterministic Remediation & Automated Rollback
> *"Ən vacib məqam: Biz canlı production mühitinə kor-koranə müdaxilə etmirik (Zero Unverified Production Mutation).*
> *Bunun əvəzinə sistemimiz developer üçün `git apply` edilə bilən hazır **Git Diff `.patch` faylı** və hər hansı problem olarsa bir əmrlə əvvəlki stabil commit-ə qayıtmaq üçün **Automated Rollback** planı hazırlayır."*

---

### Slayd 6: Single-Pane-of-Glass VAPT Dashboard
> *"Tərtibatçılar üçün 50 səhifəlik quru PDF hesabatları oxumaq çətindir.*
> *Buna görə də biz brauzerdə tək kliklə açılan müasir, qaranlıq interfeysli **Single-Pane-of-Glass VAPT Dashboard** hazırlamışıq. Burada CVSS Risk Heatmap, CWE & OWASP bölgüsü, unikal fingerprint və tək kliklə patch export əks olunur."*

---

### Slayd 7: Market Comparison & Value Proposition
> *"Bəs niyə şirkətlər Qualys, Nessus və ya DefectDojo əvəzinə bizim sistemi seçməlidir?*
> - *Qualys və Nessus illik 15-20 min dollar tələb edir və CI/CD inteqrasiyası ağırdır.*
> - *DefectDojo passiv verilənlər bazasıdır.*
> - *Bizim sistem isə **0 AZN xərclə**, tam open source baza üzərində saniyəlik PR blocking gate və real-time Telegram alert təqdim edir."*

---

### Slayd 8: Conclusion & Team (Q&A)
> *"Komandamızda rollar aydın bölünüb: Security Analyst qaydaları yazıb, DevOps Engineer CI/CD pipeline-nı qurub, Integration Developer isə Telegram Bot və Dashboard interfeysini hazırlayıb.*
> *Diqqətiniz üçün təşəkkür edirik! İndi isə canlı demo nümayişinə və suallarınızı cavablandırmağa hazırıq!"*
