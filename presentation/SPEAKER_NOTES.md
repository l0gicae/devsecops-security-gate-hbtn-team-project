# 🎙️ DevSecOps Təhlükəsizlik Qapısı: Spiker Çıxış Mətni və Slayd Təlimatı

Bu sənəd slaydları (`presentation/slides.html`) nümayiş etdirərkən hər bir slaydda **nə danışmalı olduğunuzu** cümləbəcümlə göstərir.

---

### 🖥️ Slaydı Necə Açmalı və İdarə Etməli?
1. [`presentation/slides.html`](file:///c:/Users/Aphentes/Documents/qilberton%20final%20osduraq%20project/presentation/slides.html) faylını brauzerdə açın.
2. **Klaviatura Düymələri:**
   - **`Sağ Ox` və ya `Space`:** Növbəti slayda keçid
   - **`Sol Ox`:** Əvvəlki slayda qayıdış
   - **`F`:** Tam ekran (Fullscreen) rejimi
   - **`S`:** Spiker qeydlərini ekranda açıb-bağlamaq

---

## 🗣️ Slayd-ba-Slayd Çıxış Mətni (3-4 Dəqiqəlik Nitq)

### Slayd 1: Başlıq (Cover Slide)
> *"Hörmətli münsiflər və dinləyicilər, hər birinizi salamlayırıq!*
> *Bu gün sizə müasir proqram təminatı mühəndisliyində ən kritik məsələlərdən birini həll edən **'Avtomatlaşdırılmış DevSecOps Təhlükəsizlik Qapısı'** layihəmizi təqdim edirik.*
> *Layihəmizin əsas məqsədi — kod bazasına bilərəkdən və ya səhvən sızmış API açarlarını və kritik zəiflikləri **0 AZN xərclə**, GitHub səviyyəsində anında bloklamaq və komandaya real-vaxt Telegram xəbərdarlığı göndərməkdir."*

---

### Slayd 2: Problem və Real Dünya Təhlükəsi
> *"Gəlin problemin mahiyyətinə baxaq. Ənənəvi kiber təhlükəsizlikdə şirkətlər proqramı yazıb bitirəndən sonra və ya ayda bir dəfə audit edirlər. Lakin bu artıq çox gecdir!*
> *Təcrübəsiz və ya tələsən proqramçı koda OpenAI API açarı, AWS şifrəsi və ya SQL Injection zəifliyi qoyub GitHub-a göndərdiyi anda xakerlər botlarla həmin açarları saniyələr içində ələ keçirir və şirkətə minlərlə dollar ziyan vurur."*

---

### Slayd 3: Həll Yolu və Shift-Left Arxitekturası
> *"Biz təhlükəsizliyi ən başa — proqramçının kod yazdığı ana gətiririk (yəni Shift-Left Security).*
> *Sistem necə işləyir?*
> 1. *Proqramçı kodu GitHub-a push edir və ya Pull Request açır.*
> 2. *GitHub Actions boru xətti 3 saniyə ərzində avtomatik işə düşür.*
> 3. *Əgər kodda təhlükə varsa, sistem PR-ı anında qırmızı xəta ilə bloklayır (Merge dayandırılır).*
> 4. *Saniyələr içində təhlükəsizlik komandasına və müəllifə Telegram bildirişi çatır: 'Filan faylın 14-cü sətrində açar sızıb, düzəldin!'."*

---

### Slayd 4: Texniki Mühərriklər (Core Engineering)
> *"Bəs kapronun altında hansı mühəndislik işi yatır?*
> *Biz sadəcə hazır alətləri çağıran wrapper deyilik. Biz sıfırdan 3 əsas modul yazmışıq:*
> 1. ***Custom AST & Regex Parser:** Python sintaktik ağacını analiz edərək SQL Injection, eval() və 8 növ gizli açarı tutur.*
> 2. ***Deduplication Mühərriki:** SHA-256 heşləmə ilə təkrarlanan xətaları təmizləyir və səs-küyü (noise) azaldır.*
> 3. ***CVSS v3.1 Scoring:** Riyazi çəki formulu ilə layihənin real risk dərəcəsini hesablayır."*

---

### Slayd 5: Deterministik Bərpa (Remediation & Rollback)
> *"Ən vacib məqam: Biz canlı prodakşn mühitinə kor-koranə müdaxilə etmirik. Çünki bu xidməti çökdürə bilər.*
> *Bunun əvəzinə sistemimiz developer üçün `git apply` edilə bilən hazır **Git Diff `.patch` faylı** və hər hansı problem olarsa bir əmrlə əvvəlki vəziyyətə qayıtmaq üçün **Rollback (Geri Qaytarma)** planı hazırlayır."*

---

### Slayd 6: Single-Pane-of-Glass VAPT Dashboard
> *"Tərtibatçılar üçün 50 səhifəlik quru PDF hesabatları oxumaq çətindir.*
> *Buna görə də biz brauzerdə tək kliklə açılan müasir, qaranlıq interfeysli **Single-Pane-of-Glass VAPT Dashboard** hazırlamışıq. Burada risk qrafikləri, CWE bölgüsü və tək toxunuşla yüklənə bilən patch-lər əks olunur."*

---

### Slayd 7: Bazar Rəqabəti və Biznes Dəyəri
> *"Bəs niyə şirkətlər Qualys, Nessus və ya DefectDojo əvəzinə bizim sistemi seçməlidir?*
> - *Qualys və Nessus illik 15-20 min dollar tələb edir və CI/CD inteqrasiyası ağırdır.*
> - *DefectDojo passiv verilənlər bazasıdır.*
> - *Bizim sistem isə **0 AZN xərclə**, tam açıq mənbəli baza üzərində saniyəlik bloklama və Telegram alerti təqdim edir."*

---

### Slayd 8: Komanda və Yekun (Q&A)
> *"Komandamızda rollar aydın bölünüb: Təhlükəsizlik analitiki qaydaları yazıb, DevOps mühəndisi CI/CD boru xəttini qurub, İnteqrasiya tərtibatçısı isə Telegram Bot və Dashboard interfeysini hazırlayıb.*
> *Diqqətiniz üçün təşəkkür edirik! İndi isə canlı demo nümayişinə və suallarınızı cavablandırmağa hazırıq!"*
