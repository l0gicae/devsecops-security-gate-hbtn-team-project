# 🛡️ VAPT & DevSecOps Pipeline: Müəllim Müdafiə və İmtahan Bələdçisi (Battlecard)

Bu sənəd müəllimin və ya münsiflərin ən kəskin, skeptik və küncə sıxışdıran suallarına **texniki cəhətdən əsaslandırılmış, şişirtməsiz və peşəkar** cavablar vermək üçün hazırlanmışdır.

---

## 1. Texniki İnteqrasiya və Arxitektura Sualları

### Sual 1.1: "Hazır alətləri birləşdirən wrapper-dən başqa sizin yazdığınız kodun payı nədir?"
> **Bizim Dəqiq Cavabımız:**
> *"Müəllim, tamamilə haqlısınız ki, Nmap, Nikto və ya SAST mühərriklərinin hər birinin öz çıxışı var. Lakin sənayedəki əsas problem alətlərin olmaması deyil, onların çıxardığı fərqli formatlı xam məlumatların (raw data) birləşdirilməsi və emalıdır.*
>
> *Bizim sıfırdan yazdığımız əsas mühəndislik payı 4 təməl sütundan ibarətdir:*
> 1. ***Custom AST & Regex Parser Engine (`scripts/security_scanner.py`):*** *Kod bazasındakı xüsusi sızmaları və sintaktik boşluqları analiz edən xüsusi mühərrik.*
> 2. ***Deduplication & Fingerprinting Modulu (`scripts/vapt_normalizer.py`):*** *Müxtəlif alətlərdən gələn tapıntıları `SHA-256(file + line + issue_signature)` ilə heşləyərək təkrarları təmizləyən və CVSS v3.1 bazalı risk skoru hesablayan alqoritm.*
> 3. ***Remediation Patch Generator (`scripts/remediation_engine.py`):*** *Aşkarlanan zəiflikləri birbaşa Git `.patch` faylına və addım-addım Rollback planı olan Playbook-a çevirən generator.*
> 4. ***Telegram Alert Bot və CI/CD Gate:** GitHub Actions hadisələri ilə Telegram API arasında real-vaxt körpüsü.*
>
> *Yəni bizim layihə sadəcə alət çağırmır; xam nəticəni qəbul edir, normallaşdırır, deduplikasiya edir, riskini hesablayır və bərpa üçün hazır patch yaradır."*

---

### Sual 1.2: "Skan mühərrikləri ilə əlaqəni necə qurmusunuz? CLI wrapper-dir, yoxsa API/Daemon səviyyəsində? Eyni anda bir neçə hədəf veriləndə sistem asılı qalacaq (bottleneck)?"
> **Bizim Dəqiq Cavabımız:**
> *"Memarlığımız **Asinxron Event-Driven (Hadisə Əsaslı)** model üzərində qurulub:*
> - *CI/CD mühitində (GitHub Actions) hər bir yoxlama izolyasiya olunmuş müstəqil konteyner/runner daxilində paralel icra olunur.*
> - *Lokal və ya server mühitində isə sistem **Task-Worker** modelini dəstəkləyir (məsələn, Celery/Redis və ya Python-un `asyncio/multiprocessing` hovuzu).*
> - *CLI çağırışları bloklayıcı (blocking) deyil, proseslər ayrı-ayrı worker-lərə ötürülür və nəticələr vahid JSON mesaj növbəsinə (queue) yığılıb asinxron şəkildə normallaşdırılır. Buna görə də eyni anda 10 müxtəlif PR və ya hədəf gəldikdə heç bir bottleneck yaranmır."*

---

### Sual 1.3: "Niyə Nessus və ya OpenVAS olan yerdə Nmap və Nikto-nu ayrıca işlədirsiniz? Bu redundant (artıq) deyilmi?"
> **Bizim Dəqiq Cavabımız:**
> *"Praktiki DevSecOps və Penetration Testing təcrübəsində bu alətlərin məqsədləri və resurs xərcləri tamamilə fərqlidir:*
> - ***Nmap / Fast Port Scan:** İlkin kəşfiyyat (Reconnaissance) mərhələsidir. Saniyələr içində hansı portların açıq olduğunu müəyyənləşdirir və növbəti ağır skanerlərin hədəf sahəsini daraldır.*
> - ***Nikto:** Yüngül, veb server miskonfiqurasiyalarını (köhnə fayllar, təhlükəli HTTP başlıqları) tez yoxlayır.*
> - ***OpenVAS/Nessus:** Çox ağır, dəqiqələrlə (bəzən saatlarla) davam edən tam infrastruktur zəiflik skaneridir. Hər bir kiçik commit-də OpenVAS işə salmaq CI/CD boru xəttini saatlarla dayandırar.*
> - *Bizim yanaşmamız **Çoxpilləli Süzgəc (Tiered Scanning)** prinsipidir: Hər commit-də sürətli yüngül skanlar işləyir, ağır skanlar isə yalnız planlı (məs. gecə saatlarında) işə salınır."*

---

## 2. "Remediation" (Bərpa/Düzəltmə) və AI İddiaları

### Sual 2.1: "Siz həqiqətən 'Remediation' edirsiniz, yoxsa sadəcə tövsiyə mətni çıxarırsınız?"
> **Bizim Dəqiq Cavabımız:**
> *"Biz bilirik ki, kiber təhlükəsizlikdə **'sistemi avtomatik dəyişmək' ən təhlükəli yanaşmadır**, çünki prodakşn xidmətini sıradan çıxara bilər.*
>
> *Buna görə də bizim 'Remediation' mexanizmimiz 2 real mühəndislik mərhələsindən ibarətdir:*
> 1. ***Deterministik Git Patch Faylı (`.patch` / Git Diff):*** *Məsələn, aşkar edilən zəif SQL sorğusunun təhlükəsiz parameterized versiyasını `git apply` edilə biləcək diff faylı kimi generasiya edirik.*
> 2. ***Təhlükəsizlik Playbook-u:*** *Hər tapıntı üçün 'Səbəb', 'Düzəliş addımı', 'Yoxlama testi' və ən əsası **'Rollback (Geri Qaytarma)'** təlimatı hazırlayırıq.*
>
> *Yəni biz sadəcə quru mətn vermirik; tərtibatçının birbaşa tətbiq edə biləcəyi hazır kod düzəlişini (patch) və bərpa planını təqdim edirik."*

---

### Sual 2.2: "Avtomatik remediation etsəniz, prodakşn mühitini çökdürməyəcəyinizə necə zəmanət verirsiniz?"
> **Bizim Dəqiq Cavabımız:**
> *"Məhz bu səbəbdən sistemimiz **'Zero Unverified Production Mutation'** prinsipi ilə işləyir:*
> - *Düzəlişlər birbaşa canlı serverə (prodakşn) tətbiq olunmur.*
> - *Düzəliş **Git Branch / Pull Request** səviyyəsində `.patch` kimi təklif edilir.*
> - *Hər bir təklif olunan patch layihənin mövcud vahid testlərindən (Unit/Integration Tests) keçməlidir.*
> - *Hər bir Playbook daxilində **Rollback Procedure (Geri Qaytarma Proseduru)** təyin olunur. Əgər tətbiq olunan düzəliş hər hansı asılılığı pozarsa, bir əmrlə (`git checkout / git apply -R`) əvvəlki stabil vəziyyətə qayıdılır."*

---

### Sual 2.3: "Süni intellekt (AI) burada konkret hansı riyazi/məntiqi işi görür? Yoxsa sadəcə OpenAI API-nə prompt atıb cavab alırsınız?"
> **Bizim Dəqiq Cavabımız:**
> *"Biz layihədə 'AI' sözündən ucuz marketinq və buzzword kimi istifadə etmirik.*
>
> *Bizim sistemdə zəifliklərin aşkarlanması **Deterministik Alqoritmlər (AST Syntax Trees, Regex, Fingerprint hashing və CVSS v3.1 riyazi çəki formulu)** üzərində qurulub. Çünki təhlükəsizlikdə determinizm və təkrarolunanlıq (reproducibility) şərtdir.*
>
> *AI (LLM) isə yalnız **Kontekstual Remediation Playbook-larının** tərtib edilməsində (məsələn, layihənin spesifik çərçivəsinə - Django/FastAPI/Flask uyğunlaşdırılmış izahat və test ssenarisi yazılmasında) köməkçi modul kimi istifadə olunur. Əsas qərarverici və bloklayıcı mexanizm isə 100% deterministik riyazi qaydalarla işləyir."*

---

## 3. Bazar və Rəqabət (Value Proposition)

### Sual 3.1: "Qualys, Nessus, Rapid7 və ya DefectDojo varkən şirkət niyə sizin həlli işlətsin?"
> **Bizim Dəqiq Cavabımız:**
> *"Qualys və Nessus on minlərlə dollar lisenziya haqqı olan böyük korporativ infrastruktur alətləridir və kiçik/orta şirkətlər və ya startaplar üçün həddindən artıq bahalı və mürəkkəbdir.*
>
> *DefectDojo isə nəhəng bir zəiflik idarəetmə bazasıdır, lakin onun daxilində hazır, yüngül CI/CD Təhlükəsizlik Qapısı, avtomatik Git patch generasiyası və anında Telegram insident alerti yoxdur.*
>
> *Bizim təqdim etdiyimiz dəyər:*
> 1. ***0 AZN Maliyyə Xərci:*** *Tamamilə açıq mənbəli və pulsuz infrastruktura əsaslanır.*
> 2. ***Shift-Left İnteqrasiyası:*** *Təhlükəsizliyi aylıq auditlər yerinə hər bir commit/PR səviyyəsinə endirir.*
> 3. ***Single-Pane-of-Glass Sadəliyi:*** *Qarışıq 50 səhifəlik PDF yerinə dərhal developer-in başa düşəcəyi 1 ekranlıq VAPT Dashboard və Telegram bildirişi verir."*

---

### Sual 3.2: "False Positive-ləri (yalançı həyəcan siqnallarını) necə təmizləyirsiniz?"
> **Bizim Dəqiq Cavabımız:**
> *"False Positive-ləri idarə etmək üçün **3 səviyyəli süzgəc mühərriki (`scripts/vapt_normalizer.py`)** tətbiq etmişik:*
> 1. ***Fingerprinting & Context Filtering:*** *Məsələn, şərh sətirlərindəki (`#`, `//`) və ya test/mock qovluqlarındakı kodlar SAST analizindən avtomatik kənarlaşdırılır.*
> 2. ***Deduplication Hashing:*** *Eyni xətanı bir neçə qayda tutduqda `hash(file + line + cwe)` üzrə unikal tapıntı saxlanılır, dublikatlar birləşdirilir.*
> 3. ***Severity & Confidence Threshold:*** *Yalnız **High** və **Critical** dərəcəli, etibarlılıq əmsalı (Confidence) yüksək olan insidentlər üçün CI/CD bloklanır. Medium/Low dərəcəlilər isə bloklamadan yalnız hesabatda qeyd olunur."*

---

## 📋 1 Dəqiqəlik Xülasə Müdafiə Cədvəli

| Müəllimin Şübhəsi | Bizim Güclü Tərəfimiz | İstifadə Olunan Texniki Konsept |
| :--- | :--- | :--- |
| **"Sadəcə Wrapper-dir"** | Xüsusi AST Parser, Normalizer, Deduplicator və Patch Generator yazılıb | `AST`, `SHA-256 Fingerprinting`, `CVSS v3.1` |
| **"Asinxronluq / Bottleneck"** | Event-driven GitHub Actions Runner və Asinxron Queue modeli | `Event-Driven Architecture`, `Task Queue` |
| **"Redundant Alətlər"** | Çoxpilləli süzgəc (Fast Recon vs Deep SAST) | `Tiered Multi-Stage Scanning` |
| **"Saxta Remediation"** | Prodakşna toxunmadan Git `.patch` faylı və Rollback Playbook-u yaradılır | `Git Patch Diff`, `Rollback Playbook` |
| **"Buzzword AI"** | Əsas mühərrik deterministik riyaziyyatdır, AI yalnız köməkçi izahat üçündür | `Deterministic Security Gate` |
| **"False Positives"** | Kontekst süzgəci, deduplication və severity threshold | `Noise Reduction Engine` |
