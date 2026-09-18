# CodeShield AI

**Find it, fix it, prove it.**

A code security scanner that does not stop at the alert. Every finding ships with an explanation, a concrete fix, and a generated regression test built to **fail on the vulnerable version and pass on the patched one**.

🔗 **Live site — [codeshield-app.github.io](https://codeshield-app.github.io/)**

Built for the **Tuwaiq Academy × SAIF** program by **Lamis Alanazi**.

---

## Why this exists

Mature scanners — Snyk, SonarQube, CodeQL, Copilot Autofix — detect vulnerabilities well and often suggest a patch. None of them hand you proof that the patch actually closed the hole, or that the same flaw will not quietly return three commits later.

That gap between *flagged* and *fixed* is what CodeShield addresses. The generated test is the receipt.

A second gap: no major security tool explains findings in Arabic for Arabic-speaking development teams. CodeShield's entire interface and every explanation exist in full Arabic and English.

## What it does today (v0.1)

| | |
|---|---|
| Detection rules | 9, each mapped to a CWE identifier and an OWASP Top 10 (2021) category |
| Languages recognised | Python, JavaScript, PHP, Ruby, Shell |
| Per finding | Why it is dangerous · a concrete fix · a generated verification test |
| Interface | Full Arabic and English (RTL/LTR) |
| Report export | JSON |
| Where it runs | Entirely in the browser — **source code never leaves the machine** |

### Rules shipped in v0.1

| Rule | CWE | Severity |
|---|---|---|
| SQL Injection | CWE-89 | High |
| Command / Code Injection | CWE-78 | High |
| Cross-Site Scripting (XSS) | CWE-79 | High |
| Hardcoded Credentials | CWE-798 | High |
| Insecure Deserialization | CWE-502 | High |
| TLS Verification Disabled | CWE-295 | High |
| Weak Hashing Algorithm | CWE-327 | Medium |
| Weak Randomness for a Security Value | CWE-338 | Medium |
| Unrestricted File Upload | CWE-434 | Medium |

## Scope and honest limits

This matters more than a feature list, so it is stated plainly:

- **v0.1 contains no machine-learning model.** The engine is deterministic pattern matching. This was a deliberate choice: the same code always produces the same finding, every result traces back to an explicit rule, and no vulnerability is ever hallucinated. In a security tool, being quietly wrong is worse than being narrow.
- **The engine works line by line.** It does not follow data flow across statements, so a vulnerability split over several lines can be missed.
- **The Simulation screen is an illustrative mock-up**, labelled as such throughout. It shows how repository-wide monitoring would look, using fixed sample data. The **Live Scanner** is the working engine and is what should be evaluated.
- **No benchmark results are claimed yet.** Validation against a public suite is the next milestone.

## Roadmap

- **v0.2** — AST parsing, to follow data flow across lines
- **v0.3** — measured against the OWASP Benchmark and NIST Juliet suites, publishing detection rate and false-positive rate
- **v1.0** — a language model drafts the fix, with the rule engine kept as the verification gate

## Running it

No build step, no dependencies, no server.

```bash
git clone https://github.com/codeshield-app/codeshield-app.github.io.git
cd codeshield-app.github.io
open index.html      # or just double-click it
```

Or simply open **[codeshield-app.github.io](https://codeshield-app.github.io/)**.

## License

© 2026 Lamis Alanazi. All rights reserved. See [LICENSE](LICENSE).

---
---

<div dir="rtl">

# كودشيلد AI

**اكتشفها، أصلحها، أثبت الإصلاح.**

فاحص أمني للشيفرة البرمجية لا يتوقف عند التنبيه. كل ثغرة يكتشفها تأتي مع شرح لسبب خطورتها، وإصلاح ملموس، واختبار انحدار مُولَّد مصمَّم **ليفشل على النسخة المصابة وينجح على النسخة المُصلَحة**.

🔗 **الموقع المباشر — [codeshield-app.github.io](https://codeshield-app.github.io/)**

مشروع لبرنامج **أكاديمية طويق × SAIF**، إعداد **لميس العنزي**.

## لماذا هذا المشروع

الأدوات الناضجة — Snyk وSonarQube وCodeQL وCopilot Autofix — تكتشف الثغرات بكفاءة وغالبًا تقترح إصلاحًا. لكن لا واحدة منها تعطيك دليلًا على أن الإصلاح أغلق الثغرة فعلًا، ولا على أنها لن تعود بصمت بعد ثلاثة تعديلات.

هذه الفجوة بين «مُبلَّغ عنها» و«مُصلَحة» هي ما يعالجه كودشيلد. والاختبار المُولَّد هو الإيصال.

وفجوة ثانية: لا توجد أداة أمان كبرى تشرح الثغرات بالعربية لفرق التطوير العربية. واجهة كودشيلد وكل شروحاته متوفرة بعربية وإنجليزية كاملتين.

## ما الذي يعمل اليوم (v0.1)

| | |
|---|---|
| قواعد الاكتشاف | ٩ قواعد، كل واحدة مربوطة بمعرّف CWE وتصنيف OWASP العشرة (٢٠٢١) |
| اللغات المدعومة | بايثون، جافاسكربت، PHP، روبي، الشِل |
| لكل ثغرة | سبب الخطورة · إصلاح ملموس · اختبار تحقّق مُولَّد |
| الواجهة | عربية وإنجليزية كاملة (RTL/LTR) |
| تصدير التقرير | JSON |
| مكان التشغيل | داخل المتصفح بالكامل — **الشيفرة لا تغادر جهاز المستخدم** |

## النطاق والحدود بصراحة

هذا القسم أهم من قائمة المزايا، ولذلك يُذكر صراحةً:

- **النسخة v0.1 لا تحتوي على نموذج تعلّم آلي.** المحرك قائم على مطابقة أنماط حتمية، وهذا اختيار مقصود: الكود نفسه يعطي النتيجة نفسها دائمًا، وكل نتيجة تُتتبَّع إلى قاعدة صريحة، ولا تُختلَق أي ثغرة. في أداة أمان، الخطأ الصامت أسوأ من النطاق المحدود.
- **المحرك يعمل سطرًا بسطر.** لا يتتبّع تدفّق البيانات عبر الجُمل البرمجية، لذا قد تفوته ثغرة موزّعة على عدة أسطر.
- **شاشة المحاكاة نموذج توضيحي**، وهي موسومة بذلك في كل موضع. تعرض كيف ستبدو مراقبة مستودع كامل ببيانات عيّنة ثابتة. أما **الفاحص المباشر** فهو المحرك العامل، وهو ما ينبغي تقييمه.
- **لا يُدَّعى تحقيق أي نتائج قياسية بعد.** القياس على مجموعة معيارية عامة هو المحطة التالية.

## خارطة الطريق

- **v0.2** — تحليل AST لتتبّع تدفّق البيانات عبر الأسطر
- **v0.3** — قياس على مجموعتي OWASP Benchmark وNIST Juliet مع نشر معدّل الاكتشاف ومعدّل الإيجابيات الكاذبة
- **v1.0** — نموذج لغوي يصيغ الإصلاح، مع إبقاء محرك القواعد بوابةً للتحقق

## التشغيل

بدون خطوات بناء، وبدون اعتماديات، وبدون خادم — يكفي فتح ملف `index.html`، أو زيارة [codeshield-app.github.io](https://codeshield-app.github.io/).

## الترخيص

© ٢٠٢٦ لميس العنزي. جميع الحقوق محفوظة.

</div>
