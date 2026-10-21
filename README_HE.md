<div dir="rtl">

# NetSec - דשבורד פורנזי של Wireshark + ML

> גרסה עברית של [`README.md`](README.md).

דשבורד פורנזי של Wireshark PCAPNG בנוי על Dash + scikit-learn + PyTorch.
טוען עד שני sessions של הקלטה (S1 / S2), מריץ IsolationForest, DBSCAN,
LSTM, ושתי שכבות של חוקים דטרמיניסטיים במקביל, ואז מרנדר עשרות
צ'ארטים על פני 9 סקשני ניווט (הקלטה חיה, ניתוח, פרופיל התקן,
ניתוח גלישה, אבטחה, השוואה, מצאי, תעבורה חיצונית, כיסוי).

## מה הוא עושה

- קורא הקלטות `.pcapng` מהדיסק או מקליט תעבורה חיה דרך `tshark`.
- מחלץ פיצ'רים פר-IP (ספירת פקטות, נפח בייטים, גודל פקטה ממוצע,
  יעדים ייחודיים, ספירות SYN / RST, ציון burst, שליטה).
- מריץ שלושה מודלי ML במקביל:
  - **‏IsolationForest** - זיהוי outlier פר-IP; ‏contamination
    קבוע ב-0.10 עם `n_estimators=200, random_state=42`. (סריקת
    seed-stability קודמת נמדדה מול ground truth מתויג והתאימה
    ל-F1 של 0.10 הקבוע במחיר של פי-15 fits של היער - הסריקה
    נגרסה.)
  - **‏DBSCAN** - אשכול התנהגותי, ‏IPs שאינם באף אשכול מסומנים.
  - **‏LSTM** - זיהוי אנומליה זמנית על מקבצי שנייה של גודל-פקטה
    שמולאו באפסים, מסומנים כששגיאת החיזוי חורגת מ-`val_mean + 2σ`
    (שווה-ערך בפועל ל-`quantile_0.95`). **‏LSTM מתאמן רק על
    הקלטות עם ≥20 מקבצי-זמן שמישים** (‏SEQ_LEN=10 מותיר 10 חלונות
    גולשים, הרצפה); הקלטות קצרות יותר מדלגות עליו בשקט, והחוקים
    הדטרמיניסטיים מכסים אותן.
- מריץ שתי שכבות של חוקים דטרמיניסטיים - **סוס העבודה של הזיהוי**:
  זיהוי סריקות TCP SYN / FIN / NULL / Xmas, חוק הצפת SYN אגרגטיבי
  עם מקור מזויף, ואותות ARP-spoofing / DNS-amplification /
  ‏DNS-tunneling. במדידה מול ground truth המתויג, החוקים תופסים
  100% מהתוקפים המתויגים בכל קובץ PCAP של תקיפה - תפקיד שכבת ה-ML
  הוא למצוא outliers שהחוקים לא כבר סימנו, לא לשחזר אותם.
- ציון ה-**fusion** (סקשן `Advanced threats`) הוא קורלציה ברמת
  ההתקן של חמשת המנועים המתקדמים (‏beaconing, ‏DNS tunneling, ‏DGA,
  ‏ARP/DHCP, ‏TLS) בתוך חלון של 15 דקות - הוא מכוון לתבניות
  stealth בסגנון APT ולא יידלק על הקלטות הסריקה/הגברה הרועשות
  בסט ה-ground-truth. זה העיצוב, לא פער.
- מסווג כל התקן שנצפה לאחת מ-12 קטגוריות באמצעות מנוע בן 3 שכבות
  (חוקי hostname / OUI / port → fingerprints של DNS → היוריסטיקות
  התנהגותיות).
- מרנדר השוואה side-by-side של S1 מול S2 ברגע ש-session שני נטען.

## קבצים בריפו הזה

| נתיב | מטרה |
|---|---|
| `app/Network_Security_Dashboard.ipynb` | דשבורד בקובץ יחיד - 50 תאים (25 קוד, 25 markdown), הדבר היחיד שאתם צריכים להריץ. כולל חמישה מנועי איום מתקדמים (‏beaconing, ‏DNS tunneling, ‏DGA, ‏ARP/DHCP, ‏TLS) בתוספת שלב **fusion** שנותן ציון לכל התקן על ידי קורלציה של hits של המנועים בחלון של 15 דקות (לא מנוע שישי - נותן ציון על גבי החמישה) |
| `app/dashboard_module.py` | ייצוא `.py` אוטומטי של ה-notebook לבדיקות / imports - מתחולל מחדש על ידי `tools/export_dashboard_module.py`, אל תערכו ידנית |
| `app/cloud_ranges.json` | טווחי CIDR → חיפוש ספק ענן |
| `app/device_rules.json` | 261 חוקי hostname / OUI / port לסיווג התקנים |
| `app/dns_fingerprints.json` | 217 fingerprints של DNS להסקת סוג התקן התנהגותית |
| `attack_tests/` | 5 PCAPs של תקיפות אמיתיות + צינור רגרסיה של CLI |
| `tests/` | סוויטת רגרסיה של pytest מול ground truth מתויג |
| `llm_judge/` | **אופציונלי** notebook triage עצמאי של LLM-as-Judge - ממזג את כל אותות המגלים לפסיקה מדורגת ומוסברת אחת לכל מועמד. הדשבורד רץ באופן מלא בלעדיו; ראו `llm_judge/README.md` |
| `companion/` | ‏AI Companion - צ'אט Dash מעל Ollama מקומי (streaming, תגובות markdown, כפתור עצירה, הגדרות פר-צ'אט). רץ על ה-VM כ-`netsec-companion.service`; אותו קובץ עובד ממחשב נייד דרך SSH tunnel. ראו `companion/README.md` |
| `tools/netsec_rag.py` + `tools/netsec_rag_web.py` | ‏QA מועשר-אחזור על ארכיון הדוחות + קבצים שרירותיים מאונדקסים. ‏Ollama embeddings, ‏SQLite vector store, ‏Dash UI streaming שבנוי כמו Companion. רץ על ה-VM כ-`netsec-rag.service` |
| `server/` | מערך VM של analyzer - ‏API של קליטה חתומה, ‏worker, ‏retention, ‏notify. מריץ את צינור הזיהוי המדויק של הדשבורד על VM קטן שבשליטתכם |
| `deploy/` | ‏Docker Compose + Dockerfiles + Caddyfile + יחידות systemd + סקריפטים להתקנה למערך ה-VM כולו. ראו `deploy/README.md` ל-quick start של VM טרי |
| `docs/ARCHITECTURE.md` | מפת end-to-end: מה רץ איפה, פורטים, פרסיסטנטיות, זרימת נתונים דרך המערך |
| `docs/SECURITY_MODEL.md` | מי יכול להגיע לאיפה, איזה auth שומר על כל שירות, אילו איומים מנוטרלים ואילו לא |
| `tools/upload_pcap.py` | ‏CLI של העלאה חתומה-HMAC - מזרים PCAP ל-`/v1/pcap` של ה-VM עם `--email <address>` לדוח |
| `requirements.txt` | תלויות Python קפואות |
| `docs/MODELS.md` | רפרנס לשלושת מודלי ה-ML ולפרמטרים שלהם |
| `docs/LLM_INTERFACE.md` | ה-prompt המדויק, ‏blob המועמד, וסכמת ה-verdict שנשלחים לכל שופט LLM - מה המודל בפועל רואה פר-מועמד |
| `docs/LLM_PANEL_ROLE.md` | למה פאנל ה-LLM קיים בכלל - הפערים הספציפיים שהוא ממלא שחוקים דטרמיניסטיים ו-ML לא יכולים, ארגז הכלים שלו, ומעקות הבטיחות שלו |
| `docs/VM_DEPLOYMENT.md` | העמדת VM ה-analyzer 24/7 על קופסת ARM חינמית של Oracle מעל Tailscale |
| `docs/VM_OPS.md` | פעולות יומיומיות על ה-VM (תמונת מצב בריאות, redeploy, גיבויים, הפעלת אימייל + פאנל, סבב sensor) |
| `docs/` | תיעוד מעמיק (הדרכה cell-by-cell, שאלות ותשובות, איזוני עיצוב, גרפי החלטות) |

## איך להריץ על מחשב נייד

1. התקינו Wireshark (מספק `tshark` ו-`mergecap`):
   - Windows: <https://www.wireshark.org/download.html>
2. תלויות Python: ‏`pip install -r requirements.txt` (ה-notebook עדיין
   מתקין אוטומטית חבילות חסרות כ-fallback למכונות טריות).
3. פתחו את `app/Network_Security_Dashboard.ipynb` ב-Jupyter.
4. **‏Kernel → Restart Kernel → Run All**.
5. פתחו את ה-URL שהתא האחרון מדפיס (בוחר אוטומטית את הפורט הפנוי
   הראשון בטווח 8050-8099).
6. ‏Welcome → סמנו את תיבת האישור → ‏Continue → השליכו PCAPNG
   (או הדביקו path מלא) → **לחצו Load** → כרטיס staging מופיע עם
   הקובץ → **לחצו ▶ Analyze** → דשבורד.
   (‏Load רק מאמת ו-stages את הקובץ; הניתוח בפועל רץ רק כשלוחצים
   ▶ Analyze על כרטיס ה-staging. אותה זרימה דו-שלבית מונעת מ-path
   שהוקלד שגוי להפעיל ריצה ארוכה.)
7. מהדשבורד, **+ Load second PCAP** בסרגל הצד מוסיף את sessionS2
   להשוואה (אותה זרימת Load → ‏▶ Analyze של staging).

**טיפ ל-Windows - נתיבים עם תווים לא-ASCII** (עברית, קירילית, ‏CJK,
תווים מוטעמים בשם התיקייה): הפעילו את Python עם `PYTHONUTF8=1`
(או הריצו `python -X utf8 …`) כדי שהדפסות לקונסולה לא יפלו על
`cp1255`/`cp1252`. נתיבי ASCII רגילים לא צריכים את זה. דוגמה:

```powershell
$env:PYTHONUTF8=1; jupyter notebook
```

## פריסת תיקיות

```
NetSec-Dashboard-Wireshark-Unsupervised-Anomaly-Detection/
├── README.md
├── requirements.txt                        ← תלויות Python קפואות
├── app/                                    ← כל מה שאתם מריצים, בתיקייה אחת
│   ├── Network_Security_Dashboard.ipynb    ← ה-notebook הראשי
│   ├── dashboard_module.py                 ← ייצוא .py אוטומטי (לבדיקות/imports)
│   ├── cloud_ranges.json                   ← נתונים תומכים
│   ├── device_rules.json
│   └── dns_fingerprints.json
├── attack_tests/                           ← 5 PCAPs של תקיפות אמיתיות + צינור CLI + ground truth מתויג
├── tests/                                  ← סוויטת רגרסיה של pytest מול ground truth מתויג
├── llm_judge/                              ← אופציונלי: ‏notebook triage עצמאי של LLM-as-Judge (README משלו)
├── companion/                              ← אופציונלי: ‏צ'אט דפדפן עם מודלי Ollama המקומיים של ה-VM (README משלו)
├── tools/                                  ← export_dashboard_module.py (סנכרון notebook → .py)
└── docs/                                   ← MODELS.md + מסמכי עומק + גרפי החלטות + LLM_JUDGE_SPEC.md
```

ה-notebook מאתר את קבצי ה-JSON של הנתונים אוטומטית בין אם אתם מפעילים
מ-`app/` (Jupyter) או משורש הריפו (VS Code), אז אתם לא צריכים להעביר
כלום כדי להריץ.

## ארכיטקטורה (הקמה 24/7 פעילה תמיד)

הפריסה הפעילה-תמיד חיה על VM ARM קטן של Oracle Always Free שנגיש
בלעדית דרך Tailscale. הכל יושב מאחורי URL אחד עם login אחד:

```
https://netsec-agent.<your-tailnet>.ts.net/         portal
                                          /rag/     RAG QA על הארכיון
                                          /chat/    AI Companion (קבצים+צ'אט)
http://netsec-agent:8766                            Ingest API (HMAC)
http://netsec-agent:5678                            n8n workflows (login משלו)
```

‏Caddy מכסה את הכל עם basic-auth + תעודת Let's Encrypt שהונפקה
על ידי Tailscale (מתחדשת שבועית). שם ה-DNS מתפרש רק בתוך ה-tailnet
שלכם - האתר כולו בלתי נראה מהאינטרנט הפומבי.

ראו **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** למפת השירותים
המלאה, פורטים וזרימות נתונים, ו-**[docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md)**
למודל ה-auth וה-threats.

להתקנה טרייה של VM: ‏**[deploy/README.md](deploy/README.md)**.

## הרצה על PCAPs משלכם (שלוש דרכים)

בחרו את זו שמתאימה לרמת הנוחות שלכם. כל השלוש מריצות את אותו צינור
זיהוי; ההבדל הוא *איפה* הניתוח רץ ואיך אתם מקבלים את הדוח.

### א. דשבורד אינטראקטיבי + "Send to VM" (מומלץ)

פתחו את ה-notebook, השליכו PCAP, ולחצו **‏Send S1 to VM (mail
report)** על כרטיס ה-session. הדשבורד חותם על הקובץ, מזרים אותו
ל-VM ה-analyzer שלכם, וה-worker שולח באימייל את דוח ה-PDF המוגמר
לכתובת שהקלדתם - בלי GitHub, בלי תקרת גודל, בלי LLM מקומי.

דורש: ‏VM analyzer (דרך C מקימה אחד), שלושת משתני הסביבה
`NETSEC_INGEST_URL / NETSEC_SENSOR_ID / NETSEC_SENSOR_SECRET` ב-shell
שלכם לפני השקת ה-notebook, ו-`SMTP_USER / SMTP_PASS` מוגדרים ב-
`.env` של ה-VM (‏Gmail app-password עובד). ראו `docs/VM_OPS.md`
לפרטי ה-ops המדויקים.

**מה נוחת ב-inbox שלכם.** גוף האימייל הוא תקציר מנהלים (ספירות
verdicts, ממצאים מרכזיים עם שורת ראיות אחת, מטא-דאטה של ההקלטה,
בריאות הפאנל); הדוח המלא רוכב כקובץ PDF מצורף עם באנר verdict
צבעוני, טבלת מועמדים מאוחדת, סקשן Evidence-per-finding (זהות ההתקן,
מספרי תעבורה, אילו שדות קלט השופטים ציטטו), ורשת Panel-votes שמציגה
את ההצבעה של כל שופט פר-מועמד. אחרי ניתוח של S1 ו-S2, הכפתור
**‏Compare S1 & S2** שולח באימייל דוח השוואה מסדר שני: הקלטות
זו לצד זו עם פער ההקלטה, טבלת category-flow של מה השתנה, היפוכי
verdict עם זהות ההתקן, ו-IPs חדשים/שנעלמו עם הערות על ה-verdicts
שלהם.

### ב. CLI ללא ראש על המכונה שלכם

אותו צינור זיהוי, אותו LLM Judge, בלי notebook. שתי טעמים:

**ב1. ניתוח מקומי + דוח מקומי** (שום דבר לא עוזב את המכונה שלכם):

```
pip install -r requirements.txt
python llm_judge/judge_cli.py path/to.pcap \
    --output verdicts.json --markdown verdicts.md
```

דורש `tshark` ב-PATH (מותקן עם Wireshark), בתוספת ספק LLM אחד -
Ollama לנתיב ללא-מפתח (`LLM_JUDGE_PROVIDER=ollama`),
או Groq / Gemini / Cerebras / OpenRouter / Anthropic / GitHub Models
עם מפתח משלכם. הגדירו `LLM_JUDGE_PANEL=<m1>,<m2>[,...]` ל-debate
רב-שופטי אמיתי. ראו `llm_judge/README.md` לכל כפתור.

**ב2. העלאה ל-VM שלכם + דיוור הדוח** (זהה לכפתור הדשבורד,
מה-shell):

```
export NETSEC_INGEST_URL=http://<vm-tailscale-ip>:8766
export NETSEC_SENSOR_ID=laptop NETSEC_SENSOR_SECRET=...
python tools/upload_pcap.py capture.pcapng --email you@example.com
```

הדגל `--email` רוכב דרך כ-header ‏`X-Notify-Email`; שרשרת
ה-fallback SMTP → n8n של ה-worker מספקת את דוח ה-PDF.

### ג. הריצו VM ניתוח פעיל-תמיד משלכם (רציף, פרטי)

לניטור רציף שאינו תלוי במחשב הנייד שלכם להיות ער - ושם פקטות
גולמיות לעולם לא עוזבות את הרשת שלכם - הריצו את מערך הניתוח על VM
קטן שבשליטתכם. העיצוב המלא (בעברית, לפי בקשה) הוא `ARCHITECTURE_HE.md`,
ותבניות ה-deployment חיות ב-`deploy/`.

**מה זה.** ארבע שכבות שמשתפות פעולה במקום ארבעה כלים שהודבקו עם
`scp`:

- **‏Sensor (‏Tier 0)** - המחשב הנייד, או ‏Raspberry Pi 5, מקליט
  PCAP גולמי ב-ring buffer של tshark ומעלה כל chunk סגור ל-VM.
  ההקלטה הגולמית - לא CSV מאובד שלה - היא מקור האמת ומה שמנותח.
- **‏Analyzer (‏Tier 1)** - ‏VM מריץ API של קליטה חתומה, worker שמריץ
  את צינור הזיהוי *המדויק* של הדשבורד על כל PCAP, ומסד נתונים של
  SQLite להיסטוריה. ‏PCAPs גולמיים נשמרים 7 ימים ואז מוסרים אוטומטית;
  אינדקס שדות דחוס זעיר, ה-verdicts, ודוחות HTML/PDF נשמרים לנצח.
- **שופטים (‏Tier 2)** - הפאנל הקיים של LLM-as-Judge. **אתם** בוחרים
  אילו שופטים ירוצו (אחד, שניים, או הרבה ספקים חינמיים: ‏Groq, ‏Gemini,
  ‏Cerebras, ‏OpenRouter, ‏GitHub Models, בתוספת Ollama מקומי חינמי).
  כל שופט שבחרתם רץ וכל ה-verdicts חוזרים באימייל - אין fallback
  אוטומטי שמחליף מודלים מאחורי הגב שלכם. **הפאנל הפרודקשני הנוכחי
  על VM הרפרנס הוא 4 שופטים**: `groq:llama-3.1-8b-instant`,
  `groq:llama-3.3-70b-versatile`, `ollama:qwen2.5:3b` (מקומי,
  CPU-only, ‏~55 שניות/verdict על ARM 24GB), ו-`gemini:gemini-2.5-flash`
  (‏Google AI Studio Bearer-auth). ה-ThreadPoolExecutor מריץ את כולם
  במקביל אז זמן השעון ≈ max(judges), לא sum. פירוט מלא + קוד ב-
  `docs/VM_ARCHITECTURE_HE.md` סעיף 10 וה-prompt המדויק ב-
  `docs/LLM_INTERFACE.md`.
- **צרכנים (‏Tier 3)** - ה-notebook (כ-client מרוחק *או* כ-analyzer
  מקומי לחלוטין offline), אימייל, והתראות n8n.

**למה VM.** אין תקרת גודל (ההעלאה היא HTTP stream חתום ישיר), שומר
היסטוריה כך ש-beaconing ובייסליין פר-התקן הופכים משמעותיים, ושומר
פקטות גולמיות על תשתית שבבעלותכם. זרימת ה-Actions-based "דחפו PCAP
ל-`incoming/`" שהיתה כאן נגרסה - תקרת 25 MB של Actions הפכה אותה
לבלתי שימושית ל-captures אמיתיים, ונתיב ה-VM מכסה כל מקרה שהיא
כיסתה.

**‏Quickstart** (מדריך מלא ב-`deploy/README.md`):

```bash
# על ה-VM (כל קופסת Ubuntu 22.04+; Oracle Always Free הוא נתיב ה-$0)
git clone <your-fork> && cd <repo>/deploy
cp .env.example .env          # הגדירו TS_BIND, N8N_ENCRYPTION_KEY, מפתחות LLM
docker compose up -d          # n8n + ingest API + worker + retention
python3 create_sensor.py laptop   # מדפיס אישורי sensor פעם אחת

# על כל מכונה שיש לה capture (אין מגבלת גודל, אין GitHub)
export NETSEC_INGEST_URL=http://<vm-tailscale-ip>:8766
export NETSEC_SENSOR_ID=laptop NETSEC_SENSOR_SECRET=...
python3 tools/upload_pcap.py capture.pcapng
```

ה-VM עונה רק על רשת ה-Tailscale הפרטית שלכם (שום דבר ציבורי מלבד
SSH). ‏`tools/watchdog.py` חיצוני על קופסה נפרדת פעילה-תמיד צופה
ב-VM, כי אין מכונה שאמורה לנטר את עצמה.

**העשרת OSINT אופציונלית.** עם מפתחות API חינמיים משלכם ה-VM יכול
להוסיף context ציבורי למה ש-capture ראה, כולם כבויים כברירת מחדל:

- **‏Wigle** מאתר BSSID של Wi-Fi שנתפס וה-VM מרנדר מפת geo של
  נקודות הגישה (`report kind: map`), עם הערות על RSSI וה-path-loss
  distance שהצינור כבר מחשב.
- **‏Shodan** מדרג את המוניטין של host חיצוני שהתקן מקומי דיבר איתו
  (CVEs ידועים, תגיות זדוניות); זה מפעיל את משקל ה-threat-intel
  השמור של השופט, אז "ההתקן הזה מדבר עם host מסומן" מרים את
  הקדימות של אותו מועמד.

הגדירו `WIGLE_API_NAME`/`WIGLE_API_TOKEN`, `SHODAN_API_KEY` ו-
`NETSEC_ENABLE_SHODAN=1` ב-`deploy/.env`. בלי מפתחות המפה נשארת
ריקה ומשקל ה-threat-intel לא תורם כלום - זהה להתנהגות הבסיסית.

**כל האמור לעיל הוא אופציונלי.** ה-notebook של הדשבורד המקומי עדיין
מנתח קובץ בלי VM ובלי רשת בכלל; נתיב ה-VM הוא מה שהופך notebook
חד-פעמי למערכת רציפה-שולחת-ל-inbox.

**ניהול ה-VM שלכם ביום-יום.** אחרי ההקמה החד-פעמית, כל הפעולות
הנפוצות - ‏SSH פנימה, ‏redeploy אחרי `git pull`, צפייה בריצה חיה,
הפעלה מחדש של שירות, גיבוי ה-DB ההיסטוריה, סבב sensor שנפרץ -
נאספו ב-[`docs/VM_OPS.md`](docs/VM_OPS.md) כבלוקי פקודה מוכנים
להדבקה. המסמך משתמש ב-placeholders ‏`<vm>` ו-`<sensor>` בכל מקום;
החליפו ב-IP שלכם של Tailscale ובשם ה-sensor פעם אחת והשאר פשוט
עובד.

## בדיקות

```
pip install -r requirements.txt -r server/requirements.txt pytest pytest-timeout
pytest tests/ -v
```

הסוויטה צריכה `tshark` ב-PATH (מגיע עם Wireshark). `server/requirements.txt`
מספק `fastapi`, `uvicorn` ו-`httpx` שבשימוש על ידי API הקליטה ובדיקות
end-to-end - בלעדיהם בדיקות אלה היו מדלגות בשקט. אתם יכולים גם להריץ
את צינור רגרסיית ה-CLI הידני ישירות מול כל זוג captures:

```
python3 attack_tests/run_pipeline.py <S1.pcap> <S2.pcap>
```

## רישיון

פרטי - לשימוש מחקר / חינוכי בלבד.

</div>
