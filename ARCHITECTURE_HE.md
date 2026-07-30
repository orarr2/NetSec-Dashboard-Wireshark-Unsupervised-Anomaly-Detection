# ארכיטקטורת האקוסיסטם - מסמך אפיון v2.0

תאריך: 2026-07-30 · מחליף את v1 (2026-07-22) · מסמך תכנון, ללא מימוש קוד

> הריפו הוא אנגלית-בלבד ככלל, והמסמך הזה הוא חריגה מוצהרת - כמו
> `docs/DOCKER_AI_AGENTS_HE.md`. הוא נשמר בעברית בשורש לפי בקשה
> מפורשת, כדי שתכנון המערכת יהיה הדבר הראשון שרואים.

**סטטוס: מאושר (2026-07-30).** 13 הדילמות הפתוחות הוכרעו על ידי בעל
הפרויקט ומתועדות בסעיף 13. המימוש מתבצע שלב-אחר-שלב (סעיף 10), כל
שלב באישור נפרד, בענף נפרד מחוץ ל-main. שלב א' החל עם האישור.

---

## 1. מה השתנה מ-v1 - תמצית ההכרעות

| # | הכרעת v1 | הכרעת v2 (מחייבת) |
|---|---|---|
| 1 | שדות tshark דחוסים עוברים לענן; PCAP גולמי נשאר על החיישן בלבד | **ה-PCAP הגולמי הוא המקור והוא מה שעולה ל-VM.** נשמר שם עם מחיקה אוטומטית שבועית. ההמרה לשדות היא שלב עיבוד פנימי, לא תחליף למקור |
| 2 | GitHub Actions הוא מסלול קליטה, תקרת 25MB רלוונטית | **העלאה ישירה ל-VM, בלי שום תלות ב-GitHub** ובלי תקרת גודל. Actions נשאר ל-CI ולהדגמה ציבורית בלבד |
| 3 | שופטים: Groq + Ollama בלבד | **מטריצת ספקי LLM חינמיים** (Gemini, Cerebras, OpenRouter, GitHub Models, Mistral ועוד) עם שרשרת failover ומעקב מכסות (סעיף 6) |
| 4 | מסד היסטוריה מינימלי (6 טבלאות) | **סכימה מלאה** שכוללת את כל שדות הניתוח הקריטיים להמשך: פיצ'רים פר-IP, אותות מנועים מתקדמים, פסיקות מלאות, audit של הפאנל, baselines, מכסות (סעיף 7) |
| 5 | בענן נשמרים רק אגרגטים ופסיקות | על דיסק ה-VM נשמרים גם **ה-PCAP הגולמי (שבוע), דוח ה-PDF ודוח ה-HTML של השופט - לתמיד** (סעיף 8) |
| 6 | אין מדריך הקמה גנרי | **מדריך VM גנרי לכל משתמש** + סעיף README באנגלית; חסימת ה-automation/ ב-gitignore מטופלת (סעיף 9) |
| 7 | תעבורת ההעלאה של החיישן עצמו לא טופלה (הוזכרה רק חתימת HMAC) | **פרוטוקול טלמטריה מוצהרת בשלוש שכבות: הפרדת נתיב, מניפסט מוצלב, מודעות מודלים** (סעיף 12) |

---

## 2. תיקון הנחות היסוד של v1

בדיקה מחודשת של הקוד מצאה גם אי-דיוקים ב-v1 עצמו. נרשמים כאן כדי
שהמסמך הזה יהיה מקור אמת יחיד:

1. **"analyze_pcap לא קורא PCAP" - ניסוח מטעה, והמסקנה שנגזרה ממנו
   נדחתה.** ההסבר המלא והתיקון בסעיף 3.
2. **"22 שדות" - לא מדויק.** הלואדר המהיר (`_analyze_pcap_tshark`)
   מייצא **23 שדות**; המנועים המתקדמים (`_adv_load_pk`) מייצאים **24
   שדות** (כולל TLS SNI/JA3/JA4, ‏DHCP server-id, ‏ARP opcode); האיחוד
   הוא כ-30 שדות שונים.
3. **הפניה לקובץ שאינו קיים.** v1 הפנה ל-`SELF_MONITORING_DESIGN_HE.md`
   (חלופות A ו-D) - הקובץ הזה לא נמצא בריפו. מנגנון החתימה מוגדר
   מעתה במסמך הזה עצמו (סעיף 5.1) בלי תלות חיצונית.
4. **"103 הבדיקות" - המספר לא נכון להיום.** בסוויטה יש כרגע 99
   פונקציות בדיקה (חלקן פרמטריות, כך שמספר המקרים הנאסף שונה).
   מסמך תכנון לא צריך לקבע מספר - הכלל הוא: הסוויטה כולה ממשיכה
   לעבור ללא שינוי.
5. **"ייצוא השדות הוא חסר-אובדן" - נכון רק ביחס לצינור של היום,
   ולכן לא קביל כעקרון תכנון.** ראו סעיף 3.1 לרשימת מה שכן אובד.
6. **"שבוע נתק הוא 270MB - שום דבר"** - היה נכון לשדות דחוסים. עם
   ההכרעה החדשה (PCAP גולמי עולה לענן) שבוע נתק בהקלטה רציפה הוא
   כ-99GB. מדיניות הספול עודכנה בהתאם (סעיף 11).
7. **פערים שנמצאו בקוד ורלוונטיים לתכנון:**
   - `automation/` (docker-compose, ‏judge_api, ‏תבניות n8n) נמצא כולו
     ב-.gitignore - משתמש חיצוני שעושה fork לא יכול להקים את ה-VM
     בכלל. זה חוסם את דרישת הגנריות ומטופל בסעיף 9.
   - `docs/CLOUD_DEPLOYMENT.md` מכיל כתובות IP חיות ושם קובץ מפתח
     אישי; הקובץ עצמו מזהיר "לנקות לפני פרסום". בגרסה הגנרית הם
     יוחלפו ב-placeholders.
   - הלואדר מייצא `ip.src`/`ip.dst` בלבד - תעבורת IPv6 (שדות
     `ipv6.src`/`ipv6.dst`) לא נכנסת לאגרגציה פר-IP היום. דוגמה
     חיה לסיבה שהגולמי חייב להישמר: כשנוסיף IPv6, רק PCAP שמור
     יאפשר ניתוח רטרואקטיבי.
   - הדשבורד כבר מעלה PCAP ל-VM (כפתור "Send S1/S2 to n8n Alert",
     ‏scp מעל Tailscale) - כלומר "גולמי עולה לענן" הוא לא רעיון חדש
     אלא הרחבה של נתיב קיים ועובד.
8. **מכסת Groq** - v1 ציין 100k tokens ליום; ‏`CLOUD_DEPLOYMENT.md`
   מדד גם 12k tokens לדקה. שתי המגבלות אמיתיות ושתיהן נכנסות למעקב
   המכסות (סעיף 6.3).
9. **המספרים של v1 אומתו חשבונאית** (590MB לשעה, פי 368, ‏15.6 שעות
   בתקרת 25MB, ‏7.3 שנות שדות ב-100GB) - אבל כולם נמדדו על הקלטה
   אחת של 135 שניות. הם משמשים כאן כסדרי גודל; מדידה חוזרת על
   הקלטה ארוכה היא משימת פתיחה של שלב א' במימוש.

---

## 3. סוגיה 1: מעמד ה-PCAP הגולמי (ההכרעה המרכזית)

### 3.1 למה בכלל נכתב "analyze_pcap לא קורא PCAP", ומה באמת אובד

העובדה הטכנית: `analyze_pcap` מפעיל את `tshark` על קובץ ה-PCAP,
ו-tshark - לא פייתון - הוא שמפענח את החבילות. לתוך פייתון נכנס רק
פלט טקסטואלי של 23 עמודות שממנו נבנה ה-DataFrame:

```python
raw = subprocess.check_output([tshark_path, "-r", str(path), "-n",
                               "-T", "fields", ...])
df  = pd.read_csv(io.StringIO(raw), sep="|", ...)
```

מכאן נולד הניסוח של v1. הוא נכון מילולית - ושגוי כעקרון תכנון, כי
"חסר-אובדן" שם נמדד רק מול מה שהצינור *של היום* צורך. מול ההקלטה
עצמה, ייצוא השדות מאבד באופן בלתי-הפיך:

- **תוכן החבילות** - payload של פרוטוקולים לא מוצפנים (DNS מלא,
  ‏HTTP, ‏DHCP options, ‏mDNS/SSDP), תעודות TLS, כותרות.
- **שדות שלא נכללו בייצוא** - TTL, ‏IP ID, ‏TCP seq/ack/window
  (ניתוח retransmission ו-RTT), ‏ICMP, פרגמנטציה, QUIC, ‏SMB,
  ו-IPv6 כולו (סעיף 2.7).
- **יכולת פענוח מחדש** - גרסת tshark חדשה, תיקון באג פענוח, מנוע
  עתידי שדורש שדה שלא חשבנו עליו. בלי הגולמי אין ניתוח רטרואקטיבי.
- **פורנזיקה וראיות** - פתיחת flow ב-Wireshark ברמת bytes; ‏PCAP
  עם sha256 הוא ארטיפקט ראייתי, CSV נגזר איננו.

**ההכרעה (מחייבת): קובץ ה-PCAP הגולמי הוא מהות הפרויקט והמקור
היחיד. הוא מה שמועלה ל-VM ומה שהניתוח רץ עליו. כל המרה לשדות היא
שלב עיבוד פנימי בתוך ה-VM, שנגזר מהמקור ולעולם לא מחליף אותו.**

יתרון מעשי מיידי של ההכרעה: **אפס שינוי בליבת הצינור.** ה-worker על
ה-VM מריץ את `analyze_pcap` על קובץ PCAP בדיוק כמו היום. השינוי
היחיד שv1 תכנן בליבה (קלט קובץ-שדות) מתייתר.

### 3.2 פתרון 25MB: העלאה ישירה ל-VM, בלי GitHub

הצורך בתקרת 25MB נעלם כי GitHub יוצא ממסלול הקליטה:

- **הנתיב הראשי:** העלאת ה-PCAP ישירות ל-VM דרך Ingest API ‏(HTTP
  מעל Tailscale, סעיף 5.1). אין תקרת גודל מעשית - קובץ של 1GB
  עולה כמו קובץ של 10MB, רק לאט יותר. רוחב הפס הנדרש להקלטה רציפה
  הוא כ-590MB לשעה = ‏1.3Mbps - זניח לכל חיבור ביתי.
- **נתיב גיבוי ידני:** `scp` נשאר עובד (הוא כבר ממומש בדשבורד),
  אבל הופך ל-fallback מתועד ולא לנתיב הראשי.
- **GitHub Actions נשאר** בדיוק לשני תפקידים: CI על כל push, והדגמה
  ציבורית למי שאין לו VM (fork, קובץ קטן, Issue עם טבלת פסיקות).
  שום דבר בזרימה האישית לא תלוי בו יותר.

### 3.3 שמירה ומחיקה על ה-VM

- **PCAP גולמי: נשמר 7 ימים, נמחק אוטומטית** (job יומי, סעיף 10,
  רכיב `retention.py`). אין כוונה ואין יכולת לאחסן גולמי לאורך
  שנים - זו הצהרה מפורשת של התכנון.
- מחיקה היא לפי גיל **וגם** לפי watermark: אם הדיסק חוצה 85% תפוסה,
  נמחקים הישנים ביותר גם לפני תום השבוע. רשומת ה-DB של הקובץ לא
  נמחקת לעולם - רק מסומנת `deleted_at`, כך שההיסטוריה יודעת בדיוק
  מה נותח ומתי נמחק.
- **חשבון נפח אמיתי** (הקלטה רציפה 24/7, לפי הקצב שנמדד):
  ‏14.2GB ליום, כ-99GB לשבוע. דיסק boot של 100GB, אחרי OS, ‏Docker
  ומודל Ollama, לא מכיל את זה. שלוש אפשרויות:
  - **א. (הוכרע, IDX-02+03)** לצרף block volume ייעודי ל-`/srv/netsec/data`.
    תקציב ה-Always Free של Oracle הוא 200GB אחסון כולל - ‏boot של
    50-100GB ועוד volume נתונים של 100-150GB נכנסים בחינם.
  - ב. לקצר את חלון השמירה ל-4-5 ימים.
  - ג. אם ההקלטה איננה רציפה (sessions יזומים בלבד), הבעיה קטנה
    בסדר גודל וה-boot מספיק.
- **הוכרע (IDX-04):** לצד הגולמי נשמר **לתמיד** גם
  ייצוא השדות הדחוס של כל קובץ (gzip, ‏1.6MB לשעת הקלטה, ‏14GB
  לשנה רציפה). זה לא מחליף את הגולמי - זה אינדקס היסטורי זעיר
  שממשיך לאפשר baseline, ‏beaconing רב-שבועי והשוואות "עכשיו מול
  לפני חודשיים" גם אחרי שהגולמי של אותו שבוע נמחק. בלי זה, ההיסטוריה
  העמוקה של המערכת מוגבלת למה שנשמר ב-DB המסוכם.

---

## 4. הארכיטקטורה המעודכנת

```
   Tier 0                    Tier 1                        Tier 2             Tier 3
   חיישן                     מנתח (VM)                     שופטים             צרכנים
 ┌────────────┐   PCAP     ┌──────────────────┐   ~4KB   ┌────────────┐   ┌──────────────┐
 │ לפטופ /    │   גולמי    │ Ingest API       │  מועמדים │ שרשרת      │   │ מחברת        │
 │ Pi 5       │ ─────────► │ Worker (הצינור   │ ───────► │ ספקים      │──►│ מייל (SMTP)  │
 │            │  HTTP/     │ הקיים, ללא שינוי)│          │ חינמיים +  │   │ n8n התראות   │
 │ ring       │  Tailscale │ SQLite היסטוריה  │          │ Ollama     │   │ GitHub Issue │
 │ buffer     │            │ PCAP - 7 ימים    │          │ (fallback  │   │ (דמו ציבורי) │
 │ מקומי      │            │ HTML/PDF - לתמיד │          │ תמידי)     │   └──────────────┘
 │ (אופציה)   │            │ שדות gz - לתמיד* │          └────────────┘
 └────────────┘            └──────────────────┘                 * הוכרע: כן (IDX-04)
```

העיקרון המנחה עודכן: **המקור עולה לענן, ההחלטות מתקבלות בענן,
והזמן קוצב את הגולמי - שבוע בענן, ולפי בחירה גם ring buffer מקומי
על החיישן.**

מה עובר בכל קישור:

| קישור | מה עובר | מה נשאר מאחור |
|---|---|---|
| חיישן ← VM | PCAP גולמי חתום HMAC, עם sha256 | כלום - המקור עצמו עובר |
| VM ← שופטים | מועמדים בלבד (~4KB ל-batch) | הגולמי, השדות, הפיצ'רים |
| VM ← צרכנים | דוחות (HTML/PDF/JSON), שאילתות DB | הגולמי (זמין להורדה בחלון השבוע) |

---

## 5. שכבה אחר שכבה

### 5.1 ‏Tier 0+1: קליטה - ‏Ingest API במקום scp כנתיב ראשי

- `POST /v1/pcap` ‏(FastAPI על ה-VM, מאחורי Tailscale): מקבל stream
  של הקובץ עם שלוש כותרות - `X-Sensor-Id`, ‏`X-Sha256`,
  ‏`X-Signature`. השרת מאמת sha256 בכתיבה, מאמת חתימה, שומר תחת
  `data/pcap/YYYY/MM/DD/<sha8>_<name>.pcap`, רושם ב-DB, מכניס לתור
  ומחזיר `202 {"session_id": ...}`. העלאה חוזרת של אותו sha256 היא
  ‏idempotent (מוחזר ה-session הקיים).
- **חתימה (מגדיר את מה שv1 הפנה אליו החוצה):** ‏HMAC-SHA256 על
  ‏`sha256(file) + sensor_id + timestamp` עם סוד פר-חיישן שנוצר
  בהקמה. ‏Replay נחסם בחלון timestamp; חיישן שנפרץ מבטלים בשורת
  DB אחת. זה מה שמאפשר לשרת להבדיל בין תעבורת שליחות לגיטימית לבין
  כל דבר אחר - בלי allow-list של כתובות. איך מוודאים שהתעבורה הזו
  לא מציפה את הניתוח עצמו כאנומליה - סעיף 12.
- למה לא scp כנתיב ראשי: ‏scp דורש חשבון shell על ה-VM לכל חיישן -
  הרשאה גדולה בהרבה מהנחוץ. ‏endpoint אחד append-only עם טוקן נותן
  אימות פר-חיישן, rate-limit, ‏ack מפורש, ו-resume. ‏scp נשאר
  כ-fallback מתועד.
- `GET /v1/sessions/{id}` - סטטוס + פסיקות; `GET /v1/reports/{id}.html|.pdf`
  ‏- הדוחות; `GET /healthz` - ל-watchdog. גישה לקריאה עם אותו טוקן.

### 5.2 ‏Tier 1: ‏Worker - הצינור הקיים, עטוף ולא משוכתב

ה-worker שולף מהתור ומריץ בדיוק את מה ש-`judge_cli.analyze_and_judge`
עושה היום: ‏`analyze_pcap` ‏← ‏`run_ml_on_session` ‏←
‏`run_security_scans` ‏← ‏`assemble_candidates` ‏← שופטים ‏←
‏commentary. התוספות הן מסביב: כתיבת כל התוצרים ל-DB (סעיף 7),
רינדור HTML+PDF (סעיף 8), שליחת מייל/וובהוק ל-n8n, ועדכון סטטוס.

### 5.3 ‏Tier 2: השופטים - ראו סעיף 6.

### 5.4 ‏Tier 3: הצרכנים

- **המחברת** נשארת גם דשבורד וגם מסלול גיבוי עצמאי מלא (offline,
  בלי VM). נוסף לה מצב לקוח: `load_session_from_api(session_id)`
  שמחזיר את אותו מבנה S-dict בדיוק - אפס שינוי ב-52 הצ'ארטים.
  כפתור ההעלאה הקיים עובר מ-scp ל-HTTP (עם scp כ-fallback).
- **מייל** - `send_report.py` הקיים, ללא שינוי.
- **n8n** - נשאר לאוטומציית התראות; ה-worker קורא לוובהוק שלו.
- **GitHub Issue** - רק במסלול ההדגמה הציבורי.

---

## 6. סוגיה 2: מטריצת ספקי LLM חינמיים

נקודת המוצא בקוד: הפאנל כבר יודע לערבב ספקים
(`LLM_JUDGE_PANEL="provider:model,..."`), וכל ספק שמדבר את פרוטוקול
ה-chat-completions של OpenAI עובר דרך `OpenAICompatClient` הקיים
בלי שורת קוד חדשה - רק env. כמעט כל הספקים בטבלה הם כאלה.

המגבלות נכונות לינואר 2026 ומשתנות תדיר - **חובה לאמת בעת ההקמה**:

| ספק | endpoint ‏(OpenAI-compatible) | מודלים רלוונטיים | מגבלת חינם ידועה | הערות |
|---|---|---|---|---|
| Groq (קיים) | `api.groq.com/openai/v1` | llama-3.3-70b-versatile, llama-3.1-8b-instant, qwen3-32b | ‏~12k TPM, תקרה יומית פר-מודל | המהיר ביותר (743ms נמדד) |
| **Google Gemini** | `generativelanguage.googleapis.com/v1beta/openai/` | gemini-2.5-flash, gemini-2.5-flash-lite | ‏~10-15 RPM, מאות בקשות ליום | איכות גבוהה; חלון הקשר ענק |
| **Cerebras** | `api.cerebras.ai/v1` | llama-3.3-70b, qwen-3-32b | ‏~1M tokens ליום | מהיר מאוד, מכסה יומית נדיבה |
| **OpenRouter** | `openrouter.ai/api/v1` | deepseek-r1:free, qwen3:free ועוד עשרות `:free` | ‏~50 בקשות ליום | שער אחד להרבה מודלים, כולל Qwen ו-DeepSeek |
| **GitHub Models** | `models.github.ai/inference` | gpt-4o-mini, Phi-4, Llama-3.3-70B | ‏rate-limit פר-tier, חינם עם חשבון GitHub | מתאים במיוחד - למשתמשי הפרויקט כבר יש GitHub |
| **Mistral** | `api.mistral.ai/v1` | mistral-small, open-mistral-nemo | ‏tier ניסוי חינמי, ~1 RPS | דורש הרשמה |
| SambaNova | `api.sambanova.ai/v1` | Llama 70B/405B | ‏tier חינמי | מודלים גדולים בחינם |
| NVIDIA NIM | `integrate.api.nvidia.com/v1` | Llama, Qwen, DeepSeek | ‏~40 RPM למפתחים | מבחר רחב |
| Alibaba (Qwen ישיר) | `dashscope-intl.aliyuncs.com/compatible-mode/v1` | qwen-plus, qwen-turbo | מכסת ניסיון חד-פעמית | ‏Qwen ההוסטד הרשמי; לטווח ארוך עדיף Qwen מקומי/OpenRouter |
| **Ollama על ה-VM** | מקומי `:11434` | qwen2.5:14b, phi4:14b, gemma3:12b, mistral-nemo:12b, llama3.1:8b, deepseek-r1:14b | ללא מגבלה, חינם תמיד | ‏24GB RAM מריצים 14B Q4 בנוחות; איטי (~80s למועמד ב-ARM) אך בלתי-נגמר |

### 6.1 מה זה דורש בקוד (הרחבה קטנה, לא שכתוב)

הפער היחיד: ל-`OpenAICompatClient` יש base_url וגם key גלובליים
יחידים, כך שפאנל על שני ספקי-compat שונים (Groq + Gemini) לא אפשרי
היום. הפתרון - פרופילי endpoint בשמות, דרך env בלבד:

```
LLM_JUDGE_EP_GEMINI_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai/
LLM_JUDGE_EP_GEMINI_KEY_ENV=GEMINI_API_KEY
LLM_JUDGE_EP_GEMINI_MODEL=gemini-2.5-flash
LLM_JUDGE_EP_GEMINI_TPD=250000        # תקרה יומית למעקב המכסות

LLM_JUDGE_PANEL="groq:llama-3.3-70b-versatile,gemini:gemini-2.5-flash,ollama:qwen2.5:14b"
```

`make_client` יזהה שם פרופיל כספק ויבנה `OpenAICompatClient` עם
הערכים שלו. תאימות לאחור מלאה: ‏`claude`/`ollama`/`openai_compat`
ממשיכים לעבוד כמו היום, וה-cache כבר ממופתח לפי model_id כך שאין
זיהום פסיקות בין ספקים.

### 6.2 פאנל הטרוגני - ברירת המחדל (הוכרע, IDX-06)

שלושה שופטים משלושה ספקים שונים:
`groq:llama-3.3-70b + gemini:gemini-2.5-flash + ollama:qwen2.5:14b`.
מודלים ממשפחות שונות טועים אחרת - הצבעה ביניהם שווה יותר משלושה
עותקים של אותו מודל, ומנגנון הפאנל/עימות הקיים עובד עליהם ללא שינוי.

### 6.3 מעקב מכסות ו-failover

- טבלת `llm_quota` ‏(סעיף 7): צריכת בקשות ו-tokens פר-ספק פר-יום,
  כולל חותמת 429 אחרון. הערת מימוש: תשובות ה-API כוללות שדה
  ‏`usage` שהקליינטים היום זורקים - הוא יתחיל להישמר.
- שרשרת failover מוגדרת env: ‏`LLM_JUDGE_FAILOVER="groq,gemini,cerebras,ollama"`.
  ספק שמוצה (מכסה יומית או 429 עקבי) מדולג עד חצות; ‏Ollama בסוף
  השרשרת תמיד זמין - **כשהמכסות נגמרות המערכת מאטה, לא נופלת.**

---

## 7. סוגיה 3: סכימת מסד הנתונים המלאה

‏SQLite, קובץ `db/netsec.db` על ה-VM, ‏WAL mode, גרסת סכימה ב-
`PRAGMA user_version`. ‏`judge_cache.sqlite` הקיים נשאר קובץ נפרד
כמו היום (הוא cache, לא היסטוריה). הסכימה נגזרת מהשדות שהקוד באמת
מייצר - שמות העמודות זהים לשמות בקוד:

```sql
-- זהות ומקור
CREATE TABLE sensors (
    id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL,
    token_hash TEXT NOT NULL,      -- sha256 של טוקן הקריאה בלבד
    hmac_secret TEXT NOT NULL,     -- סוד החתימה עצמו: אימות HMAC מחייב
                                   -- את הסוד; מוגן בהרשאות קובץ ה-DB
    created_at TEXT NOT NULL, last_seen_at TEXT, revoked_at TEXT);

CREATE TABLE pcap_files (
    id INTEGER PRIMARY KEY, sha256 TEXT UNIQUE NOT NULL,
    orig_name TEXT, size_bytes INTEGER, sensor_id INTEGER,
    received_at TEXT NOT NULL, capture_start REAL, capture_end REAL,
    storage_path TEXT NOT NULL,
    fields_path TEXT,          -- ייצוא שדות דחוס, אם אושר לשמור
    deleted_at TEXT);          -- הגולמי נמחק; השורה נשארת לתמיד

-- ריצת ניתוח (קובץ אחד יכול להינתח יותר מפעם אחת)
CREATE TABLE sessions (
    id INTEGER PRIMARY KEY, pcap_id INTEGER NOT NULL,
    label TEXT, status TEXT NOT NULL,          -- queued|running|done|error
    kind TEXT NOT NULL DEFAULT 'prod',         -- prod|test, סעיף 12.3
    queued_at TEXT, started_at TEXT, finished_at TEXT, error TEXT,
    n_pkts INTEGER, n_ips INTEGER, duration_s REAL,
    pipeline_version TEXT, prompt_version TEXT,
    tshark_version TEXT, git_commit TEXT);

-- הפיצ'רים שהמודלים רואים - קריטי ל-baseline ולשחזור
CREATE TABLE ip_features (
    session_id INTEGER NOT NULL, ip TEXT NOT NULL,
    mean_len REAL, std_len REAL, count INTEGER, burst_score REAL,
    unique_dsts INTEGER, syn_count INTEGER, rst_count INTEGER,
    fin_count INTEGER, null_count INTEGER, xmas_count INTEGER,
    bytes_src INTEGER, bytes_dst INTEGER,
    iso_score REAL, iso_flag INTEGER,
    dbscan_cluster INTEGER, dbscan_anomaly INTEGER, lstm_flag INTEGER,
    self_telemetry INTEGER DEFAULT 0,          -- סעיף 12.2
    PRIMARY KEY (session_id, ip));

-- שכבת הכללים הדטרמיניסטית
CREATE TABLE findings (
    id INTEGER PRIMARY KEY, session_id INTEGER NOT NULL,
    layer TEXT, rule TEXT, ip TEXT, severity TEXT, detail_json TEXT);

-- חמשת המנועים המתקדמים - בדיוק סכימת _adv_sig מהקוד
CREATE TABLE adv_signals (
    id INTEGER PRIMARY KEY, session_id INTEGER NOT NULL,
    device TEXT, peer TEXT, signal TEXT, tactic TEXT, technique TEXT,
    score REAL, severity TEXT, count INTEGER,
    first_ts REAL, last_ts REAL, detail TEXT);

CREATE TABLE fusion_scores (
    session_id INTEGER NOT NULL, device TEXT NOT NULL,
    score REAL, engines_hit INTEGER, window_start REAL,
    PRIMARY KEY (session_id, device));

-- מה נשלח לשופט ומה חזר
CREATE TABLE candidates (
    id INTEGER PRIMARY KEY, session_id INTEGER NOT NULL,
    candidate_id TEXT NOT NULL,     -- ip או session:<label>
    kind TEXT, rank INTEGER, capped INTEGER DEFAULT 0,
    context_json TEXT NOT NULL);    -- ה-blob המדויק שנשלח - שחזור מלא

CREATE TABLE verdicts (
    id INTEGER PRIMARY KEY, candidate_row INTEGER NOT NULL,
    session_id INTEGER NOT NULL,
    verdict TEXT, category TEXT, confidence REAL, priority_score REAL,
    guardrail_applied INTEGER, needs_human_review INTEGER,
    verdict_json TEXT NOT NULL,
    provider TEXT, model TEXT, latency_ms INTEGER, cached INTEGER,
    tokens_in INTEGER, tokens_out INTEGER);

-- שקיפות הפאנל: עמדה ראשונית, עימות, עמדה סופית - פר שופט
CREATE TABLE panel_audit (
    id INTEGER PRIMARY KEY, session_id INTEGER NOT NULL,
    candidate_id TEXT NOT NULL, judge_model TEXT NOT NULL,
    initial_verdict TEXT, final_verdict TEXT,
    debated INTEGER DEFAULT 0, error TEXT);

-- תוצרים על הדיסק (סעיף 8)
CREATE TABLE reports (
    id INTEGER PRIMARY KEY, session_id INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('json','md','html','pdf')),
    path TEXT NOT NULL, sha256 TEXT, created_at TEXT NOT NULL);

-- ההמשך: baseline פר-מכשיר, פערי הקלטה, מכסות LLM
CREATE TABLE device_baselines (
    device_key TEXT NOT NULL,       -- MAC כשידוע, אחרת IP
    window_start TEXT NOT NULL, window_end TEXT,
    features_json TEXT NOT NULL, updated_at TEXT NOT NULL,
    PRIMARY KEY (device_key, window_start));

CREATE TABLE gaps (
    id INTEGER PRIMARY KEY, sensor_id INTEGER,
    start_ts REAL, end_ts REAL, reason TEXT);

CREATE TABLE llm_quota (
    provider TEXT NOT NULL, day TEXT NOT NULL,
    requests INTEGER DEFAULT 0, tokens INTEGER DEFAULT 0,
    last_429_at TEXT,
    PRIMARY KEY (provider, day));

-- הצהרות ערוץ הטלמטריה והצלבתן (סעיף 12)
CREATE TABLE telemetry_log (
    id INTEGER PRIMARY KEY, sensor_id INTEGER NOT NULL,
    started_at REAL, ended_at REAL,
    dst TEXT, dst_port INTEGER, bytes_sent INTEGER, file_sha256 TEXT,
    source TEXT NOT NULL CHECK (source IN ('manifest','ingest_log')),
    matched_session_id INTEGER);

CREATE INDEX idx_sessions_pcap    ON sessions(pcap_id);
CREATE INDEX idx_verdicts_session ON verdicts(session_id);
CREATE INDEX idx_adv_session      ON adv_signals(session_id);
CREATE INDEX idx_findings_session ON findings(session_id);
```

מה שהסכימה הזו פותחת, מעבר לתיעוד: ‏beaconing אמיתי לאורך ימים,
‏baseline פר-מכשיר ("מה נורמלי למכשיר הזה" במקום "מה נורמלי ב-135
השניות האלה"), השוואת now-מול-שבוע-שעבר בלי לטעון שני קבצים ביד,
מדידת drift של השופטים לאורך גרסאות prompt, וחשבון מכסות אמיתי.
גיבוי: ‏`sqlite3 .backup` לילי לצד הדוחות (הקובץ קטן - עשרות MB
לשנה).

---

## 8. סוגיה 4: תוצרים שנשמרים על דיסק ה-VM

פריסת הדיסק (volume הנתונים):

```
/srv/netsec/
├── data/pcap/YYYY/MM/DD/<sha8>_<orig>.pcap      ← גולמי, 7 ימים
├── data/fields/YYYY/MM/<sha8>.tsv.gz            ← אם אושר (סעיף 3.3), לתמיד
├── reports/<session_id>/verdicts.json           ← לתמיד
├── reports/<session_id>/verdicts.md             ← לתמיד
├── reports/<session_id>/report.html             ← לתמיד
├── reports/<session_id>/report.pdf              ← לתמיד
└── db/netsec.db (+ גיבויים יומיים)              ← לתמיד
```

- **HTML - כמעט בחינם:** ‏`send_report.markdown_to_html` כבר מרנדר
  את הדוח המלא כ-HTML עצמאי בשביל המייל. אותה פונקציה בדיוק תכתוב
  את הקובץ לדיסק. תוספת מתוכננת: בלוק metadata (שם קובץ, sha256,
  גרסאות, הרכב פאנל) בראש הדוח.
- **PDF - רכיב חדש:** ההמלצה היא **WeasyPrint** - ‏HTML+CSS נכנס,
  ‏PDF יוצא, אותו HTML שכבר יש לנו, רץ נקי על aarch64 (תלויות
  מערכת: ‏pango/cairo דרך apt). חלופות שנשקלו: ‏reportlab (בניית
  עמוד ידנית - לבנות את הדוח פעמיים), ‏wkhtmltopdf (פרויקט נעצר),
  ‏Chromium headless (מאות MB בשביל PDF). הוכרע: ‏WeasyPrint
  ‏(IDX-07).
- נפח: ‏HTML+PDF+JSON כ-1-2MB לניתוח. גם עשרת אלפים ניתוחים הם
  פחות מ-20GB - "לתמיד" הוא מעשי.
- כל תוצר נרשם בטבלת `reports` עם sha256, כך שהמחברת וה-API יודעים
  בדיוק מה קיים לכל session.

---

## 9. סוגיה 6: מדריך VM גנרי + README

### 9.1 החסם שחייב להיפתר קודם

`automation/` (compose, ‏judge_api, תבניות n8n) נמצא כולו ב-
‏.gitignore - כלומר משתמש שעושה fork היום מקבל הוראות שמפנות לקבצים
שאינם קיימים אצלו. במימוש: תיקיית `deploy/` חדשה **בתוך הריפו** עם
כל התבניות, בלי אף סוד - ‏`docker-compose.yml`, ‏`Dockerfile` של
‏judge_api/ingest, יחידות systemd, ‏`.env.example` עם כל משתנה מתועד,
ותבנית workflow של n8n. הסודות עצמם (מפתחות API, סוד HMAC, ‏SMTP)
חיים רק ב-`.env` מקומי על ה-VM, שנשאר מחוץ ל-git.

### 9.2 המדריך הגנרי (ייכנס ל-README באנגלית, תמצית כאן)

- **דרישות מינימום:** כל VM עם ‏Ubuntu 22.04+, ‏x86-64 או ‏ARM,
  ‏4GB RAM לצינור בלבד; ‏16-24GB אם רוצים גם שופט Ollama מקומי.
  ‏Oracle Always Free ‏(4 OCPU / ‏24GB / ‏200GB) הוא המסלול החינמי
  המומלץ ומקבל נספח מפורט; ‏AWS/GCP/Azure/Hetzner עובדים זהה.
- **שלבי הקמה:** ‏(1) התקנת Docker + ‏Tailscale + ‏chrony ‏(NTP -
  נדרש להצלבת הטלמטריה, סעיף 12), צירוף ל-tailnet;
  ‏(2) ‏`git clone` של הריפו; ‏(3) ‏`cp deploy/.env.example .env`
  ומילוי ערכים; ‏(4) ‏`docker compose up -d`; ‏(5) יצירת חיישן -
  ‏`python deploy/create_sensor.py <name>` שמדפיס token+secret
  חד-פעמיים; ‏(6) בדיקת עשן - העלאת PCAP לדוגמה וקבלת דוח.
- **מה נפתח לרשת:** כלום ציבורי מלבד SSH. הכול מעל Tailscale
  (החלופה למתקדמים - reverse proxy עם TLS ו-token - מתועדת אך לא
  ברירת המחדל). כללי ה-iptables הקיימים ב-`CLOUD_DEPLOYMENT.md`
  נשארים, עם placeholders במקום כתובות אישיות.
- **שימוש יומי:** העלאה מהדשבורד בכפתור, או
  ‏`python tools/upload_pcap.py capture.pcap` מכל מכונה, או ‏scp
  ‏fallback; צפייה - ‏`/v1/sessions`, דוח HTML/PDF בדפדפן, מייל.
- סעיף ה-README החדש ("Run your own analysis VM") ייכתב באנגלית
  כחלק משלב ההקמה במימוש, לפי התמצית הזו, כולל טבלת env מלאה.

---

## 10. תוכנית המימוש בפייתון

מודולים חדשים תחת `server/` ו-`sensor/`; ליבת `app/` ו-`llm_judge/`
לא משתכתבת. סקיצות - לא קוד סופי:

**`server/ingest_api.py`** ‏(FastAPI; נכנס ל-image של judge_api או
לצדו):

```python
@app.post("/v1/pcap", status_code=202)
async def upload_pcap(request: Request,
                      x_sensor_id: str = Header(...),
                      x_sha256: str = Header(...),
                      x_signature: str = Header(...)):
    sensor = auth.verify(x_sensor_id, x_sha256, x_signature)  # 401 on fail
    tmp = spool_path(x_sha256)
    digest = await stream_to_disk(request, tmp)               # sha256 תוך כדי כתיבה
    if digest != x_sha256:
        raise HTTPException(400, "sha256 mismatch")
    pcap_id = db.register_pcap(digest, tmp, sensor)           # idempotent
    session_id = db.enqueue(pcap_id)
    return {"session_id": session_id}
```

**`server/worker.py`** - לולאת תור על ה-DB (תהליך systemd נפרד):

```python
while True:
    job = db.claim_next()               # UPDATE ... WHERE status='queued'
    if not job:
        time.sleep(POLL_S); continue
    out, assembled, client, context = judge_cli.analyze_and_judge(job.pcap_path)
    telemetry.reconcile(job)                                 # הצלבה, סעיף 12.2
    db.write_session_results(job, out, assembled, context)   # סעיף 7
    html = report_html.render(job, out)                      # markdown_to_html הקיים
    report_pdf.render(html, job.pdf_path)                    # WeasyPrint
    notify.email_and_webhook(job, out)                       # send_report + n8n
    db.mark_done(job)
```

**`server/db.py`** - ה-DDL מסעיף 7 + מיגרציות לפי `user_version`.

**`server/retention.py`** - ‏systemd timer יומי: מחיקת PCAP מעל 7
ימים או מעל watermark ‏85%, סימון `deleted_at`, גיבוי DB, ‏VACUUM
חודשי.

**`sensor/capture_agent.py`** - על הלפטופ היום, על Pi 5 בעתיד, אותו
קוד: ‏tshark ב-ring buffer ‏(`-b duration:900 -b files:N`), על סגירת
chunk - ‏sha256 ‏← חתימה ‏← ‏POST עם retry; כישלון - ספול מקומי
שמתנקז כשהקישור חוזר (סעיף 11). ‏`LiveCaptureWorker` הקיים כבר כותב
‏chunks של PCAP גולמי - ה-agent הוא ההכללה שלו מחוץ למחברת. ה-agent
גם כותב מניפסט חתום של כל העלאה ומייצר את ה-capture filter
מהקונפיג של עצמו - שני צידי סעיף 12.

**`llm_judge/` - הרחבות בלבד:** פרופילי endpoint ‏(סעיף 6.1), שמירת
‏`usage` מהתשובות, שרשרת failover, כתיבת `llm_quota`.

**`tools/upload_pcap.py`** - ‏CLI חד-פעמי: קובץ ‏← חתימה ‏← העלאה
‏← הדפסת session_id. זה הפתרון הישיר לקובץ גדול מהטלפון של תקרת
‏25MB - בלי GitHub בכלל.

**שינוי דשבורד מינימלי:** כפתור השליחה קורא ל-`upload_pcap` במקום
‏scp ‏(env ‏`NETSEC_INGEST_URL`; ‏scp נשאר fallback מוצהר).

**בדיקות לכל שלב:** אימות HMAC (תקין/מזויף/replay), ‏idempotency של
העלאה כפולה, ‏retention על עץ קבצים מדומה, ‏failover עם ‏429 מדומה,
סכימת DB ומיגרציות, ‏round-trip של דוח HTML/PDF. הסוויטה הקיימת
ממשיכה לעבור ללא שינוי.

### שלבי הביצוע (כל שלב עומד בפני עצמו, כל שלב באישור נפרד)

| שלב | תוכן | תלות |
|---|---|---|
| א' | `deploy/` בריפו + ‏`.env.example` + ניקוי IPs אישיים מהמסמכים + כלי המדידה `tools/measure_pipeline_ratios.py` (ההרצה על הקלטה ארוכה - אצל בעל הפרויקט) **(בוצע)** | - |
| ב' | `server/db.py` + ‏`ingest_api.py` + ‏`tools/upload_pcap.py` + בדיקות **(בוצע)** | א' |
| ג' | `server/worker.py` + כתיבת תוצרים ל-DB + הצלבת טלמטריה + ‏HTML + ‏PDF **(בוצע)** | ב' |
| ד' | `retention.py` + גיבוי DB + ‏watchdog חיצוני **(בוצע)** | ב' |
| ה' | פרופילי LLM + ‏failover + ‏quota + פאנל הטרוגני | - (מקביל) |
| ו' | `sensor/capture_agent.py` + מניפסט + ספול + רשומות gap **(בוצע)** | ב' |
| ז' | דשבורד: כפתור ‏HTTP + ‏`load_session_from_api` **(בוצע)** | ג' |
| ח' | ‏README באנגלית + נספח Oracle **(בוצע)** | א'-ז' |
| ט' | ‏baseline פר-מכשיר מההיסטוריה + השוואות לאורך זמן **(בוצע)** | ג' |
| י' | חומרה: ‏Pi 5 נכנס כ-Tier 0 - אפס שינוי ארכיטקטוני **(בוצע - מתועד)** | ו' |
| יא' | **העשרת OSINT** (בהשראת WireTapper, בלי שיתוף קוד): ‏Wigle לפי BSSID, ‏Shodan כ-threat-intel שמפעיל את משקל W_TI, ומפת AP גאוגרפית **(בוצע)** | ג', ה' |

**שער אישור (סוגיה 5, מחייב):** המימוש מתחיל רק אחרי אישור מפורש
בכתב של המסמך הזה, שלב-אחר-שלב לפי הטבלה, בענף נפרד מחוץ ל-main.
שום שלב לא מתמזג בלי אישור נפרד שלו.

---

## 11. מצבי כשל

| כשל | התנהגות מתוכננת |
|---|---|
| הקישור חיישן-VM נפל | ספול מקומי עם תקרה קונפיגורבילית (ברירת מחדל 20GB); בהקלטה רציפה זה ~33 שעות של גולמי. מעבר לתקרה - הישן נמחק ונכתבת רשומת `gap` עם טווח הזמן. שקט וחוסר-נתונים נשארים מובחנים |
| ה-VM למטה | החיישן ממשיך להקליט ל-ring המקומי; המחברת מנתחת מקומית (מסלול הגיבוי המלא נשמר) |
| מכסת ספק LLM מוצתה | ‏failover אוטומטי בשרשרת עד Ollama המקומי - המערכת מאטה, לא נופלת |
| שופט אחד מחזיר זבל | מנגנון הפאנל הקיים ממשיך עם השאר ומתעד ב-`panel_audit` |
| חיישן נפרץ | ביטול token+secret בשורת DB; תעבורה לא-חתומה נדחית ב-401 ונרשמת |
| ההעלאות של החיישן מוצפות כאנומליה או beaconing | שלוש השכבות של סעיף 12: הפרדת נתיב מונעת את מעגל ההיזון, ההצלבה מתייגת self_telemetry, וחוסר התאמה בהצלבה הוא התראה בפני עצמה |
| הדיסק מתמלא | ‏watermark ‏85% מוחק גולמי ישן לפני שהכתיבה נחנקת; הדוחות וה-DB לא נמחקים לעולם |
| העלאה נקטעת באמצע | ‏sha256 לא מאומת - הקובץ החלקי נזרק, החיישן מעלה מחדש (idempotent) |
| tshark קורס על PCAP עוין | ה-worker רץ כמשתמש לא-מיוחס בקונטיינר; הכשל נרשם ב-`sessions.error` והתור ממשיך. ‏tshark מתעדכן שוטף - פענוח PCAP הוא משטח תקיפה |

---

## 12. בעיית הצופה: המערכת מקליטה את עצמה

### 12.1 מה קורה בלי טיפול

החיישן מקליט את הרשת שהוא עצמו משתמש בה, ותעבורת השליחות שלו -
העלאת ה-PCAP ל-VM - עוברת על אותה רשת. שלוש תוצאות:

1. **החיישן הופך לאנומליה הקבועה של המערכת.** העלאה בקצב ההקלטה
   (כ-590MB לשעה, ‏chunk של ~150MB כל 15 דקות) היא כמעט תמיד
   ה-talker הכבד ביותר ברשת ביתית. ‏bytes_src, ‏count ו-burst_score
   של כתובת החיישן מזנקים, ו-IsolationForest מסמן אותו בכל ריצה.
2. **ההעלאה נראית כמו C2 מהספר.** תקשורת מחזורית קבועה, ליעד חיצוני
   יחיד, בפרקי זמן אחידים - בדיוק הדפוס שמנוע ה-beaconing נבנה
   לתפוס. בלי טיפול, הממצא החמור ביותר בכל דוח יהיה ערוץ הדיווח
   של המערכת עצמה.
3. **מעגל היזון חוזר בהקלטה רציפה.** ההעלאה של chunk N נקלטת לתוך
   chunk N+1. אם התעבורה האורגנית היא O לשעה, ה-chunks גדלים
   ‏O, ‏2O, ‏3O... בלי תקרה (וב-Wi-Fi במצב monitor החיישן רואה את
   הפריימים של עצמו פעמיים - בדרך ל-AP ובשידור מחדש). ב-v1 הבעיה
   לא הורגשה: מה שעלה היה 1.6MB לשעה - תוספת של 0.3%. הכרעת הגולמי
   של v2 היא שהופכת אותה לקריטית, וזה מחיר שההכרעה חייבת להכיר בו
   ביושר ולטפל בו.

הבחנה מעשית: במצב העבודה של היום - הקלטת session, עצירה, העלאה -
מעגל ההיזון לא קיים כלל (ההעלאה מתרחשת אחרי שההקלטה נגמרה),
ותוצאות 1-2 מופיעות רק כשהקלטה חדשה חופפת העלאה קודמת. הבעיה
במלוא חריפותה שייכת למצב הרציף של Pi 5, ולכן הפתרון מדורג לפי מצב.

### 12.2 העיקרון: אין החרגה בלי הצהרה, ואין הצהרה בלי אימות

‏allow-list נאיבי ("תתעלם מכל מה שהולך ל-VM") נדחה על הסף: הוא יוצר
ערוץ עיוור קבוע שתוקף ירכב עליו. במקומו - שלוש שכבות:

**שכבה 0 - הפרדת נתיב: הטלמטריה יוצאת מהרשת המנוטרת.**
זו הפרקטיקה המקובלת ברשתות ניטור (out-of-band management), והיא
היחידה שפותרת את מעגל ההיזון - תיוג בדיעבד משאיר את ה-bytes בקובץ.

| מצב הפעלה | הפתרון | מה מהטלמטריה נשאר בקלט |
|---|---|---|
| ‏session ידני (היום) | ה-agent מעלה רק אחרי עצירת ההקלטה - ברירת המחדל | כלום |
| ‏Pi 5 רציף (היעד) | הקלטה על ממשק ה-Wi-Fi, העלאה דרך ה-Ethernet | כלום - רשת ממותגת, ה-WLAN לא רואה את ה-unicast הקווי |
| לפטופ רציף, ממשק יחיד | ‏capture filter צר: `not (host <VM-IP> and udp port 41641)` - שלושה תנאים מצטברים, לא "כל מה שהולך ל-443" | הזרימה המוחרגת בלבד, מדווחת ומאומתת בשכבה 1 |

ה-BPF נוצר אוטומטית מקונפיגורציית ה-agent: אותו קובץ שמגדיר את יעד
ההעלאה מגדיר את ההחרגה. אי-אפשר להחריג יעד שלא הוצהר, וכל החרגה
פעילה נרשמת בלוג ההקלטה ובמניפסט.

הסתייגות מתועדת: ‏Tailscale יכול ליפול ל-DERP relay ‏(TCP ליעד אחר),
ואז ההעלאה עוקפת את הפילטר וכן נקלטת. חוקי ה-iptables של
‏`CLOUD_DEPLOYMENT.md` נועדו למנוע בדיוק את זה, ואם זה בכל זאת קרה -
ההצלבה של שכבה 1 מזהה זרימה תואמת-מניפסט ליעד לא צפוי ומתריעה
"הטלמטריה ירדה ל-relay": תקלת תשתית שראוי לדעת עליה, לא אזעקת שווא.

**שכבה 1 - מניפסט חתום והצלבה משולשת (במקום allow-list).**
- ה-agent רושם כל העלאה שביצע: זמן התחלה וסיום, יעד ופורט, ‏bytes
  שנשלחו, ‏sha256 של הקובץ. הרשומה חתומה HMAC, נשמרת מקומית ונשלחת
  עם ה-chunk הבא.
- ל-VM יש אמת עצמאית מהצד השני: יומן ה-ingest שלו יודע בדיוק כמה
  bytes התקבלו, מתי, ומאיזה חיישן.
- ה-worker מצליב שלושה מקורות: הזרימות שבקובץ ↔ מניפסט החיישן ↔
  יומן ה-ingest. התאמה (חלון זמן ±120 שניות, יעד, נפח בסטייה של עד
  ‏15%) מתייגת את הזרימה `self_telemetry`. היא לא נמחקת ולא
  מוסתרת - היא מוצגת בפאנל בריאות ייעודי ומוצאת ממאגר האנומליות.
- **כל חוסר התאמה הוא ממצא, לשני הכיוונים:** זרימה ליעדי התשתית
  בלי הצהרה תואמת - התראת "שימוש זר בערוץ הטלמטריה"; תוקף שרוכב
  על הערוץ מנפח את הנפח הנצפה מול המוצהר ונחשף **בגלל** ההצהרה.
  הצהרה בלי זרימה תואמת בקלט - התראת "נקודה עיוורת בהקלטה"
  (הפילטר רחב מדי, או שהחיישן לא רואה את עצמו).

**שכבה 2 - מודעות בצד המודלים.**
- זרימות `self_telemetry` לא נכנסות למטריצת האימון של
  ‏IsolationForest, לא נמנות כמועמדות beaconing, ולא משתתפות
  ב-baseline של מכשיר החיישן. הן כן נשמרות ב-DB ומוצגות בצ'ארטים
  עם תג מובחן - נראות מלאה, בלי אזעקה.
- סדירות ההעלאות הופכת ממקור רעש למדד: ‏jitter חריג, נפח חסר או
  העלאה שלא הגיעה הם התראת תפעול על החיישן - לא התראת אבטחה על
  הרשת.

### 12.3 עוד בעיות אמיתיות מאותה משפחה, והטיפול בהן

| בעיה | המנגנון | הטיפול המתוכנן |
|---|---|---|
| הרצות בדיקה מרעילות היסטוריה | הרצת attack_tests או סריקה עצמית בזמן שהחיישן מקליט נכנסת ל-DB, וה-baseline לומד ש"סריקות זה נורמלי" | דגל `kind=test\|prod` על כל session בהעלאה; ‏baseline והשוואות היסטוריות נבנים מ-prod בלבד; העלאות מסקריפטי הבדיקה מסומנות test אוטומטית |
| ‏rDNS של הצינור מרעיש את הרשת | ניתוח מקומי תוך כדי הקלטה יורה מאות שאילתות PTR - פרץ DNS שנקלט בעצמו | ב-v2 הניתוח רץ על ה-VM והשאילתות יוצאות מהרשת שלו, לא מהמנוטרת; במסלול המקומי ה-rDNS ממילא opt-in |
| ניתוח חוזר מכפיל משקל | אותו PCAP מנותח פעמיים (לגיטימי) ונספר פעמיים בהיסטוריה | ‏job ה-baseline מצרף לפי `pcap_files.sha256` - ‏session אחרון לכל קובץ - לא לפי שורות sessions |
| סטיית שעונים | ההצלבה (±120s) וה-anti-replay של ה-HMAC תלויים בשעונים מסונכרנים | ‏NTP ‏(chrony) חובה על החיישן ועל ה-VM - נכלל בצ'קליסט ההקמה בסעיף 9.2 |
| רחש הרקע של Tailscale | ‏keepalives/STUN/DERP - תעבורה מחזורית קטנה מהחיישן, בצורת beaconing | יעדי התשתית מוצהרים בקונפיג ה-agent ומקבלים את אותה הצלבה; מוצגים בפאנל הבריאות |
| המחברת כלקוח API | ‏polling של `load_session_from_api` מהרשת המנוטרת נראה כתקשורת מחזורית אל ה-VM | אותו מנגנון: יעד מוצהר, הצלבה מול יומן הגישה של ה-API |

---

## 13. ההכרעות (נחתמו 2026-07-30)

כל הדילמות הפתוחות הוכרעו על ידי בעל הפרויקט. זהו תיעוד מחייב:

| IDX | דילמה | הכרעה |
|---|---|---|
| 01 | מצב ההקלטה | sessions יזומים היום; מעבר לרציף כשה-Pi 5 ייכנס כחיישן |
| 02+03 | שמירת גולמי ודיסק | 7 ימים + block volume ייעודי 100-150GB; מחיקה מוקדמת ב-85% תפוסה |
| 04 | אינדקס שדות היסטורי | נשמר לתמיד לצד הגולמי |
| 05 | ספקי LLM ראשונים | כל הארבעה: Gemini, Cerebras, OpenRouter, GitHub Models (בנוסף ל-Groq ול-Ollama הקיימים) |
| 06 | פאנל ברירת מחדל | הטרוגני: Groq-70B + Gemini-Flash + Ollama-Qwen14B |
| 07 | מנוע PDF | WeasyPrint |
| 08 | חשיפת ה-API | Tailscale בלבד; גישה ציבורית מתועדת כאופציה בלבד |
| 09 | שכבה 0 של בעיית הצופה | שלוש ברירות המחדל אושרו: העלאה-אחרי-עצירה, Ethernet נפרד ב-Pi, BPF צר בלפטופ רציף |
| 10 | מניפסט והצלבה משולשת | אושר, כתחליף ל-allow-list |
| 11 | דגל test\|prod | אושר; baseline לומד מ-prod בלבד |
| 12 | אזכור ערך ה-provider הקיים בקוד | נשאר כפי שהוא - תיעוד טכני, לא ייחוס |
| 13 | אישור המסמך | אושר סופית; שלב א' יוצא לדרך |

---

## 14. מה לא משתנה

- **חוזה ה-S-dict** - כל 52 הצ'ארטים ממשיכים לעבוד; הם לא יודעים
  אם ה-dict הגיע מקובץ מקומי או מה-API.
- **ליבת הצינור** - ‏`analyze_pcap` ממשיך לקבל PCAP גולמי, כמו
  היום. בזכות הכרעת סעיף 3 אין בו שום שינוי.
- **‏llm_judge** - הפאנל, ה-guardrail, ה-cache והכיול עובדים כמו
  שהם; ההרחבות (פרופילים, מכסות) מתווספות מסביב.
- **המחברת כמסלול עצמאי מלא** - ניתוח מקומי בלי VM ובלי רשת נשאר
  בדיוק כמו היום.
- **סוויטת הבדיקות** - ממשיכה לעבור ללא שינוי; כל שלב מוסיף בדיקות
  משלו.
- **מסלול ההדגמה הציבורי** - ‏fork + ‏Actions + ‏Issue ממשיך לעבוד
  למי שאין לו VM.
