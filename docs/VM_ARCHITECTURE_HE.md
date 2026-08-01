# ארכיטקטורת ה-VM המנתחת - מדריך עומק

מסמך זה מסביר לעומק מה קיים על המכונה הוירטואלית שמשמשת כמנתחת PCAP-ים
מרוחקת בפרויקט הזה. הוא כתוב עבור מי שרוצה להבין **מה** רץ שם, **למה**
זה רץ שם, **איך** הוא מדבר עם שאר הרכיבים, ו**מה קורה** לקובץ PCAP
מרגע שהוא נשלח למכונה ועד שהדוח נוחת בתיבת המייל.

כל מונח שיוצא-דופן מוסבר בפעם הראשונה שהוא מופיע - לא מונחות שום היכרות
מוקדמת עם Docker, HMAC, Tailscale, worker queue, sqlite migration, או
retention.

---

## תוכן העניינים

1. [רקע: מה זו בעצם "מכונה מנתחת"](#1-רקע-מה-זו-בעצם-מכונה-מנתחת)
2. [סקירה על-על של הארכיטקטורה](#2-סקירה-על-על-של-הארכיטקטורה)
3. [שכבת התקשורת: Tailscale](#3-שכבת-התקשורת-tailscale)
4. [שירותי המערכת - מה רץ ב-VM](#4-שירותי-המערכת---מה-רץ-ב-vm)
5. [Ingest API - נקודת הכניסה של PCAP](#5-ingest-api---נקודת-הכניסה-של-pcap)
6. [Worker - מנוע הניתוח שרץ מאחורי הקלעים](#6-worker---מנוע-הניתוח-שרץ-מאחורי-הקלעים)
7. [Retention - שירות תחזוקה שוטף](#7-retention---שירות-תחזוקה-שוטף)
8. [Ollama - LLM מקומי חופשי (אופציונלי)](#8-ollama---llm-מקומי-חופשי-אופציונלי)
9. [מסד הנתונים - SQLite ומעברי-סכמה](#9-מסד-הנתונים---sqlite-ומעברי-סכמה)
10. [ה-Panel של השופטים - LLM-as-Judge](#10-ה-panel-של-השופטים---llm-as-judge)
11. [Sensors ו-HMAC - איך זיהוי מכריע מי רשאי להעלות](#11-sensors-ו-hmac---איך-זיהוי-מכריע-מי-רשאי-להעלות)
12. [Retention ו-Data Lifecycle](#12-retention-ו-data-lifecycle)
13. [Reconciliation - זיהוי תעבורת המערכת עצמה](#13-reconciliation---זיהוי-תעבורת-המערכת-עצמה)
14. [נתונים טכניים: זיכרון, CPU, אחסון](#14-נתונים-טכניים-זיכרון-cpu-אחסון)
15. [גישה ל-VM](#15-גישה-ל-vm)
16. [Troubleshooting](#16-troubleshooting)

---

## 1. רקע: מה זו בעצם "מכונה מנתחת"

בפרויקט הזה יש שני מסלולים שבהם משתמש יכול לנתח קובץ PCAP:

- **מסלול מקומי**: המשתמש פותח את ה-notebook על המחשב שלו, טוען את
  ה-PCAP, וכל הניתוח (‏parsing עם tshark, אלגוריתמי ML, מנועי החוקים,
  ה-LLM Judge) רץ במקום, על אותה מכונה. יעיל להצצה חד-פעמית, אבל דורש
  שהמחשב יהיה מחובר לפייתון, ל-tshark, למפתחות LLM וכו'.

- **מסלול המכונה המנתחת** (‏זה מה שהמסמך הזה מסביר): המשתמש שולח
  את ה-PCAP במסלול HTTP מוצפן ל-VM ‏(שרת ענן), ה-VM מריץ *את אותו pipeline
  בדיוק* של הדשבורד, אבל בצד השרת, שומר את התוצאות ב-DB היסטורי, ושולח
  דוח למייל של המשתמש. המחשב של המשתמש יכול להיסגר תוך שנייה - הניתוח
  ממשיך לרוץ.

מה שהופך את זה ל"מכונה מנתחת" ולא רק "אחסון PCAP" הוא ש-**כל האלגוריתמים
שכתובים בדשבורד רצים גם על ה-VM**. הצד השרת לא מבצע גרסה שונה או פשוטה
יותר של הניתוח - הוא מבצע *אותו* קוד ‏(דרך מודול משותף `app/advanced_engines.py`
שחולץ במיוחד למטרה זו).

---

## 2. סקירה על-על של הארכיטקטורה

הארכיטקטורה בנויה מ-**ארבע שכבות** שמדברות אחת עם השנייה ברשת פרטית
(‏Tailscale, שנסביר בקרוב):

```
┌─────────────────────────────────────────────────────────────────┐
│ Tier 0 - Sensor (מקליט)                                          │
│  הלפטופ / בעתיד Raspberry Pi. מקליט את ה-PCAP (או טוען קובץ      │
│  קיים) ושולח ל-VM דרך HTTP חתום ב-HMAC.                          │
└──────────────────────┬──────────────────────────────────────────┘
                       │ POST /v1/pcap (streaming)
                       │ X-Sha256, X-Signature, X-Notify-Email
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│ Tier 1 - Analyzer VM (מנתח)                                      │
│  זו המכונה שהמסמך הזה מסביר.                                     │
│                                                                 │
│  ingest_api → sessions queue → worker → detection engines →    │
│               ↓                                    ↓            │
│         history DB                          reports/           │
└──────────────────────┬──────────────────────────────────────────┘
                       │ HTTPS to Groq / Gemini / Ollama
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│ Tier 2 - Judges (השופטים) - LLM Panel                            │
│  2-4 מודלים שמתדיינים על כל candidate. יכולים להיות סיפקים      │
│  שונים בו-זמנית: Groq (חינם, אבל rate limits), Gemini, Ollama   │
│  מקומי שרץ בעצמו על ה-VM.                                        │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│ Tier 3 - Consumers (צרכנים)                                      │
│  המייל של המשתמש (SMTP), הדשבורד המקומי כשהוא רוצה לראות דוח,  │
│  webhook ל-n8n (fallback אופציונלי).                            │
└─────────────────────────────────────────────────────────────────┘
```

**למה מפרידים לשכבות?** כי כל שכבה יכולה להתחלף בלי לשנות את שאר
המערכת:
- Sensor: יכול להיות לפטופ, Raspberry Pi, שרת ייעודי - כל מכשיר
  שיודע לחתום בקשה עם HMAC ולשלוח PCAP.
- Analyzer VM: יכול להיות Oracle ARM (‏כפי שכרגע), AWS, Hetzner, שרת
  ביתי - כל מקום שיריץ Docker + Tailscale.
- Judges: יכולים להיות Groq בלבד, Groq+Gemini+Ollama, רק Ollama (‏zero-key),
  או צירוף אחר - נשלט על ידי משתנה סביבה אחד ‏(`LLM_JUDGE_PANEL`).
- Consumers: המייל היום, וב-webhook לעתיד ל-Slack או Telegram אם רוצים.

---

## 3. שכבת התקשורת: Tailscale

**מה זה Tailscale?** שירות שבונה רשת פרטית מוצפנת בין המכשירים של
המשתמש. אחרי התקנה על 2 מחשבים (‏או יותר) הם מקבלים כתובות IP פרטיות
בטווח `100.x.x.x` שמפנות ישירות זה אל זה - **בלי** לעבור דרך שרת
אמצעי, בלי להיחשף לאינטרנט הפתוח, ובלי צורך ב-VPN קלאסי או SSH tunnel.

**איך זה נראה בפועל?**
- ה-VM שלנו מקבל כתובת Tailscale: `100.68.246.54`
- הלפטופ (‏Sensor) מקבל: `100.x.x.x` אחר
- שני המחשבים "רואים" אחד את השני כאילו הם באותה רשת מקומית, גם אם
  אחד באוסטרליה והשני בישראל

**למה זה חשוב לנו?**
1. שירותי הניתוח על ה-VM (‏ingest_api, ollama, וכו') מקשיבים **רק על
   ה-IP של Tailscale**, לא על 0.0.0.0. כלומר, אין דרך להגיע אליהם
   מהאינטרנט הפתוח - חייבים להיות מחוברים ל-Tailscale של המשתמש.
2. הפורט היחיד שכן חשוף לאינטרנט הפתוח הוא SSH (‏22), מוגן על ידי
   מפתח פרטי - אין סיסמאות בכלל.
3. iptables (‏חומת האש של הקרנל של Linux) מקבע את הכלל הזה: כל תעבורה
   נכנסת שלא מ-`tailscale0` (‏ה-interface של Tailscale) או מ-SSH -
   נדחית עם `icmp-host-prohibited`.

**איך יודעים ש-iptables ישרוד reboot?** בדוק שהחבילה `netfilter-persistent`
מותקנת ומופעלת: `systemctl is-enabled netfilter-persistent`. אם יוצא
`enabled`, הכללים ייטענו אוטומטית בכל אתחול מקובץ `/etc/iptables/rules.v4`.

---

## 4. שירותי המערכת - מה רץ ב-VM

ה-VM מריץ **Docker Compose** - כלי שמפעיל כמה services (‏שירותים) יחד
מקובץ הגדרות אחד ‏(`deploy/docker-compose.yml`). כל שירות רץ כ-**container**
נפרד, שזה בעצם תהליך Linux מבודד עם מערכת קבצים משלו.

**Docker Compose כרגע מרים 5 שירותים:**

| שירות | מה זה עושה | חייב? |
|---|---|---|
| `ingest_api` | מקבל PCAP-ים מהמשתמשים בבקשת HTTP חתומה, שומר לדיסק, מכניס לתור לניתוח | ✅ קריטי |
| `worker` | קורא מהתור, מריץ את ה-pipeline המלא, כותב תוצאות, שולח מייל | ✅ קריטי |
| `retention` | job יומי - מוחק PCAP-ים ישנים, מבצע VACUUM ל-DB, שומר גיבויים | ✅ מומלץ |
| `n8n` | פלטפורמת אוטומציה - fallback אם SMTP נכשל | אופציונלי |
| `ollama` | מריץ מודלי LLM מקומית על ה-VM (‏zero-key) | אופציונלי |

**מה זה container בפועל?** תהליך Linux שרואה רק את הקבצים שדחפו אליו
(‏ה-Dockerfile מגדיר איזה), לא רואה תהליכים אחרים במערכת, ומחובר לרשת
פנימית של docker בה כל container רואה את השאר בשם השירות (‏אם `worker`
רוצה לדבר עם `ollama`, הוא פשוט פונה ל-`http://ollama:11434` והרשת
של docker מתרגמת את זה ל-IP הפנימי).

**איך רואים מה רץ עכשיו?**
```bash
docker compose ps
```

תראה טבלה של השירותים החיים, כמה זמן הם למעלה, ואילו פורטים הם
פורסים. פורטים בפורמט `100.68.246.54:8766->8766/tcp` פירושם: השירות
מקשיב על פורט 8766 של ה-container, ומנופה ל-IP של Tailscale של
ה-VM על פורט 8766 מבחוץ.

---

## 5. Ingest API - נקודת הכניסה של PCAP

**מה זה בכלל "ingest"?** מונח שאול מ-data engineering, פירושו "לבלוע" -
לקבל נתונים לתוך המערכת מקבצי חוץ. בעולם שלנו, "ingest" הוא ה-endpoint
שמקבל את קובץ ה-PCAP מהמשתמש ומכניס אותו לתהליך הניתוח.

### הפורט ומיקום

`ingest_api` מקשיב על **פורט 8766** (‏TCP) בכתובת ה-Tailscale של ה-VM
בלבד. הוא לא נגיש מהאינטרנט. כדי להגיע אליו צריך להיות בתוך ה-tailnet
של המשתמש.

### מה קורה כשמעלים קובץ

1. הלקוח ‏(‏`tools/upload_pcap.py` או הדשבורד) מחשב `sha256` של הקובץ.
2. הלקוח חותם את השילוב `sha256:sensor_id:timestamp` עם **סוד HMAC**
   ‏(‏מפתח סודי שנוצר בעת יצירת ה-sensor) בגיבוב `SHA-256`.
3. הלקוח שולח `POST /v1/pcap` עם ה-headers הבאים:
   - `X-Sensor-Id`: מזהה ה-sensor
   - `X-Sha256`: הגיבוב של הקובץ
   - `X-Timestamp`: unix seconds
   - `X-Signature`: החתימה שחישבנו
   - `X-Notify-Email`: (אופציונלי) לאן לשלוח את הדוח
   - Content: הקובץ עצמו, streaming
4. `ingest_api` מוודא:
   - שהחתימה תקפה לפי ה-sensor שהוגדר (‏מוגן מפני "אנחנו לא יודעים
     מי אתה"),
   - שה-timestamp בטווח סביר (‏מוגן מפני replay attack),
   - שהקובץ שהתקבל *באמת* מגיע לאותו sha256 שהוצהר (‏מוגן מפני שינוי
     בדרך).
5. אם הכל תקין, הקובץ נשמר תחת `/srv/netsec/data/pcap/YYYY/MM/DD/<sha8>_<name>.pcap`,
   ונוצרת רשומה חדשה בטבלת `sessions` במסד הנתונים עם `status='queued'`.
6. תשובת ה-API מחזירה `session_id` (‏מספר רץ).

### דדופ אוטומטית

אם המשתמש מעלה את *אותו* קובץ פעם שנייה (‏אותו sha256 בדיוק), במקום
לקבל כפילות ה-API מזהה את זה ומחזיר את ה-session שכבר קיים עם דגל
`duplicate: true`. חוסך זמן ניתוח וזיכרון דיסק.

---

## 6. Worker - מנוע הניתוח שרץ מאחורי הקלעים

**מה זה worker?** תהליך רקע שעושה עבודה כבדה. לא מגיב לבקשות מהמשתמש -
במקום זאת, הוא בודק **תור** ‏(queue) של משימות ומטפל בכל אחת בסדר.

### לולאת ה-worker

```
כל 10 שניות:
  1. בדוק אם יש session עם status='queued'.
  2. אם יש - מרים אותו: status='running'.
  3. הרץ את הצינור המלא (~1-5 דק' תלוי בגודל ה-PCAP).
  4. כתוב תוצאות ל-DB + קבצי דוח לדיסק.
  5. שלח מייל למשתמש (אם הזין כתובת).
  6. סמן status='done' או 'error'.
```

### מה עובר ה-PCAP במהלך הניתוח

**שלב 1 - Parsing** (‏~10-30 שניות ל-16k packets):
- `tshark` (‏גרסת command-line של Wireshark) קורא את ה-PCAP ומייצא 26
  שדות רלוונטיים (‏IPs, פורטים, TCP flags, DNS queries, TLS SNI/JA3,
  ARP opcodes, DHCP server IDs וכו') לטבלת pandas.
- מ-Frame בסיסית, ה-pipeline בונה **פר-IP feature vector**: כמה חבילות
  יצאו ממנו, לאילו יעדים, מה ההתפלגות של גדלי חבילות, איזה TCP flags
  הופיעו, כמה DNS lookups עשה, וכו'.

**שלב 2 - Machine Learning** (‏~5 שניות):
- **IsolationForest**: אלגוריתם unsupervised שמזהה חריגים סטטיסטיים.
  מקבל את הווקטורים ומסמן אילו IPs "לא נראים כמו כולם" עם `iso_score`
  שלילי (‏ככל שיותר שלילי - יותר חריג).
- **DBSCAN**: אלגוריתם clustering שמזהה קבוצות סמוכות בפיצ'ר-ספייס.
  IPs שלא נכללים בשום cluster (‏cluster=-1) מסומנים כ-`dbscan_noise`.
- **LSTM** (‏עומק זמן): רשת נוירונית שמסתכלת על סדר הזמן של החבילות
  ומסמנת "פרצי בורות" - שניות שבהן ה-traffic חרג ממה שהמודל למד
  לצפות.

**שלב 3 - Rule Engines** (‏חוקים דטרמיניסטיים, ‏<1 שניה):
- **Horizontal port scan**: IP ששלח הרבה SYN-only packets ליעדים
  שונים בלי לגמור handshake.
- **SYN flood**: פרץ SYN מרוכז לאותו יעד.
- **DNS amplification**: תשובות DNS גדולות (‏>200 בתים ממוצע) שיוצאות
  מ-IP אחד למקורות רבים.
- **ARP multi-MAC**: אותו IP מוכרז דרך שני MAC addresses שונים - חתימה
  קלאסית של ARP spoofing / MITM.

**שלב 4 - Advanced MITRE-mapped detectors** (‏~5 שניות):
מנועים ממופים ל-MITRE ATT&CK, כל אחד מזהה חתימה שונה של תוקף:
- `arp_dhcp`: ARP spoofing + DHCP starvation
- `dns_tunnel`: DNS queries עם שמות מאוד ארוכים / entropy גבוה
- `dga`: Domain Generation Algorithms - שמות דומיין שנראים "רנדומליים"
- `beaconing`: תקשורת מחזורית (‏C2 callback)
- `tls`: JA3/JA4 nadir - חתימות TLS נדירות שיכולות להצביע על malware
- `fusion`: משקלל את כל האותות ומחזיר ציון סיכון לכל מכשיר

**שלב 5 - Assemble candidates** (‏<1 שנייה):
- כל IP שנתפס באיזשהו מנוע (‏ML או Rules או Advanced) הופך ל-"candidate"
  לשיפוט של ה-LLM.
- הצינור מגביל ל-40 candidates לכל היותר (‏`LLM_JUDGE_MAX_CANDIDATES=40`)
  כדי לא לגרר את ה-LLM ל-100+ קריאות.

**שלב 6 - LLM Panel** (‏~1-6 דק', תלוי כמה שופטים):
- כל candidate מוגש לפאנל של 2-4 מודלים בו-זמנית (‏ראה סעיף 10).
- אם ה-verdicts שונים, מתקיים סבב דיון אחד ‏(‏"debate round").
- resolver דטרמיניסטי מכריע בין הצדדים ‏(‏fail-safe: אם עדיין חלוקים -
  לוקח את הצד החמור, מסמן ⚖ REVIEW).

**שלב 7 - כתיבה לדיסק** (‏~2 שניות):
- `verdicts.json` - הפלט המלא של הפאנל
- `verdicts.md` - Markdown קריא לבן-אדם
- `report.html` - עם CSS לתצוגה בדפדפן
- `report.pdf` - נבנה עם `weasyprint`

**שלב 8 - Notification** (‏~3 שניות):
- אם `notify_email` הוגדר לסשן, שולח מייל SMTP עם הדוח PDF מצורף
- אם SMTP נכשל, נופל ל-`N8N_WEBHOOK_URL` (‏אם מוגדר)

### למה worker נפרד ולא callback ישיר ב-ingest_api?

בגלל שהניתוח לוקח 2-6 דקות, אם היינו מריצים אותו בתוך HTTP request
של ingest, הבקשה תעבור timeout. כך שאנחנו מקבלים תשובה מהירה ("קיבלתי
את הקובץ, session=3"), והמשתמש יכול לסגור את הלפטופ - הניתוח ימשיך.

---

## 7. Retention - שירות תחזוקה שוטף

**מה זה retention?** מונח שאול מהעולם של Data Warehousing, פירושו
"שימור" - הכללים שקובעים מתי לשמור נתונים ומתי למחוק אותם. שם ה-service
נובע מהתפקיד: לוודא שאנחנו לא צוברים דיסק לנצח.

### מה הוא עושה, אחת ליום

1. **מוחק PCAP-ים ישנים** מעל 7 ימים (‏`RETENTION_PCAP_DAYS=7`) - הרכיב
   הכבד ביותר בדיסק. עדיין נשמר `fields_export.tsv.gz` שהוא ייצוג
   דחוס של השדות שהוצאנו - זעיר, מהיר, ומספיק למרבית השאילתות
   הרטרואקטיביות.
2. **כשהדיסק מתחיל להתמלא** (‏>85%, `RETENTION_WATERMARK_PCT=85`): מוחק
   PCAP-ים ישנים אגרסיבית עוד לפני שהעברו 7 ימים.
3. **גיבוי DB יומי** ל-`/srv/netsec/db/backups/`. שומר 14 גיבויים
   ‏(‏`RETENTION_BACKUP_KEEP=14`).
4. **`VACUUM` על SQLite** - מפנה מקום פנוי בקובץ, שיפור ביצועים.
5. **פונג ל-healthchecks.io** (‏אם `NETSEC_HEARTBEAT_URL` מוגדר) - חיצוני
   שיודע אם ה-VM עדיין בחיים.

### למה חשוב שיהיה שירות נפרד?

כי ה-worker עסוק בניתוחים ולא צריך להאט בגלל שידוד ניקיון. הפרדה
מאפשרת ל-retention לרוץ בפעם אחת ביום, בלילה, בזמן שלרוב אין עומס.

---

## 8. Ollama - LLM מקומי חופשי (אופציונלי)

**מה זה Ollama?** פרויקט open-source שמאפשר להריץ מודלי LLM על CPU
מקומי (‏או GPU) עם command-line פשוט. אין צורך במפתח API, אין rate
limits, כל התעבורה נשארת פנימית.

### למה בכלל להריץ מקומית אם יש Groq בחינם?

- **Groq TPD limits**: 100k tokens ליום לכל מודל. אם מעלים הרבה PCAP-ים
  ‏(‏או משתמשים בפאנל של 4-5 שופטים), אפשר להיתקל ב-429.
- **פרטיות**: הפרומפט של השופט כולל את ה-candidate context (IPs, MAC
  addresses, שמות דומיין). מי שלא רוצה לשלוח את זה לספק חיצוני יכול
  לרוץ מקומית.
- **גיוון פאנל**: מודלי Ollama שונים במהותם מ-Groq (‏גדלים שונים,
  ארכיטקטורות שונות) - חוות דעת מגוונות יותר.

### מה מותקן ואיך

- ה-image `ollama/ollama:latest` רץ ב-container חדש.
- **לא נחשף ל-Tailscale** - אין `ports:` בהגדרה של docker-compose.
  רק ה-worker container רואה אותו דרך DNS פנימי של docker: `http://ollama:11434`.
- Volume בשם `ollama_models` שומר את המודלים שהורדנו - נשארים גם
  אחרי `docker compose down`.

### להוריד מודל

```bash
docker exec deploy-ollama-1 ollama pull llama3.1:8b
docker exec deploy-ollama-1 ollama pull qwen2.5:7b
docker exec deploy-ollama-1 ollama pull gemma2:9b
```

כל אחד ~5-6 GB, לוקח כ-3 דקות דרך רשת Oracle.

### להפעיל בפאנל

ב-`.env` על ה-VM:
```
LLM_JUDGE_PANEL=openai_compat:llama-3.3-70b-versatile,ollama:llama3.1,ollama:qwen2.5
```

אז `docker compose up -d --force-recreate worker` כדי לאסוף את השינוי.

### בענייני ביצועים

CPU-only inference על ARM 24GB:
- `llama3.1:8b`: ~2.5 tokens/sec = ~30-45 שניות per verdict
- `qwen2.5:7b`: ~3 tokens/sec = ~25-35 שניות per verdict
- `gemma2:9b`: ~2 tokens/sec = ~40-55 שניות per verdict

כלומר איטי משמעותית מ-Groq (‏~1 שנייה/verdict) אבל בחינם ובלי rate
limits.

---

## 9. מסד הנתונים - SQLite ומעברי-סכמה

### למה SQLite ולא PostgreSQL/MySQL?

- אנחנו מקבלים בקשה אחת אחת (‏worker רץ סדרתית) - אין חשש מ-write
  contention.
- SQLite הוא קובץ בודד - קל לגבות, לשקף בין סביבות, ולפתוח בכל דפדפן
  SQLite.
- אין תהליך נפרד להפעיל - הוא embedded בתהליך שקורא.
- 2 GB של נתונים = מהיר במיוחד; לא צריך שרת DB.

### WAL - Write-Ahead Logging

ה-DB פועל במצב WAL ‏(‏`PRAGMA journal_mode=WAL`), שזה שיטת כתיבה שמשפרת
concurrency: קוראים ‏(select) יכולים לרוץ בזמן שכותב (‏insert/update)
כותב. זה חשוב ל-`ingest_api` שרוצה לרשום telemetry_log בזמן שה-worker
מעדכן sessions.

### Schema versioning

השדה `PRAGMA user_version` מכיל את גרסת הסכמה. כשה-VM מרים את ה-DB
לראשונה, `db.migrate()` בודק את המספר ומריץ את כל ה-migrations שחסרים
עד `SCHEMA_VERSION` הנוכחי. כרגע:
- **v1**: יצירת כל הטבלאות הבסיסיות.
- **v2**: הוספת טבלת `enrichment` (‏Wigle/Shodan cache) + הוספת `map`
  לסוגי דוחות מותרים.
- **v3**: הוספת עמודת `notify_email` לטבלת `sessions` - כתובת המייל
  שהמשתמש הזין בעת ההעלאה.
- **v4**: הרחבת `panel_audit` ב-4 עמודות ‏(`stance`, `rebuttal`,
  `revised`, `needs_review`) + התחלת רישום per-candidate rows.

### הטבלאות בגדול

| טבלה | מטרה |
|---|---|
| `sensors` | הגדרות ה-sensors המורשים (name, HMAC secret, revoked_at) |
| `pcap_files` | כל קובץ PCAP שהתקבל (sha256 unique, storage_path, size) |
| `sessions` | ריצת ניתוח - state machine (queued → running → done/error) |
| `ip_features` | וקטור פיצ'רים לכל IP לכל סשן (mean_len, syn_count, iso_score...) |
| `findings` | התראות מהחוקים הדטרמיניסטיים (scan_alerts, flood_alerts...) |
| `adv_signals` | אותות המנועים המתקדמים (per device + peer, tactic, technique) |
| `fusion_scores` | ציון סיכון מאוחד לכל מכשיר בסשן |
| `candidates` | הקלט המדויק שנשלח לשופטי ה-LLM (JSON) |
| `verdicts` | הפלט של השופטים (JSON מלא + עמודות indexed) |
| `panel_audit` | תיעוד הדיון של הפאנל: per-(candidate, judge) rows |
| `reports` | נתיבים לקבצי הדוח (json/md/html/pdf/map) |
| `device_baselines` | history per-device לצורך "האם המכשיר הזה מתנהג כמו רגיל?" |
| `gaps` | חורים בהקלטה של ה-sensor (זמן שלא כוסה) |
| `llm_quota` | מונה טוקנים שהשתמשנו מכל ספק, לפי יום |
| `telemetry_log` | תיעוד תעבורת המערכת עצמה - ל-reconciliation (סעיף 13) |
| `enrichment` | cache של lookups חיצוניים (Wigle לוקציה של BSSID, Shodan reputation) |

---

## 10. ה-Panel של השופטים - LLM-as-Judge

### הרעיון

במקום להסתמך על מודל LLM יחיד ("מה חושב ChatGPT על זה?"), אנחנו מריצים
**וועדה** של מודלים שונים שכל אחד מגיע ממשפחה שונה, ומחייבים אותם
להסכים - או להסביר למה הם חולקים.

### שלבי הפאנל

**סיבוב 1 - עמדות עצמאיות (במקביל):**
כל שופט מקבל את ה-candidate בלי לדעת מה אמרו האחרים, ומחזיר:
```json
{"verdict": "malicious",
 "category": "arp_mitm",
 "confidence": 0.9,
 "evidence_features": [...],
 "reasoning": "..."}
```

הקריאות ל-N השופטים רצות במקביל דרך `ThreadPoolExecutor`, אז wall-clock
= max(A, B, C, D) במקום sum. עם 4 שופטים ב-Groq, זמן הריצה נשאר כמו
של השופט האיטי ביותר.

**Check for disagreement:**
`_panel_disagrees()` בודק אם ה-labels או ה-categories שונים בין
השופטים.

**סיבוב 2 - הדיון (רק אם יש מחלוקת):**
כל שופט מקבל *מחדש* את ה-candidate, אבל הפעם עם הפרומפט מציג לו את
עמדות העמיתים (אנונימיות: "Analyst 1", "Analyst 2") ומבקש ממנו:
- **stance**: `"maintain"` (אני נשאר בעמדתי) או `"revise"` (אני משנה).
- **rebuttal**: משפט של עד 300 תווים למה.
- verdict מעודכן ‏(אם revise).

גם הסיבוב הזה במקביל.

**Resolver (‏דטרמיניסטי, בלי LLM):**
לאחר סיבוב 2, `resolve_panel()` מקבל את כל העמדות ומחליט מה ה-verdict
"האפקטיבי" של הפאנל. הכללים:

| מצב | תוצאה | needs_review |
|---|---|---|
| כולם מסכימים על label+category | ה-confidence הגבוה ביותר | ❌ |
| כולם על אותו label, category שונה | הגבוה ב-confidence | ✅ |
| labels שונים | **הכי חמור** (malicious > suspicious > benign), הגבוה בו ב-confidence | ✅ |
| רק שופט אחד הצליח | ה-verdict שלו | ✅ (uncorroborated) |
| כולם נכשלו | ה-candidate נופל ל-`dropped` | - |

**המאפיין הקריטי:** אין `while` בשום מקום. אחרי סיבוב הדיון היחיד,
resolver מחליט וזה נגמר. **אין לופ אינסופי**. הפער שנשאר מסתובב בעולם
כ-⚖ REVIEW = נדרש עין אנושית.

### הפעלה

**LLM_JUDGE_PANEL** ‏ב-`.env`:
```
LLM_JUDGE_PANEL=openai_compat:llama-3.3-70b-versatile,openai_compat:openai/gpt-oss-20b
```

ריק = single-judge mode (הצינור פשוט קורא ל-`OPENAI_COMPAT_MODEL` פעם
אחת בלי resolver ובלי דיון).

**LLM_JUDGE_DEBATE=0** ל-single-round only (‏פאנל בלי דיון - כל שופט
מצביע פעם אחת, resolver מכריע ישר).

### מה בדיוק שולחים לשופטים? (‏Prompt + Blob + Verdict)

לכל candidate = קריאת HTTP אחת לכל שופט. אין קריאה אחת לכל ההקלטה. אם
5 IPs חשודים, ‏5 קריאות מקבילות לכל שופט. מה שרואה השופט:

**‏1. פרומפט המערכת (‏זהה לכל השופטים, לכל candidate, לא משתנה בזמן ריצה):**

```
You are a network-security triage analyst. You receive a JSON blob
describing one candidate (an IP, a flow, or the whole session) that at
least one unsupervised detector or deterministic rule has flagged.

1. Return a strict JSON object matching the schema below.
2. Assign a verdict (benign | suspicious | malicious) and category.
3. Ground every claim in the input blob - cite feature names in evidence_features.
4. If signals are contradictory, prefer "suspicious" over "malicious".
5. Never invent facts not in the blob. null = unknown, not zero.
6. recommended_action is a suggestion, not an action.
7. confidence is [0.0, 1.0]. reasoning: one paragraph, <=400 chars.
8. Deterministic rules are HIGH-PRECISION. If any rule fired, classify
   into the matching attack category and do NOT return "benign".
```

בנוסף מצטרפים ‏(‏1) ה-schema של ה-verdict, ‏(‏2) cheat-sheet של 7 הקטגוריות,
ו-(‏3) שתי דוגמאות מעובדות (‏SYN scan → malicious, ‏ML anomaly → benign).

**סה"כ פרומפט: ~1500 תווים.** מקור אמת: `llm_judge/judge_core.py` -
המשתנה `SYSTEM_PROMPT`.

**‏2. הבלוב של ה-candidate (‏JSON per-IP, ‏זה כל מה שהשופט רואה על ה-IP):**

```json
{
  "candidate_id": "192.168.1.10",
  "kind": "ip",
  "session_context": {"duration_s": 0.1, "total_packets": 2000, "total_ips": 2},
  "features": {
    "mean_len": 54.0, "std_len": 0.0, "count": 1000.0, "burst_score": 1000.0,
    "unique_dsts": 1.0, "syn_count": 0.0, "rst_count": 0.0, "fin_count": 0.0,
    "null_count": 0.0, "xmas_count": 1000.0
  },
  "ml_signals": {
    "iso_score": 0.0, "iso_stability": 0.0, "anomaly": false,
    "cluster": -1, "silhouette": null, "lstm_bin_flag_count": null
  },
  "rule_signals": {
    "scan_alerts": [{"type": "XMAS", "count": 1000, "unique_dsts": 1, "ratio": 1.0}],
    "flood_alerts": [], "amp_alerts": [], "arp_multi_mac": false
  },
  "advanced_signals": {"beaconing": null, "dns_tunneling": null,
                       "dga": null, "tls_anomaly": null, "fusion_score": null},
  "device_context": {"category": "unknown", "hostname": null, "oui_vendor": null},
  "enrichments": {"is_private": true, "reverse_dns": null,
                  "asn": null, "baseline_seen_before": null},
  "trigger_reasons": ["scan_rule"]
}
```

**מקור אמת:** `llm_judge/judge_core.py` - הפונקציה `assemble_candidates`.

**‏3. תשובת השופט (‏verdict schema):**

```json
{
  "verdict": "suspicious",
  "category": "port_scan",
  "confidence": 0.95,
  "evidence_features": ["rule_signals.scan_alerts", "features.xmas_count"],
  "reasoning": "The high burst score suggests a more sophisticated attack.",
  "recommended_action": "investigate"
}
```

השרתי עמידים מאומתים ב-`validate_verdict` - מנרמל ל-1 שורה, חותך את
reasoning ל-400 תווים, מעגל confidence ל-3 ספרות, ודוחה כל דבר מחוץ
לenums.

**מקור אמת מלא (‏עם דוגמאות ולכידויות):** [`docs/LLM_INTERFACE.md`](LLM_INTERFACE.md).

### מה חסר לשופט לדעת (‏העשרות מתוכננות)

הפייפליין אוסף הרבה יותר ממה שהשופט רואה. שדות שהשופט **לא** מקבל עכשיו,
אבל שהיו עוזרים לו:

| שדה | נאסף בפייפליין? | עלות הוספה |
|---|---|---|
| שם המכשיר + OUI vendor + קטגוריה | ✅ ‏(`device_classifier` + `build_local_inventory`) | נמוכה - `device_context` כבר בסכימה, רק צריך לאכלס |
| HTTP Host + TLS SNI + top DNS | ✅ ‏(`host_stats`) | נמוכה |
| Top-5 destination ports + protocol | ✅ | נמוכה |
| Hour of day + day of week | ✅ ‏(מ-`session_context.t0`) | טריוויאלית |
| bytes_in / bytes_out per IP | ⚠️ יש `total_bytes` אבל לא directional | בינונית |
| TLS versions + weak ciphers | ⚠️ יש `tls_anomaly` engine (‏score בלבד) | בינונית |
| Baseline history (‏האם ה-IP חדש?) | ✅ (‏`baseline` module) | בינונית |

---

## 11. Sensors ו-HMAC - איך זיהוי מכריע מי רשאי להעלות

### הבעיה שאנחנו פותרים

ה-VM חשוף ל-Tailscale, אבל מי אמר שכל *מכשיר* בתוך ה-tailnet רשאי
להעלות ל-ingest? רוצים controlled access - רק המכשירים שהמשתמש רשם
כ-sensor רשאים.

### איך זה עובד

**יצירת sensor:**
```bash
sudo python3 deploy/create_sensor.py my-laptop
```

הפקודה מייצרת שני מחרוזות אקראיות:
- `NETSEC_SENSOR_ID` - מזהה קריא ("my-laptop")
- `NETSEC_SENSOR_SECRET` - סוד HMAC ‏(‏64 hex chars, 256 bits של אקראיות)

ומדפיסה אותם **פעם אחת בלבד**. חובה לשמור אותם - אין דרך לשלוף מ-DB.

הסוד מאוחסן ב-`sensors.hmac_secret` ‏(‏עמודה TEXT). כן, בצורה גלויה
במסד - כי HMAC חייב לחשב מחדש את החתימה עם אותו סוד; אין אופציה
לשמור hash של הסוד. הגנה: ה-DB נגיש רק מ-root ומכל container.

### חתימת בקשה (‏client-side)

```python
signature = hmac.new(
    secret.encode(),
    f"{sha256}:{sensor_id}:{timestamp}".encode(),
    hashlib.sha256
).hexdigest()
```

### אימות (‏server-side)

`auth.verify_upload()` מחשב מחדש את החתימה עם הסוד המאוחסן ומשווה עם
`X-Signature`. חייבת להיות זהה. גם בודק:
- ה-sensor לא revoked (`revoked_at IS NULL`)
- ה-timestamp בטווח `NETSEC_HMAC_WINDOW_S=300` שניות (‏מונע replay)
- ה-sha256 של הבייטים שהתקבלו בפועל = מה שהוצהר ב-header (‏מונע tamper)

### ביטול sensor שנפרץ

```bash
sudo NETSEC_DATA_ROOT=/srv/netsec python3 -c "
from server import db
c = db.connect()
c.execute('UPDATE sensors SET revoked_at=DATETIME(\"now\") WHERE name=?', ('my-laptop',))
c.commit()"
```

ואז ליצור sensor חדש עם שם אחר.

---

## 12. Retention ו-Data Lifecycle

מה קורה לקובץ PCAP מרגע שהוא נכנס למערכת:

**יום 0 - קליטה:**
- הקובץ נשמר לדיסק תחת `/srv/netsec/data/pcap/YYYY/MM/DD/<sha8>_<name>.pcap`.
- ה-worker מנתח אותו, שומר field export ל-`/srv/netsec/data/fields/YYYY/MM/<sha8>.tsv.gz`.
- דוחות ב-`/srv/netsec/reports/<session_id>/`.
- כל הרשומות ב-DB (`pcap_files`, `sessions`, `ip_features`, `findings`,
  `adv_signals`, `candidates`, `verdicts`, `panel_audit`, `reports`,
  `telemetry_log`).

**יום 1-7 - שמירה מלאה:**
כל הקבצים והרשומות זמינים. אפשר לקרוא את ה-report.html או להוריד את
ה-PCAP הגולמי בחזרה.

**יום 8 ואילך - Retention purge:**
- ה-PCAP הגולמי נמחק מהדיסק.
- `pcap_files.deleted_at` מסומן, `pcap_files.storage_path` נשאר לצורך
  אודיט.
- ה-field export **נשאר** ‏(`KEEP_FIELDS_FOREVER=1`) - זעיר וסטטיסטית
  מספיק לשאילתות בעתיד.
- כל הרשומות ב-DB **נשארות** - היסטוריה של הניתוח מלאה.
- ה-reports **נשארים** ‏(PDFs).

**מתי מגיע ל-watermark (‏>85% של הדיסק):**
- retention מוחק PCAP-ים ישנים אגרסיבית עוד לפני 7 ימים.

**הבנות:**
- הצינור לא מוחק כלום מיוזמתו במהלך `worker`. רק retention מוחק.
- הגיבויים של ה-DB יורדים ל-`/srv/netsec/db/backups/backup_YYYYMMDD.db`,
  ‏14 גיבויים לפי `RETENTION_BACKUP_KEEP=14`.

---

## 13. Reconciliation - זיהוי תעבורת המערכת עצמה

### הבעיה

ה-sensor שלנו (‏הלפטופ) מקליט את התעבורה של ה-network. כשהוא מעלה
PCAP ל-`ingest_api`, הוא **בעצמו** יוצר תעבורה נוספת - שגם היא
נכללת ב-PCAP הבא שהוא יעלה. שני תרחישים בעייתיים:

1. **False positive**: ה-`ip_features` יראו את ה-IP של ה-VM מקבל
   הרבה חבילות משמעותיות ("‏dst אחד עם 900 packets") - עלול לצוץ
   כ-scan target.
2. **Loop**: הניתוח של תעבורת ההעלאה עצמה תיצור עוד verdict, שגם
   הוא יופיע במייל...

### הפתרון

טבלת `telemetry_log`:
- **מהצד של ה-sensor**: הלקוח (‏`tools/upload_pcap.py`) כותב שורה
  ב-`~/.netsec/telemetry.jsonl` בכל העלאה מוצלחת: `{started_at, ended_at, dst, dst_port, bytes_sent, file_sha256}`.
- **מהצד של ה-VM**: `ingest_api` כותב שורה ב-`telemetry_log` על כל
  בקשת POST שהתקבלה (`source='ingest_log'`).

בזמן הניתוח, ה-worker קורא את ה-`telemetry_log` וב-`reconcile.reconcile()`
מזהה אילו IPs ב-PCAP הנוכחי הם ה-sensor שלנו מדבר עם ה-VM - ומסמן אותם
כ-`self_telemetry=1` בטבלת `ip_features`. הפאנל לא רואה אותם בכלל.

### למה זה משהו יצירתי ולא ה-"allow list"?

Allow list נאיבי היה אומר "התעלם מ-100.68.246.54". אבל אם ה-VM נפרץ
ומישהו מתחיל להשתמש בו כפרוקסי, גם אנחנו לא היינו רואים את זה. עם
reconciliation אנחנו רק "מפחיתים תעבורה שאנחנו יודעים שנוצרה על ידינו",
לא "מכבים את ה-VM מהמעקב". כל תעבורה של ה-VM שאיננה בטבלה עדיין נבדקת.

---

## 14. נתונים טכניים: זיכרון, CPU, אחסון

**מפרט חומרה (‏Oracle Cloud Always Free ARM):**

| רכיב | ערך |
|---|---|
| CPU | 4 OCPU (Ampere Altra, ARM64) |
| RAM | 24 GB |
| דיסק | 96 GB (boot volume) |
| Bandwidth | 10 Gbps (הוא ה-oracle limit) |

**צריכת זיכרון בפועל** (‏מבוססת על מדידה):

| container | RAM | CPU idle | CPU בעומס |
|---|---|---|---|
| `ingest_api` | 32 MB | 0% | ~10% במהלך upload |
| `worker` | 413 MB | 0% | 40-70% במהלך parse+ML |
| `retention` | 15 MB | 0% | ~5% פעם ביום |
| `n8n` | ~200 MB | 0% | - |
| `ollama` (עם llama3.1:8b טעון) | ~5 GB | 0% | ~350% (‏3.5 CPU cores) בעת inference |

**סה"כ בזמן idle:** ~700 MB. **בזמן ניתוח פעיל:** ~1.5 GB.
עם Ollama פעיל: +5 GB לכל מודל טעון.

**דיסק בפועל** (‏אחרי חודש שימוש):
- `/srv/netsec/data/pcap/`: ~2 GB (‏PCAPs של 7 ימים)
- `/srv/netsec/data/fields/`: ~50 MB (‏gzipped exports)
- `/srv/netsec/reports/`: ~100 MB (‏HTMLs + PDFs)
- `/srv/netsec/db/`: 2-5 MB (‏SQLite) + ~30 MB backups
- Docker images (ollama_models, כשמותקן): ~16 GB
- Docker layers (worker, ingest, retention, n8n): ~15 GB
- מערכת Ubuntu + Tailscale + kernel: ~4 GB
- **סה"כ:** ~40 GB מתוך 96 = 42% ‏(‏עם Ollama מלא).

---

## 15. גישה ל-VM

### SSH

```bash
ssh -i C:\path\to\netsec-agent.key\ssh-key-2026-07-12.key ubuntu@100.68.246.54
```

**שיפור נוח:** להוסיף לקובץ `~/.ssh/config`:
```
Host netsec-vm
  HostName 100.68.246.54
  User ubuntu
  IdentityFile C:\Users\OR\.ssh\netsec-agent.key\ssh-key-2026-07-12.key
  ServerAliveInterval 60
```

ואז פשוט `ssh netsec-vm`.

### עדכון קוד ב-VM אחרי push לגית

```bash
cd ~/netsec
git pull --ff-only origin main
cd deploy
docker compose build worker ingest_api
docker compose up -d --force-recreate worker ingest_api
```

**חשוב:** `up -d --force-recreate` **בלי `build` קודם** יריץ מחדש את
אותה תמונת container ישנה. Dockerfile משתמש ב-`COPY . .` שמכניס את
הקוד בזמן BUILD, לא בזמן run.

### לצפות בלוגים חיים

```bash
docker compose logs -f worker
# Ctrl+C ליציאה
```

### להריץ פקודה בתוך container

```bash
docker exec deploy-worker-1 python3 -c "print('hello from worker')"
# או שאילתת DB דרך ingest_api container (שיש לו גישה לאותו סוקט):
docker compose exec -T ingest_api python3 -c "from server import db; ..."
```

### בדיקה מהירה שהכל בסדר

```bash
curl -sS http://100.68.246.54:8766/healthz
# צריך להחזיר {"status":"ok","schema":4}

docker compose ps
# צריך להראות ingest_api + worker + retention כ-Up
```

---

## 16. Troubleshooting

### `curl /healthz` נכשל עם timeout

- `tailscale status` על הלפטופ - האם ה-VM ברשימה?
- `docker compose ps` על ה-VM - האם ingest_api Up?
- `sudo iptables -L INPUT -n --line-numbers` - האם REJECT rule חוסם
  אותך? (‏רק Tailscale + SSH מותרים)

### Worker לא מתקדם, `docker top deploy-worker-1` מראה 0% CPU

- כנראה תקוע על HTTP call ל-LLM שלא חוזר. ‏429? DNS?
- `docker compose logs --tail=30 worker | grep -i "rate\|error\|429"`

### עדכון קוד לא הגיע ל-container

- `docker exec deploy-worker-1 grep -c "SOME_NEW_STRING" /app/server/worker.py`
- אם 0 → צריך `docker compose build worker` אחרי `git pull`.

### מייל לא מגיע

- `docker compose logs worker | grep "notify"` - איזה path נסלט?
- אם `[smtp]: SMTP authentication failed` → הסיסמה של Google לא app-password
  ‏(‏חייבת להיות 16 תווים ממש, לא הסיסמה הרגילה).
- Google מבטלת app-passwords שלא היו בשימוש 6 חודשים - ליצור חדש
  ב-myaccount.google.com/apppasswords.

### שגיאת `no such column: notify_email`

- ה-DB לא עלה למvרסת סכמה 3 או 4. `docker compose exec ingest_api
  python3 -c "from server import db; c=db.connect(); print(c.execute('PRAGMA user_version').fetchone())"` → צריך להיות `(4,)`.
- אם קטן מ-4: הקוד עדכני אבל ה-DB לא מיגר. בדוק `docker compose logs
  worker | grep -i migrate`.

### Ollama לא מגיב

- `docker compose ps ollama` - Up?
- `docker exec deploy-ollama-1 ollama list` - איזה מודלים טעונים?
- `docker exec deploy-worker-1 curl -sS http://ollama:11434/api/tags`
  - האם ה-worker רואה את ה-Ollama container?

---

*המסמך מתעדכן ככל שהמערכת מתפתחת. שינויי סכמה גדולים או שירותים
חדשים - נוספים לסעיפים הרלוונטיים.*
