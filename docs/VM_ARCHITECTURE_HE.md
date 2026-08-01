# ארכיטקטורת ה-VM המנתחת - מדריך עומק

<div dir="rtl">

מסמך זה מסביר לעומק מה קיים על המכונה הוירטואלית שמשמשת כמנתחת PCAP-ים
מרוחקת בפרויקט הזה. הוא כתוב עבור מי שרוצה להבין **מה** רץ שם, **למה**
זה רץ שם, **איך** הוא מדבר עם שאר הרכיבים, ו**מה קורה** לקובץ PCAP
מרגע שהוא נשלח למכונה ועד שהדוח נוחת בתיבת המייל.

כל מונח שיוצא-דופן מוסבר בפעם הראשונה שהוא מופיע - לא מונחות שום היכרות
מוקדמת עם Docker, HMAC, Tailscale, worker queue, sqlite migration, או
retention.

**עדכון אחרון:** ‏2026-08-01 (‏prompt v0.4.0, ‏פאנל של 4 שופטים, ‏schema v4).

</div>

---

<div dir="rtl">

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
17. [הוספת ספק LLM חדש לפאנל](#17-הוספת-ספק-llm-חדש-לפאנל)
18. [מצבי כשל ומה קורה בכל אחד](#18-מצבי-כשל-ומה-קורה-בכל-אחד)
19. [היסטוריית גרסאות ה-prompt](#19-היסטוריית-גרסאות-ה-prompt)

</div>

---

<div dir="rtl">

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

</div>

---

<div dir="rtl">

## 2. סקירה על-על של הארכיטקטורה

הארכיטקטורה בנויה מ-**ארבע שכבות** שמדברות אחת עם השנייה ברשת פרטית
(‏Tailscale, שנסביר בקרוב):

</div>

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

<div dir="rtl">

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

**קוד המפתח של iptables של ה-VM** (‏אחרי `bootstrap.sh`):

</div>

```bash
# רק Tailscale + SSH נכנסים; שאר האינטרנט נדחה
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -i tailscale0 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -j REJECT --reject-with icmp-host-prohibited
```

<div dir="rtl">

</div>

---

<div dir="rtl">

## 4. שירותי המערכת - מה רץ ב-VM

ה-VM מריץ **Docker Compose** - כלי שמפעיל כמה services (‏שירותים) יחד
מקובץ הגדרות אחד ‏(`deploy/docker-compose.yml`). כל שירות רץ כ-**container**
נפרד, שזה בעצם תהליך Linux מבודד עם מערכת קבצים משלו.

**Docker Compose כרגע מרים 5 שירותים:**

| שירות | מה זה עושה | חייב? | סטטוס נוכחי |
|---|---|---|---|
| `ingest_api` | מקבל PCAP-ים מהמשתמשים בבקשת HTTP חתומה, שומר לדיסק, מכניס לתור לניתוח | ✅ קריטי | Up 13h+ |
| `worker` | קורא מהתור, מריץ את ה-pipeline המלא, כותב תוצאות, שולח מייל | ✅ קריטי | Up (‏מתחדש בעת deploy) |
| `retention` | job יומי - מוחק PCAP-ים ישנים, מבצע VACUUM ל-DB, שומר גיבויים | ✅ מומלץ | Up 24h+ |
| `n8n` | פלטפורמת אוטומציה - fallback אם SMTP נכשל | אופציונלי | Up 2d+ |
| `ollama` | מריץ מודלי LLM מקומית על ה-VM (‏zero-key, ‏qwen2.5:3b טעון) | אופציונלי אבל נדרש לפאנל 4-שופטים | Up |

**מה זה container בפועל?** תהליך Linux שרואה רק את הקבצים שדחפו אליו
(‏ה-Dockerfile מגדיר איזה), לא רואה תהליכים אחרים במערכת, ומחובר לרשת
פנימית של docker בה כל container רואה את השאר בשם השירות (‏אם `worker`
רוצה לדבר עם `ollama`, הוא פשוט פונה ל-`http://ollama:11434` והרשת
של docker מתרגמת את זה ל-IP הפנימי).

**איך רואים מה רץ עכשיו?**

</div>

```bash
docker compose ps
```

<div dir="rtl">

תראה טבלה של השירותים החיים, כמה זמן הם למעלה, ואילו פורטים הם
פורסים. פורטים בפורמט `100.68.246.54:8766->8766/tcp` פירושם: השירות
מקשיב על פורט 8766 של ה-container, ומנופה ל-IP של Tailscale של
ה-VM על פורט 8766 מבחוץ.

</div>

---

<div dir="rtl">

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

**קוד המפתח של חתימת ה-HMAC** (‏מ-`tools/upload_pcap.py`, ‏משותף עם ‏`server/auth.py`):

</div>

```python
def _signature(secret, file_sha256, sensor_id, timestamp):
    # server/auth.py::upload_signature - the exact mirror
    import hmac, hashlib
    msg = f"{file_sha256}:{sensor_id}:{int(timestamp)}"
    return hmac.new(secret.encode("utf-8"),
                    msg.encode("utf-8"),
                    hashlib.sha256).hexdigest()
```

<div dir="rtl">

### דדופ אוטומטית

אם המשתמש מעלה את *אותו* קובץ פעם שנייה (‏אותו sha256 בדיוק), במקום
לקבל כפילות ה-API מזהה את זה ומחזיר את ה-session שכבר קיים עם דגל
`duplicate: true`. חוסך זמן ניתוח וזיכרון דיסק.

</div>

---

<div dir="rtl">

## 6. Worker - מנוע הניתוח שרץ מאחורי הקלעים

**מה זה worker?** תהליך רקע שעושה עבודה כבדה. לא מגיב לבקשות מהמשתמש -
במקום זאת, הוא בודק **תור** ‏(queue) של משימות ומטפל בכל אחת בסדר.

### לולאת ה-worker

</div>

```
כל 10 שניות:
  1. בדוק אם יש session עם status='queued'.
  2. אם יש - מרים אותו: status='running'.
  3. הרץ את הצינור המלא (~1-5 דק' תלוי בגודל ה-PCAP).
  4. כתוב תוצאות ל-DB + קבצי דוח לדיסק.
  5. שלח מייל למשתמש (אם הזין כתובת).
  6. סמן status='done' או 'error'.
```

<div dir="rtl">

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

### הפעלת ה-pipeline - קטע קוד מרכזי מ-`server/worker.py`

</div>

```python
# Simplified skeleton of server/worker.py::run_once
def run_once(conn, analyze_fn=None, md_fn=None):
    row = db.claim_next_job(conn)   # atomic dequeue: queued -> running
    if row is None:
        return None                  # nothing to do this cycle
    sid = row["session_id"]
    pcap_path = row["storage_path"]
    try:
        # Delegate to the injected pipeline (real one = judge_cli.analyze_and_judge)
        out, assembled, client, context, S, findings = (analyze_fn or
            _default_analyze_and_judge)(pcap_path, label=row["label"],
                                         return_session=True)
        results.write_all(conn, sid, S, findings, out, client, context)
        report_html.render(conn, sid, out, context, md_fn=md_fn)
        report_pdf.render(conn, sid)
        _notify(conn, sid, row["notify_email"], out, context)
        db.mark_done(conn, sid, n_pkts=S["n_pkts"],
                     n_ips=len(S["ips_src"]))
    except Exception as e:
        db.mark_error(conn, sid, str(e))
        raise
```

<div dir="rtl">

**עיקרון הבידוד**: `analyze_fn` ו-`md_fn` הן dependency injection. ב-tests
מזריקים stubs שלא דורשים tshark/LLM/GPU. ב-production הם נטענים ממודולי
`judge_cli` ו-`report_html` בפועל.

</div>

---

<div dir="rtl">

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

</div>

---

<div dir="rtl">

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

### המודל הנוכחי שרץ בפאנל: `qwen2.5:3b`

לאחר בדיקות (‏אוגוסט 2026):
- **qwen2.5:3b נבחר** - ‏1.9GB, ‏מדויק על scan candidates, ‏~55s per verdict
- **llama3.2:3b נפסל** - ‏2GB, ‏hallucinated benign על scan (‏חובה
  לפעיל את הguardrail)
- **מודלים 7B+ נפסלו** - איטיים מדי (‏~50s לverdict *לפני* שכל מודל
  אחר מוסיף עומס RAM)

### להוריד מודל

</div>

```bash
docker exec deploy-ollama-1 ollama pull qwen2.5:3b     # 1.9 GB - הנוכחי בפאנל
docker exec deploy-ollama-1 ollama pull llama3.2:3b    # אלטרנטיבה, פחות מדויק
docker exec deploy-ollama-1 ollama pull qwen2.5:14b    # אם יש GPU בעתיד
```

<div dir="rtl">

כל אחד ~1-6 GB, לוקח כ-1-3 דקות דרך רשת Oracle.

### להפעיל בפאנל

ב-`.env` על ה-VM (‏זו ההגדרה הנוכחית):

</div>

```bash
LLM_JUDGE_PANEL=groq:llama-3.1-8b-instant,groq:llama-3.3-70b-versatile,ollama:qwen2.5:3b,gemini:gemini-2.5-flash
```

<div dir="rtl">

אז `docker compose up -d --force-recreate worker` כדי לאסוף את השינוי.

### בענייני ביצועים

CPU-only inference על ARM Neoverse-N1 4-vCPU, 24GB RAM ‏(‏מדוד):

| מודל | RAM | Tokens/sec | ‏זמן per verdict |
|---|---|---|---|
| `qwen2.5:3b` (‏נוכחי) | ~2.4 GB | ~15-20 | ~53s |
| `llama3.2:3b` | ~2.5 GB | ~15-18 | ~55s |
| `llama3.1:8b` | ~4.9 GB | ~2.5 | ~30-45s |
| `qwen2.5:7b` | ~4.7 GB | ~3 | ~25-35s |
| `gemma2:9b` | ~5.4 GB | ~2 | ~40-55s |

כלומר איטי משמעותית מ-Groq (‏~1 שנייה/verdict) אבל בחינם ובלי rate
limits. גיוון הבחירה בין qwen ל-llama נקבע לפי דיוק - qwen מדויק יותר
על scan candidates של ה-benchmark שלנו.

---

</div>

---

<div dir="rtl">

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

**קוד המפתח של ה-migration** (‏מ-`server/db.py`):

</div>

```python
def migrate(conn):
    """Idempotent schema migration. Uses PRAGMA user_version as the version
    counter so downgrades are detectable and reruns are safe."""
    v = conn.execute("PRAGMA user_version").fetchone()[0]
    if v < 1: conn.executescript(_SCHEMA_V1); v = 1
    if v < 2: conn.executescript(_SCHEMA_V2); v = 2
    if v < 3: conn.executescript(_SCHEMA_V3); v = 3
    if v < 4: conn.executescript(_SCHEMA_V4); v = 4
    if v > SCHEMA_VERSION:
        raise RuntimeError(
            f"DB is at schema v{v}, code only knows v{SCHEMA_VERSION}. "
            "Downgrade is not supported - restore an older backup.")
    conn.execute(f"PRAGMA user_version = {v}")
    conn.commit()
```

<div dir="rtl">

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

<div dir="rtl">

## 10. ה-Panel של השופטים - LLM-as-Judge

### הרעיון

במקום להסתמך על מודל LLM יחיד ("מה חושב ChatGPT על זה?"), אנחנו מריצים
**וועדה** של מודלים שונים שכל אחד מגיע ממשפחה שונה, ומחייבים אותם
להסכים - או להסביר למה הם חולקים.

### 4 השופטים הנוכחיים ב-VM (‏אוגוסט 2026)

הפאנל שרץ עכשיו על ה-VM ‏(`deploy/.env` ← `LLM_JUDGE_PANEL`):

| # | Provider | מודל | ‏פורמט מפתח | ‏Latency ב-VM | ‏Free-tier |
|---|---|---|---|---|---|
| 1 | Groq | `llama-3.1-8b-instant` | ‏Groq key ‏(`gsk_...`) | ~500ms | 100k tokens/day |
| 2 | Groq | `llama-3.3-70b-versatile` | ‏אותו key | ~700ms | 100k tokens/day |
| 3 | Ollama (‏local) | `qwen2.5:3b` | ‏zero-key | ~55s (‏CPU-only ARM) | ‏מקומי - ‏unlimited |
| 4 | Gemini | `gemini-2.5-flash` | ‏AI Studio ‏(`AQ...` ‏Bearer) | ~1-2s | 15 RPM, ‏1M tokens/day |

**Wall-clock של הפאנל = max(‏כל 4)** ‏(‏ThreadPoolExecutor רץ במקביל).
qwen2.5:3b הוא bottleneck על ARM CPU ‏(~55s per verdict), אז candidate
בודד לוקח כדקה. ב-PCAP עם 5 candidates: ‏~5 דקות end-to-end.

**למה davka 4 שופטים?** ‏(‏decision IDX-06):
- **diversity**: ‏שני מודלי Meta (‏Llama 8B ו-70B) ‏+ ‏Google (‏Gemini) ‏+ ‏Alibaba (‏Qwen).
  כל אחד מאומן על corpus שונה, ומגיע לverdict מזוית אחרת. גיוון כזה
  מקטין את הסיכוי שכולם יטעו יחד באותה טעות.
- **Fault-tolerance**: ‏אפילו אם 2 שופטים נופלים ‏(‏rate-limit, timeout,
  ‏broken model), ה-resolver עדיין מקבל 2 verdicts תקפים ומסוגל להכריע.
- **Free-tier headroom**: ‏Groq נותן 100k tokens ליום *לכל מודל* - שני
  Groq שונים = כפל quota. Ollama בכלל לא סופר. Gemini עוד 1M tokens.

### שלבי הפאנל

**סיבוב 1 - עמדות עצמאיות (במקביל):**
כל שופט מקבל את ה-candidate בלי לדעת מה אמרו האחרים, ומחזיר:

</div>

```json
{"verdict": "malicious",
 "category": "arp_mitm",
 "confidence": 0.9,
 "evidence_features": ["rule_signals.arp_multi_mac", "features.count"],
 "reasoning": "..."}
```

<div dir="rtl">

הקריאות ל-N השופטים רצות במקביל דרך `ThreadPoolExecutor`, אז wall-clock
= max(A, B, C, D) במקום sum. עם 4 שופטים ב-Groq, זמן הריצה נשאר כמו
של השופט האיטי ביותר.

**קטע קוד מרכזי מ-`llm_judge/judge_core.py` (‏פונקציה `judge_candidates_panel`):**

</div>

```python
_pool = concurrent.futures.ThreadPoolExecutor(
    max_workers=max(len(clients), 1),
    thread_name_prefix="panel-judge")
try:
    for i, cand in enumerate(candidates, 1):
        # Round 1: fan out per candidate to N judges in parallel.
        client_results = list(_pool.map(
            lambda cl: _verdict_from_client(cand, cl, cache, prompt_version),
            clients))
        # ... build positions[] with each judge's verdict + status
        valid = [p for p in positions if p["verdict"] is not None]
        did_debate = False
        if (debate and len(valid) >= 2
                and _panel_disagrees([p["verdict"] for p in valid])):
            did_debate = True
            # Round 2: each judge sees peers' analyses, revises or defends.
            debate_results = list(_pool.map(_one_debate, valid))
            # ... update each position with revised verdict + stance + rebuttal
        effective, info = resolve_panel(positions)
        # ... write to DB (panel_audit rows per candidate + per judge)
finally:
    _pool.shutdown(wait=True)
```

<div dir="rtl">

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

**דוגמת debate rebuttal אמיתית** (‏session 6, ‏xmas scan, ‏v0.4.0):
`llama-3.3-70b-versatile` (‏stance: maintain):

> *"Analysts 1 and 3 agree the scan rule fired, but 'suspicious'
> underestimates the threat; 1000 XMAS packets against one destination
> is a clear malicious indicator."*

`qwen2.5:3b` (‏stance: revise):

> *"The high burst score suggests a more sophisticated attack."*

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

**הקוד המדויק של ה-resolver** ‏(‏מ-`judge_core.py`):

</div>

```python
def resolve_panel(positions):
    valid = [p for p in positions if p["verdict"] is not None]
    if not valid:
        return None, {"agreement": False, "needs_human_review": True,
                      "note": "every panel judge failed"}
    if len(valid) == 1:
        return dict(valid[0]["verdict"]), {
            "agreement": False, "needs_human_review": True,
            "note": "only one panel judge returned a valid verdict"}
    labels = {p["verdict"]["verdict"] for p in valid}
    cats = {p["verdict"]["category"] for p in valid}
    if len(labels) == 1 and len(cats) == 1:            # ← consensus
        eff = max(valid, key=lambda p: p["verdict"]["confidence"])
        return dict(eff["verdict"]), {"agreement": True,
                                       "needs_human_review": False,
                                       "note": None}
    if len(labels) == 1:                                # ← same label, split cat
        eff = max(valid, key=lambda p: p["verdict"]["confidence"])
        return dict(eff["verdict"]), {
            "agreement": False, "needs_human_review": True,
            "note": "judges agree on the verdict but dispute the category"}
    worst = max(labels, key=lambda v: SEVERITY[v])      # ← labels split
    side = [p for p in valid if p["verdict"]["verdict"] == worst]
    eff = max(side, key=lambda p: p["verdict"]["confidence"])
    return dict(eff["verdict"]), {
        "agreement": False, "needs_human_review": True,
        "note": "judges disagree after debate; using the more severe verdict"}
```

<div dir="rtl">

**המאפיין הקריטי:** אין `while` בשום מקום. אחרי סיבוב הדיון היחיד,
resolver מחליט וזה נגמר. **אין לופ אינסופי**. הפער שנשאר מסתובב בעולם
כ-⚖ REVIEW = נדרש עין אנושית.

### הפעלה

**LLM_JUDGE_PANEL** ‏ב-`.env` על ה-VM (‏ההגדרה הנוכחית):

</div>

```bash
LLM_JUDGE_PANEL=groq:llama-3.1-8b-instant,groq:llama-3.3-70b-versatile,ollama:qwen2.5:3b,gemini:gemini-2.5-flash
```

<div dir="rtl">

**ריק** = single-judge mode (הצינור פשוט קורא ל-`OPENAI_COMPAT_MODEL` פעם
אחת בלי resolver ובלי דיון).

**LLM_JUDGE_DEBATE=0** ל-single-round only (‏פאנל בלי דיון - כל שופט
מצביע פעם אחת, resolver מכריע ישר).

**עלות בפועל** (‏מדוד על ‏session 6, ‏xmas_scan, ‏candidate בודד):
- Groq llama-8b: ‏~460ms, ‏~1200 tokens (‏prompt+response)
- Groq llama-70b: ‏~715ms, ‏~1200 tokens
- Ollama qwen 3b: ‏~52700ms (‏CPU-bound), ‏~1200 tokens (‏חופשי)
- Gemini flash: ‏~1500ms (‏באזור הצפוני), ‏~1300 tokens

**סך הכל טוקנים ליום** על 5 sessions * 3 candidates ממוצע = ‏~18k tokens/day
per Groq model, ‏רחוק מ-100k limit.

### קוד מרכזי - בניית ה-clients

מ-`llm_judge/llm_clients.py`, ‏פונקציה `make_panel_clients`:

</div>

```python
def make_panel_clients(entries, verdict_schema=None):
    """Build one client per (provider, model) panel entry.

    Construction failures (e.g. the anthropic package missing for a claude
    entry) do not abort the whole panel: the failed entry is recorded and
    the remaining judges carry on - the panel's whole point is surviving
    the loss of one expert. Returns (clients, init_failures) where
    init_failures is [{"entry", "error"}].
    """
    clients, init_failures = [], []
    for provider, model in entries:
        try:
            clients.append(make_client(provider=provider,
                                       verdict_schema=verdict_schema,
                                       model=model))
        except Exception as e:
            init_failures.append({"entry": f"{provider}:{model}",
                                  "error": str(e)})
    return clients, init_failures
```

<div dir="rtl">

**הרעיון בקוד הזה**: אם 1 מ-4 שופטים לא מצליח להיבנות (‏חסר מפתח, ‏פרויקט לא
מוגדר, ‏מודל לא נמצא) - שאר ה-3 עדיין רצים. הפאנל שורד את אובדן של יחיד.

### מה בדיוק שולחים לשופטים? (‏Prompt + Blob + Verdict)

לכל candidate = קריאת HTTP אחת לכל שופט. אין קריאה אחת לכל ההקלטה. אם
5 IPs חשודים, ‏5 קריאות מקבילות לכל שופט. מה שרואה השופט:

**‏1. פרומפט המערכת (‏זהה לכל השופטים, לכל candidate, לא משתנה בזמן ריצה):**

</div>

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

<div dir="rtl">

בנוסף מצטרפים ‏(‏1) ה-schema של ה-verdict, ‏(‏2) cheat-sheet של 7 הקטגוריות,
ו-(‏3) שתי דוגמאות מעובדות (‏SYN scan → malicious, ‏ML anomaly → benign).

**סה"כ פרומפט: ~1500 תווים.** מקור אמת: `llm_judge/judge_core.py` -
המשתנה `SYSTEM_PROMPT`.

**‏2. הבלוב של ה-candidate (‏JSON per-IP, ‏זה כל מה שהשופט רואה על ה-IP):**

</div>

```json
{
  "candidate_id": "192.168.1.10",
  "kind": "ip",
  "session_context": {
    "duration_s": 0.1, "total_packets": 2000, "total_ips": 2,
    "iso_timestamp": "2026-08-01T09:41:00",
    "hour_of_day": 9, "day_of_week": "Sat"
  },
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
  "device_context": {"category": "unknown",
                     "hostname": "orarr-macbook.local",
                     "oui_vendor": "Apple, Inc."},
  "websites": {
    "top_http_hosts": null,
    "top_tls_sni": [{"host": "cloudflare.com", "count": 87}],
    "top_dns_queries": [{"host": "evil-c2.duckdns.org", "count": 128}]
  },
  "traffic": {
    "top_dst_ports": [{"port_proto": "443/tcp", "count": 900}],
    "bytes_in": 3000000, "bytes_out": 1000000, "upload_ratio": 0.25
  },
  "enrichments": {"is_private": true, "reverse_dns": null,
                  "asn": null, "baseline_seen_before": null},
  "trigger_reasons": ["scan_rule"]
}
```

<div dir="rtl">

**מקור אמת:** `llm_judge/judge_core.py` - הפונקציה `assemble_candidates`.

**‏3. תשובת השופט (‏verdict schema):**

</div>

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

<div dir="rtl">

השדות ב-verdict מאומתים ב-`validate_verdict` - מנרמל ל-1 שורה, חותך את
reasoning ל-400 תווים, מעגל confidence ל-3 ספרות, ודוחה כל דבר מחוץ
ל-enums.

**מקור אמת מלא (‏עם דוגמאות ותוצאות):** [`docs/LLM_INTERFACE.md`](LLM_INTERFACE.md).

### מה נוסף לשופט ב-I2 (‏2026-08-01, ‏prompt v0.4.0)

הוספנו 5 העשרות שהשופט רואה כעת בכל candidate blob:

| שדה | מקור | דוגמה |
|---|---|---|
| `session_context.iso_timestamp` + `.hour_of_day` + `.day_of_week` | מ-`S["t0"]` | `"09"`, `"Sat"` - סריקה ב-3AM Sun מקבלת ניקוד גבוה יותר |
| `device_context.oui_vendor` + `.hostname` | `manuf` package + mDNS `.local` | `"Apple, Inc."`, `"orarr-macbook.local"` |
| `websites.top_http_hosts` + `.top_tls_sni` + `.top_dns_queries` | tshark חדש: `http.host`, `tls.handshake.extensions_server_name` | `[{"host": "api.example.com", "count": 42}, ...]` (‏top 5) |
| `traffic.top_dst_ports` | groupby על tcp_dport/udp_dport | `[{"port_proto": "445/tcp", "count": 900}]` - lateral movement signal |
| `traffic.bytes_in/bytes_out/upload_ratio` | `bytes_src`, `bytes_dst` (‏קיימים) | `upload_ratio: 0.98` = exfiltration shape |

**שינוי בפייפליין**: `attack_tests/run_pipeline.py` מרחיב את שאילתת tshark
עם 2 שדות (http.host, tls.sni) - עלות זניחה על קפצ'ר של 2000 packets.

**PROMPT_VERSION** קפץ מ-v0.3.0 ל-v0.4.0 → כל ה-cache verdicts יתחדשו.

### קטע קוד - איך ה-enrichment של websites נבנה

מ-`llm_judge/judge_core.py`, ‏פונקציה `_websites_for`:

</div>

```python
def _websites_for(S, ip):
    """Build the 'websites' block for one candidate IP from S maps."""
    http_c = (S.get("http_host_per_ip") or {}).get(ip)
    sni_c  = (S.get("tls_sni_per_ip") or {}).get(ip)
    dns_c  = (S.get("dns_per_ip") or {}).get(ip)
    # Drop mDNS/.arpa noise from top DNS queries - the LLM cares about
    # external browsing, not local service discovery.
    if dns_c:
        dns_c = {k: v for k, v in dns_c.items()
                 if k and not k.endswith(".local")
                 and not k.endswith(".arpa")
                 and not k.endswith(".in-addr.arpa")
                 and not k.startswith("_")}
    return {
        "top_http_hosts": _top_n_from_counter(http_c, 5, "host"),
        "top_tls_sni":   _top_n_from_counter(sni_c, 5, "host"),
        "top_dns_queries": _top_n_from_counter(dns_c, 5, "host"),
    }
```

<div dir="rtl">

**עיקרון חשוב**: אם הפייפליין לא ראה HTTP/TLS/DNS על ה-IP הזה בכלל -
השדה חוזר `null` ולא `[]`. הפרומפט מלמד את ה-LLM שnull = ‏unknown, אז
`null` על websites לא מטעה אותו לחשוב שה-IP "שקט" אלא ש"אנחנו לא יודעים".

### מה עדיין חסר (‏פתוח)

- `device_context.category` on worker path - דורש extraction של
  `classify_local_device` מ-`dashboard_module.py` ‏(~380 שורות). הקטגוריה
  ‏(‏Mobile / Desktop / IoT) עדיין `"unknown"` על ה-VM; רק hostname+vendor
  נטענים כרגע.
- TLS versions + weak ciphers - `tls_anomaly` engine כרגע מחזיר רק score.
- Baseline history (‏האם ה-IP הזה חדש?) - יש טבלת baseline אבל לא מזרימים.

</div>

---

<div dir="rtl">

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

</div>

---

<div dir="rtl">

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

</div>

---

<div dir="rtl">

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

</div>

---

<div dir="rtl">

## 14. נתונים טכניים: זיכרון, CPU, אחסון

**מפרט חומרה (‏Oracle Cloud Always Free ARM):**

| רכיב | ערך |
|---|---|
| CPU | 4 OCPU (Ampere Altra, ARM64) |
| RAM | 24 GB |
| דיסק | 96 GB (boot volume) |
| Bandwidth | 10 Gbps (הוא ה-oracle limit) |

**צריכת זיכרון בפועל** (‏מבוססת על מדידה, ‏אוגוסט 2026 עם פאנל 4 שופטים):

| container | RAM | CPU idle | CPU בעומס |
|---|---|---|---|
| `ingest_api` | 32 MB | 0% | ~10% במהלך upload |
| `worker` | 413 MB | 0% | 40-70% במהלך parse+ML |
| `retention` | 15 MB | 0% | ~5% פעם ביום |
| `n8n` | ~200 MB | 0% | - |
| `ollama` (‏‏qwen2.5:3b טעון) | ~2.4 GB | ~50 MB | ~350% (‏3.5 CPU cores) בעת inference |

**סה"כ בזמן idle:** ~1.7 GB. **בזמן ניתוח פעיל:** ~3-4 GB.
עם Ollama בinference: ‏עוד ~2 GB לזמן ריצה של מודל אחד.

**דיסק בפועל** (‏אחרי חודש שימוש):
- `/srv/netsec/data/pcap/`: ~2 GB (‏PCAPs של 7 ימים)
- `/srv/netsec/data/fields/`: ~50 MB (‏gzipped exports)
- `/srv/netsec/reports/`: ~100 MB (‏HTMLs + PDFs)
- `/srv/netsec/db/`: 2-5 MB (‏SQLite) + ~30 MB backups
- Docker images (ollama_models, ‏qwen2.5:3b + לפעמים llama3.2:3b): ~4 GB
- Docker layers (worker, ingest, retention, n8n): ~15 GB
- מערכת Ubuntu + Tailscale + kernel: ~4 GB
- **סה"כ:** ~25 GB מתוך 96 = 26% ‏(‏עם qwen2.5:3b בלבד).

</div>

---

<div dir="rtl">

## 15. גישה ל-VM

### SSH

</div>

```bash
ssh -i C:\path\to\netsec-agent.key\ssh-key-2026-07-12.key ubuntu@100.68.246.54
```

<div dir="rtl">

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

- ה-DB לא עלה לגרסת סכמה 3 או 4. `docker compose exec ingest_api
  python3 -c "from server import db; c=db.connect(); print(c.execute('PRAGMA user_version').fetchone())"` → צריך להיות `(4,)`.
- אם קטן מ-4: הקוד עדכני אבל ה-DB לא מיגר. בדוק `docker compose logs
  worker | grep -i migrate`.

### Ollama לא מגיב

- `docker compose ps ollama` - Up?
- `docker exec deploy-ollama-1 ollama list` - איזה מודלים טעונים?
- `docker exec deploy-worker-1 curl -sS http://ollama:11434/api/tags`
  - האם ה-worker רואה את ה-Ollama container?

### שופט בפאנל מחזיר "The request is suspicious"

- זה סימן ש-Google (‏Gemini) חסם את הבקשה. קורה בעיקר עם AI Studio.
- אם המפתח AQ.-format: וודא שהוא נשלח כ-`Authorization: Bearer` header
  (‏לא כ-`?key=` parameter) - אצלנו זו התנהגות ברירת המחדל של `OpenAICompatClient`.
- אם המפתח בפורמט AIza (‏מ-Google Cloud Console): צריך שהאISo יכלול את
  Generative Language API ברשימת ה-restricted APIs, או שיהיה unrestricted.

### הפאנל תקוע "judging..." זמן ארוך

- זה יכול לקרות אם מודל שבור (‏למשל `allam-2-7b`) מחזיר 400 שוב ושוב.
  התיקון של H3 מ-2026-08-01 סימן 4xx כ-`permanent` ומדלג על retry loop.
- לוודא שהקוד עדכני: `docker exec deploy-worker-1 grep "permanent" /app/llm_judge/llm_clients.py`
- אם 0 → צריך `git pull && docker compose build worker` + ‏restart.

</div>

---

<div dir="rtl">

## 17. הוספת ספק LLM חדש לפאנל

רוצים להוסיף ספק חדש (‏Cerebras, ‏OpenRouter, ‏Anthropic, ‏DeepSeek)?
הפרויקט תוכנן ‏mecanismo של **endpoint profiles** ‏(‏decision IDX-05) שמאפשר
להוסיף ספק ב-3 שורות ב-`.env`, בלי לגעת בקוד.

### 3 השורות שדרוש להוסיף לספק חדש

</div>

```bash
LLM_JUDGE_EP_<NAME>_BASE_URL=<the-openai-compat-endpoint>
LLM_JUDGE_EP_<NAME>_MODEL=<default-model-name>
LLM_JUDGE_EP_<NAME>_KEY_ENV=<NAME_OF_ENV_VAR_HOLDING_KEY>
<THE_ENV_VAR>=<actual-key>
```

<div dir="rtl">

`<NAME>` הופך לאותיות קטנות ולpanel spec: `<name>:model`.

### דוגמה 1 - Cerebras (‏כבר מוגדר ב-`.env.example`)

</div>

```bash
LLM_JUDGE_EP_CEREBRAS_BASE_URL=https://api.cerebras.ai/v1
LLM_JUDGE_EP_CEREBRAS_MODEL=llama-3.3-70b
LLM_JUDGE_EP_CEREBRAS_KEY_ENV=CEREBRAS_API_KEY
CEREBRAS_API_KEY=csk_xxxxxxxxxxxx
```

<div dir="rtl">

ואז ב-`LLM_JUDGE_PANEL`: להוסיף `cerebras:llama-3.3-70b`.

### דוגמה 2 - OpenRouter (‏כבר מוגדר, ‏חינם בחלק מהמודלים)

</div>

```bash
LLM_JUDGE_EP_OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
LLM_JUDGE_EP_OPENROUTER_MODEL=deepseek/deepseek-r1:free
LLM_JUDGE_EP_OPENROUTER_KEY_ENV=OPENROUTER_API_KEY
OPENROUTER_API_KEY=sk-or-v1-xxxxxxxxxxxx
```

<div dir="rtl">

### מה שכן צריך לוודא לפני שמוסיפים

1. **OpenAI-compatible chat endpoint** - הספק חייב לתמוך במסלול
   `POST /chat/completions` עם המבנה הסטנדרטי.
2. **JSON response format** - עדיף שהספק תומך ב-`response_format: json_object`.
   אם רק ב-`json_schema` - עדיין יעבוד אצלנו (‏יש fallback ל-json_object).
3. **מפתח לא בפורמט מוזר** - `Authorization: Bearer <key>` הוא הדפולט.
   אם הספק דורש `X-Api-Key` או משהו אחר - צריך לגעת בקוד.

### הקוד שרץ מאחורי הקלעים

`llm_judge/judge_config.py::endpoint_profiles` סורק את `.env` על כל
`LLM_JUDGE_EP_<NAME>_BASE_URL` ובונה dict של profiles. `judge_cli._build_panel`
קורא את `LLM_JUDGE_PANEL`, ואם רואה prefix מסוג `cerebras:` - מחפש את
ה-profile ומרים `OpenAICompatClient` עם ה-base_url המתאים.

</div>

---

<div dir="rtl">

## 18. מצבי כשל ומה קורה בכל אחד

מטריקס של תקלות אפשריות ואיך המערכת מגיבה:

| מצב כשל | מה קורה |
|---|---|
| **שופט 1 מ-4 נופל** (‏429 permanent, ‏bad key, ‏timeout) | resolver מקבל 3 verdicts, ‏מכריע כרגיל, ‏מסמן `⚖ REVIEW` אם השופט שנפל היה חשוב |
| **2 מ-4 נופלים** | resolver מקבל 2 verdicts, ‏אם מסכימים - ‏consensus; ‏אם חולקים - ‏חמור יותר עם `⚖ REVIEW` |
| **3 מ-4 נופלים** | resolver מקבל 1 verdict, ‏מסמן `needs_review=True` עם note "‏only one panel judge returned a valid verdict" |
| **כל 4 נופלים** | ה-candidate נכנס ל-`dropped` list, ‏לא מופיע בדוח, ‏ה-worker ממשיך לcandidates הבאים |
| **worker נהרג באמצע ניתוח** (‏OOM, ‏docker restart) | ה-session נשאר `status='running'` עד שהstale reclaimer שם `queued` שוב (‏אחרי `NETSEC_STALE_RUNNING_S=3600` שניות) |
| **ingest_api מקבל חתימה לא תקפה** | מחזיר 401 מיד, ‏לא שומר קובץ, ‏לא יוצר session |
| **PCAP corrupt / empty** | worker זורק שגיאה מוקדם (‏`_MIN_PCAP_HEADER_BYTES = 24`), ‏session מסומן `error`, ‏מייל לא נשלח |
| **DB נעול** (‏שני processes מנסים לכתוב) | WAL mode - כותב אחד, קורא רב-מפעילים בו זמנית. ‏SQLite עצמו queues writes |
| **הדיסק מתמלא > 85%** | retention מתחיל מחיקה אגרסיבית של PCAP-ים ישנים |
| **הדיסק מתמלא > 95%** | ingest_api יכול להיכשל בכתיבה - PCAPs חדשים ידחו עם 507 Insufficient Storage |
| **Groq TPD limit** (‏100k tokens ליום) | 429 עם retry logic. אם באמת מיצה - השופט נופל, ‏אחרים ממשיכים |
| **Gemini quota depleted** | 429 "prepayment credits depleted". ‏מטופל אותו דבר כ-permanent 4xx (‏‏‏‏השופט נופל, אחרים ממשיכים) |
| **Ollama container down** | worker רואה connection refused, ‏השופט הזה נופל, ‏אחרים ממשיכים |
| **Tailscale down על ה-VM** | לפטופ לא יכול לשלוח PCAP חדש, ‏אבל ה-worker ממשיך לעבד sessions בתור |
| **SMTP fail** | ‏(‏Google, ‏incorrect app-password, ‏quota) → נופל ל-`n8n` webhook אם מוגדר |
| **כל ההזרימו טוב, אבל LLM מחזיר "benign" על scan** | ‏`RULE_GUARDRAIL=1` מעלה אוטומטית ל-`suspicious` עם ה-category של החוק שירה |

**עיקרון הכללי**: כל שכבה fail-safe. אף כישלון בודד לא מפיל את כל
המערכת. אף לוגיקה לא צריכה שתתערב יד אנושית בזמן ריצה - הכל מטופל.

</div>

---

<div dir="rtl">

## 19. היסטוריית גרסאות ה-prompt

הפרומפט המערכתי (`SYSTEM_PROMPT` ‏ב-`llm_judge/judge_core.py`) עובר גרסאות
מסודרות. גרסת הפרומפט היא חלק מ-cache fingerprint - ‏bump = ‏cache
invalidation אוטומטי.

| גרסה | תאריך | שינוי מרכזי |
|---|---|---|
| **v0.1.0** | 2026-06 | פרומפט בסיסי - ‏verdict/category/confidence/reasoning בלבד |
| **v0.2.0** | 2026-07 | הוספת cheat sheet לקטגוריות + 2 worked examples |
| **v0.2.5** | 2026-07 | הוספת `evidence_features` + `recommended_action` |
| **v0.3.0** | 2026-07 | הוספת כלל HIGH-PRECISION rules + rule guardrail |
| **v0.4.0** | 2026-08-01 | **הנוכחי**. ‏הוספת פסקאות על 5 בלוקים חדשים ב-blob: session_context.time, device_context, websites, traffic |

**כשbump את הגרסה:** ‏(‏מ-`llm_judge/judge_config.py`)

</div>

```python
PROMPT_VERSION = "v0.4.0"  # I2: blob enrichments (time, device, websites, traffic)
```

<div dir="rtl">

**מה קורה אחרי bump:**
- ‏כל cache verdicts הופכים ל-stale (‏fingerprint כולל את PROMPT_VERSION)
- ‏בהעלאה הבאה של PCAP: השופטים נקראים מחדש, אבל עם הבלוב החדש ‏(‏מכיל
  את השדות שהוספנו)
- ‏אם השופטים משנים verdict בעקבות מידע חדש - ‏זה מופיע ב-debate audit

</div>

---

<div dir="rtl">

*המסמך מתעדכן ככל שהמערכת מתפתחת. שינויי סכמה גדולים או שירותים
חדשים - נוספים לסעיפים הרלוונטיים.*

</div>
