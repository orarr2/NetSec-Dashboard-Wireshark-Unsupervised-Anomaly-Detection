<div dir="rtl" align="right">

# תפעול שרת הניתוח

מדריך ההקמה הוא [`VM_DEPLOYMENT.md`](VM_DEPLOYMENT.md); המסמך הזה
הוא דף-ייחוס לפעולות שגרה. כל בלוק למטה מוכן להדבקה - החליפו את
`<vm>` (כתובת ה-Tailscale או ה-hostname של השרת שלכם), את `<key>`
(מפתח ה-SSH הפרטי שרשמתם אצל הספק), ואת `<sensor>` (השם שבחרתם
ב-`create_sensor.py`).

שום דבר על השרת לא מאזין על ה-interface הציבורי מלבד פורט 22 (ראו
[`VM_DEPLOYMENT.md`](VM_DEPLOYMENT.md#2-let-tailscale-traffic-past-the-local-firewall)
לחוקי ה-iptables). כל פקודה למטה מניחה שאתם מתחברים דרך Tailscale
או דרך SSH.

---

## התחברות

```bash
# מכל מכונה בתוך ה-tailnet שלכם:
ssh -i <key> ubuntu@<vm>

# קיצור אופציונלי - להוסיף פעם אחת ל-~/.ssh/config:
#   Host netsec-vm
#     HostName <vm>
#     User     ubuntu
#     IdentityFile <key>
#     ServerAliveInterval 60
# ואז פשוט:  ssh netsec-vm
```

חוסמים נפוצים כש-SSH מסרב:

- **‏Tailscale ב-client לא פועל.** ‏`tailscale status` אמור להציג
  את השרת; אם הוא מראה `NoState`, הפעילו את יישום ה-tray של Tailscale
  או את ה-daemon שלו ב-client ונסו שוב.
- **הרשאות שגויות של המפתח ב-Windows.** ‏OpenSSH דוחה מפתחות
  קריאים לעולם או לקבוצה. תיקון חד-פעמי:
  `icacls <key> /inheritance:r; icacls <key> /grant:r "$env:USERNAME:(R)"`.
- **‏`Permission denied (publickey)`.** קובץ המפתח קיים, אבל זו
  תיקייה; חלק מהספקים מורידים את המפתח בתוך תיקייה שנושאת את שמו.
  הפנו את `-i` לקובץ שבתוך התיקייה, לא לתיקייה.

---

## תמונת מצב של בריאות המערכת

```bash
ssh -i <key> ubuntu@<vm> '
echo "=== containers ==="
cd ~/netsec/deploy && docker compose ps
echo
echo "=== ports (אמורים להיות קשורים ל-Tailscale, לא ל-0.0.0.0) ==="
sudo ss -tlnp | grep -E ":(5678|8765|8766)\b" | awk "{print \$4, \$7}"
echo
echo "=== ingest healthz ==="
curl -sS http://<vm>:8766/healthz
echo
echo "=== disk ==="
df -h / | tail -1
echo
echo "=== timestamp של הניתוח האחרון ==="
docker compose exec -T worker sh -c "python3 -c \"
from server import db
c = db.connect()
r = c.execute(\\\"SELECT MAX(finished_at) FROM sessions WHERE status=\\\\\\\"done\\\\\\\"\\\").fetchone()
print(r[0] or \\\"(no completed sessions yet)\\\")
\"" 2>/dev/null
'
```

---

## צפייה בניתוח חי

```bash
# זורם את ה-log של ה-worker עד שהסבב הנוכחי נגמר; עצירה עם Ctrl+C.
ssh -i <key> ubuntu@<vm> 'cd ~/netsec/deploy && docker compose logs -f worker'
```

סימנים מרכזיים שכדאי לחפש:

- `[cli] analyzing /srv/netsec/data/pcap/...` - ה-worker תפס עבודה
  מהתור.
- `[<label>] advanced engines: N signal(s) across M device(s)` -
  ששת המגלים הממופים ל-MITRE רצו.
- `[cli] provider=... guardrail=on prompt=v0.5.0` - שופט ה-LLM
  מתחיל לפעול.
- `[worker] session <id> done (<K> verdicts)` - הצלחה.
- `[worker] session <id> FAILED: <reason>` - שגיאה נרשמה לשורת
  הסבב; הצינור ממשיך הלאה והתור ממשיך לזרום.

---

## פריסה מחדש אחרי `git pull`

ה-Dockerfiles של `ingest_api` ו-`worker` עושים `COPY` של הריפו אל
תוך ה-image בזמן ה-BUILD - **לא** בזמן ריצה - ולכן `git pull` על
המארח בלתי נראה ל-containers הרצים עד שה-image נבנה מחדש. יש לבנות
תמיד מחדש, ואז לאלץ recreate. ‏`force-recreate` לבד מריץ את אותו
image, אז קוד ה-Python החדש שלכם נשאר מחוץ ל-container.

```bash
ssh -i <key> ubuntu@<vm> '
cd ~/netsec
git pull --ff-only origin main
cd deploy
docker compose build ingest_api worker retention
docker compose up -d --force-recreate ingest_api worker retention
docker compose ps
'
```

ה-build מהיר בשינוי של קוד בלבד: ‏torch, ‏tshark וכל שכבת apt נמצאים
במטמון; רק שכבת ה-`COPY . .` האחרונה רצה שוב.

---

## התבוננות בסבב מסוים

```bash
ssh -i <key> ubuntu@<vm> '
SID=${SID:-1}
echo "=== דוחות על הדיסק ==="
sudo ls /srv/netsec/reports/$SID/
echo
echo "=== סיכום הפסיקות ==="
sudo cat /srv/netsec/reports/$SID/verdicts.json | python3 -c "
import sys, json
v = json.load(sys.stdin)
s = v.get(\"stats\") or {}
print(f\"model={v.get(\\\"model\\\") or s.get(\\\"model\\\")}  cache_hits={s.get(\\\"cache_hits\\\")}  judged={s.get(\\\"judged\\\")}\")
for r in (v.get(\"results\") or [])[:8]:
    vd = r.get(\"verdict\") or {}
    print(f\"  {r.get(\\\"candidate_id\\\"):22s} -> {vd.get(\\\"verdict\\\"):11s} / {vd.get(\\\"category\\\")}\")
"
' SID=42   # <-- להחליף למספר הסבב שרוצים לבדוק
```

להורדת דוח מהמחשב הנייד במקום לקרוא אותו על השרת:

```bash
scp -i <key> ubuntu@<vm>:/srv/netsec/reports/42/report.html ./
```

---

## הפעלה מחדש, עצירה או התחלה של שירות

```bash
ssh -i <key> ubuntu@<vm> '
cd ~/netsec/deploy
docker compose restart worker         # איתחול ה-worker בלבד
docker compose stop worker            # עצירה שלו
docker compose start worker           # הפעלה שלו
docker compose down                   # עצירת כל המערך (n8n נשאר)
docker compose up -d ingest_api worker retention
'
```

הפקודה `docker compose restart` משתמשת בסביבה האפויה בתוך ה-container;
אם ערכתם את `.env`, השתמשו ב-`up -d --force-recreate` במקום, כדי
שהערכים החדשים ייכנסו לתוקף.

---

## גיבוי מסד הנתונים של ההיסטוריה

שירות ה-`retention` כבר מצלם את ה-DB כל לילה אל
`/srv/netsec/db/backups/` ומגזום לפי `RETENTION_BACKUP_KEEP` עותקים
(ברירת מחדל 14). לדאמפ ידני מחוץ ללוח הזמנים:

```bash
ssh -i <key> ubuntu@<vm> '
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT=/srv/netsec/db/backups/manual_$STAMP.db
sudo mkdir -p /srv/netsec/db/backups
sudo sqlite3 /srv/netsec/db/netsec.db ".backup $OUT"
sudo ls -lh /srv/netsec/db/backups/ | tail -5
'
# להורדה למחשב מקומי, אם רוצים עותק מחוץ לשרת:
scp -i <key> ubuntu@<vm>:/srv/netsec/db/backups/manual_*.db ./
```

---

## החלפת חיישן שנפרץ

אם סוד של חיישן הודבק במקום שלא היה צריך:

```bash
ssh -i <key> ubuntu@<vm> '
cd ~/netsec/deploy
# 1. ביטול החיישן הישן
sudo NETSEC_DATA_ROOT=/srv/netsec python3 -c "
from server import db
c = db.connect()
c.execute(\"UPDATE sensors SET revoked_at=DATETIME(\\\"now\\\") WHERE name=?\", (\"<sensor>\",))
c.commit()
print(\"revoked:\", c.execute(\"SELECT name, revoked_at FROM sensors WHERE name=?\", (\"<sensor>\",)).fetchone())
"
# 2. יצירת חיישן חדש (כל שם; למשל laptop2) - האישורים החדשים מודפסים פעם אחת
sudo NETSEC_DATA_ROOT=/srv/netsec python3 create_sensor.py <sensor>2
'
```

לאחר מכן, יש לעדכן את ה-client (הדשבורד, ‏`tools/upload_pcap.py`,
סוכן ה-capture) ב-`NETSEC_SENSOR_ID` וב-`NETSEC_SENSOR_SECRET`
החדשים.

---

## שליחת אימייל בסיום ניתוח

ה-worker עובד בשרשרת גיבוי: **קודם SMTP, אחר כך webhook של n8n**
כש-SMTP נכשל. סדר הקדימות של הנמען: הכותרת `X-Notify-Email`
שבהעלאה מנצחת את `NETSEC_NOTIFY_EMAIL` ב-`.env` (ברירת המחדל
של מפעיל יחיד).

מלאו את השורות האלה ב-`~/netsec/deploy/.env` על השרת:

```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=<כתובת ה-gmail שלכם>
SMTP_PASS=<Gmail app-password, 16 תווים, לא סיסמת החשבון>
SMTP_FROM=NetSec Analyzer <כתובת ה-gmail שלכם>
NETSEC_NOTIFY_EMAIL=<נמען גיבוי אופציונלי>
N8N_WEBHOOK_URL=<אופציונלי; בשימוש רק כש-SMTP עצמו נכשל>
```

הפיקו Gmail app-password חד-פעמי בכתובת
`https://myaccount.google.com/apppasswords` (צריך אימות דו-שלבי
פעיל). ואז בנו מחדש ואלצו recreate של ה-worker כדי שהסביבה החדשה
תיקלט - `docker compose restart` משתמש בערכים הישנים האפויים:

```bash
ssh -i <key> ubuntu@<vm> '
cd ~/netsec/deploy
docker compose up -d --force-recreate worker
'
```

הפעילו העלאה טרייה עם הכתובת כפרמטר:

```bash
python3 tools/upload_pcap.py <capture.pcap> --email you@example.com
```

אשרו משלוח מתוך ה-log של ה-worker - שורה אחת לכל מנגנון שנוסה:

```
[worker] notify [smtp]: report sent to you@example.com
```

או במקרה כשל עם נפילה חזרה:

```
[worker] notify FAILED [smtp]: SMTP authentication failed (535)...
[worker] notify [n8n_fallback]: n8n accepted (200)
```

## הפעלת פאנל השופטים (דיון רב-מודלי)

הערך של `LLM_JUDGE_PANEL` ב-`.env` קובע אילו מודלים שופטים כל
הקלטה. ריק = מצב שופט יחיד (רק `OPENAI_COMPAT_MODEL` רץ). שני
שופטים ומעלה מפעילים "ועדת דיון" אמיתית - כל מודל מצביע באופן
עצמאי, מחלוקות מפעילות סיבוב של debate, והתמלול של הפאנל נוחת
בדוח ה-markdown שהאימייל שולח.

פאנל Groq-בלבד של שני שופטים ששורד הגעה למכסה היומית של 429 במודל
אחד:

```
LLM_JUDGE_PANEL=openai_compat:llama-3.3-70b-versatile,openai_compat:openai/gpt-oss-20b
```

לכל מודל יש מכסה חינמית נפרדת של 100k טוקנים ליום, אז מודל אחד
שנגמר לא חוסם את השני. אלצו recreate של ה-worker אחרי העריכה:

```bash
ssh -i <key> ubuntu@<vm> 'cd ~/netsec/deploy && docker compose up -d --force-recreate worker'
```

## מעקב אחר מכסת ה-LLM של ה-free tier

אם תגדירו `LLM_JUDGE_QUOTA_DB=/srv/netsec/db/quota.db` ב-`.env`, כל
קריאה לשופט מקדמת מונה. קריאת ההוצאה הנוכחית:

```bash
ssh -i <key> ubuntu@<vm> '
sudo sqlite3 /srv/netsec/db/quota.db "
SELECT provider, model, DATE(ts) day,
       SUM(tokens_in) tokens_in, SUM(tokens_out) tokens_out,
       COUNT(*) n
FROM llm_calls
WHERE ts >= DATETIME(\"now\", \"-24 hours\")
GROUP BY provider, model, DATE(ts)
ORDER BY day DESC, tokens_in DESC;
"
'
```

ה-free tier של Groq הוא 100k טוקנים ליום למשפחת 70B; חציית הגבול
מחזירה 429 מהשופט שנרשם כשורת `judge failed` - עדכנו את
`LLM_JUDGE_PANEL` או עברו ל-Ollama מקומי במקום להעמיד פנים שהפאנל
הצביע.

---

## הסרה או התחלה מחדש

```bash
ssh -i <key> ubuntu@<vm> '
cd ~/netsec/deploy
docker compose down -v            # הורג containers + volumes בשם
sudo rm -rf /srv/netsec/data /srv/netsec/reports /srv/netsec/db
# לשמור או לזרוק את הקוד:
# rm -rf ~/netsec
'
```

ה-`-v` ב-`down` מסיר גם את ה-volume של n8n - גבו אותו קודם אם
אתם רוצים לשמור את תהליכי העבודה והאישורים.

</div>
