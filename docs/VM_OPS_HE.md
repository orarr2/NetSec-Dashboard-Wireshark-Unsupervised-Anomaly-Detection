<div dir="rtl" align="right">

# תפעול VM הניתוח שלכם

מדריך ההקמה הוא [`docs/VM_DEPLOYMENT.md`](VM_DEPLOYMENT.md); המסמך
הזה הוא cheat-sheet לפעולות שוטפות. כל בלוק למטה מוכן להדבקה -
החליפו את `<vm>` (ה-IP או ה-hostname של Tailscale של ה-VM שלכם),
את `<key>` (מפתח ה-SSH הפרטי שרשמתם אצל הספק), ואת
`<sensor>` (השם שבו השתמשתם ב-`create_sensor.py`).

שום דבר על ה-VM לא מאזין על ה-interface הציבורי מלבד פורט 22 (ראו
[`docs/VM_DEPLOYMENT.md`](VM_DEPLOYMENT.md#2-let-tailscale-traffic-past-the-local-firewall) לחוקי ה-iptables).
כל פקודה למטה מניחה שאתם מתחברים מעל Tailscale או SSH.

---

## התחברות

```bash
# מכל מכונה ב-tailnet שלכם:
ssh -i <key> ubuntu@<vm>

# קיצור אופציונלי - הוסיפו פעם אחת ל-~/.ssh/config:
#   Host netsec-vm
#     HostName <vm>
#     User     ubuntu
#     IdentityFile <key>
#     ServerAliveInterval 60
# ואז פשוט:  ssh netsec-vm
```

חוסמים נפוצים כש-SSH מסרב:

- **‏Tailscale ב-client לא פעיל.** `tailscale status` אמור להציג
  את ה-VM; אם זה אומר `NoState`, הפעילו את אפליקציית/daemon ה-tray
  של Tailscale ב-client ונסו שוב.
- **הרשאות שגויות של מפתח ב-Windows.** ‏OpenSSH מסרב מפתחות
  קריאים לעולם או לקבוצה. תקנו פעם אחת עם:
  `icacls <key> /inheritance:r; icacls <key> /grant:r "$env:USERNAME:(R)"`
- **‏`Permission denied (publickey)`.** קובץ המפתח קיים אבל הוא
  תיקייה; חלק מהספקים מורידים את המפתח כתיקייה בשם המפתח.
  הפנו את `-i` לקובץ בתוך התיקייה, לא לתיקייה.

---

## תמונת מצב בריאות

```bash
ssh -i <key> ubuntu@<vm> '
echo "=== containers ==="
cd ~/netsec/deploy && docker compose ps
echo
echo "=== ports (should all be bound to the Tailscale IP, not 0.0.0.0) ==="
sudo ss -tlnp | grep -E ":(5678|8765|8766)\b" | awk "{print \$4, \$7}"
echo
echo "=== ingest healthz ==="
curl -sS http://<vm>:8766/healthz
echo
echo "=== disk ==="
df -h / | tail -1
echo
echo "=== last analysis timestamp ==="
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
# ‏Stream של ה-worker log עד שה-session הנוכחי נגמר; ‏Ctrl+C לעצירה.
ssh -i <key> ubuntu@<vm> 'cd ~/netsec/deploy && docker compose logs -f worker'
```

סימנים מרכזיים לחיפוש:

- `[cli] analyzing /srv/netsec/data/pcap/...` - ה-worker תפס עבודה בתור.
- `[<label>] advanced engines: N signal(s) across M device(s)` - ששת ה-detectors הממופים ל-MITRE רצו.
- `[cli] provider=... guardrail=on prompt=v0.5.0` - שופט LLM מתחיל.
- `[worker] session <id> done (<K> verdicts)` - הצלחה.
- `[worker] session <id> FAILED: <reason>` - שגיאה נרשמה לשורת ה-session; הצינור ממשיך הלאה והתור ממשיך לזרום.

---

## Redeploy אחרי `git pull`

ה-Dockerfiles של ingest_api ו-worker עושים `COPY` של הריפו אל ה-image
בזמן ה-BUILD - **לא** בזמן ריצה - אז `git pull` על ה-host בלתי נראה
ל-containers שרצים עד שה-image נבנה מחדש. תמיד בנו מחדש, ואז
אלצו recreate. ‏`force-recreate` לבד מעתיק את אותו image, אז קוד
ה-Python החדש שלכם נשאר מחוץ ל-container.

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

ה-build מהיר בשינוי קוד-בלבד: ‏torch, ‏tshark, וכל שכבת apt
ב-cache; רק שכבת ‏`COPY . .` הסופית רצה מחדש.

---

## התבוננות ב-session ספציפי

```bash
ssh -i <key> ubuntu@<vm> '
SID=${SID:-1}
echo "=== reports on disk ==="
sudo ls /srv/netsec/reports/$SID/
echo
echo "=== verdict summary ==="
sudo cat /srv/netsec/reports/$SID/verdicts.json | python3 -c "
import sys, json
v = json.load(sys.stdin)
s = v.get(\"stats\") or {}
print(f\"model={v.get(\\\"model\\\") or s.get(\\\"model\\\")}  cache_hits={s.get(\\\"cache_hits\\\")}  judged={s.get(\\\"judged\\\")}\")
for r in (v.get(\"results\") or [])[:8]:
    vd = r.get(\"verdict\") or {}
    print(f\"  {r.get(\\\"candidate_id\\\"):22s} -> {vd.get(\\\"verdict\\\"):11s} / {vd.get(\\\"category\\\")}\")
"
' SID=42   # <-- החליפו ל-session id שאתם רוצים לבדוק
```

משיכת דוח מהמחשב הנייד במקום לקרוא אותו ב-VM:

```bash
scp -i <key> ubuntu@<vm>:/srv/netsec/reports/42/report.html ./
```

---

## הפעלה מחדש / עצירה / התחלה של שירות

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

`docker compose restart` משתמש בסביבה האפויה בתוך ה-container; אם
ערכתם את `.env`, השתמשו ב-`up -d --force-recreate` במקום כדי שהערכים
החדשים יכנסו לתוקף.

---

## גיבוי DB ההיסטוריה

שירות ה-`retention` כבר מצלם את ה-DB כל לילה אל
`/srv/netsec/db/backups/` ומגזום ל-`RETENTION_BACKUP_KEEP` עותקים
(ברירת מחדל 14). ‏Dump ידני כשאתם רוצים אחד מחוץ ללוח:

```bash
ssh -i <key> ubuntu@<vm> '
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT=/srv/netsec/db/backups/manual_$STAMP.db
sudo mkdir -p /srv/netsec/db/backups
sudo sqlite3 /srv/netsec/db/netsec.db ".backup $OUT"
sudo ls -lh /srv/netsec/db/backups/ | tail -5
'
# משכו אותו החוצה מה-VM אם אתם רוצים עותק off-box:
scp -i <key> ubuntu@<vm>:/srv/netsec/db/backups/manual_*.db ./
```

---

## סבב של sensor שנפרץ

אם SECRET של sensor הודבק איפשהו שלא היה אמור:

```bash
ssh -i <key> ubuntu@<vm> '
cd ~/netsec/deploy
# 1. ‏Revoke של ה-sensor הישן
sudo NETSEC_DATA_ROOT=/srv/netsec python3 -c "
from server import db
c = db.connect()
c.execute(\"UPDATE sensors SET revoked_at=DATETIME(\\\"now\\\") WHERE name=?\", (\"<sensor>\",))
c.commit()
print(\"revoked:\", c.execute(\"SELECT name, revoked_at FROM sensors WHERE name=?\", (\"<sensor>\",)).fetchone())
"
# 2. יצירת sensor טרי (כל שם; למשל laptop2) - מדפיס אישורים חדשים פעם אחת
sudo NETSEC_DATA_ROOT=/srv/netsec python3 create_sensor.py <sensor>2
'
```

ואז עדכנו את ה-client (דשבורד, ‏`tools/upload_pcap.py`, סוכן capture)
עם `NETSEC_SENSOR_ID` ו-`NETSEC_SENSOR_SECRET` החדשים.

---

## משלוח אימייל בסיום

ה-worker הולך בשרשרת fallback: **‏SMTP קודם, ‏n8n webhook כגיבוי**
כש-SMTP נכשל. סדר העדיפויות של הנמען: ‏`X-Notify-Email` של ההעלאה
מנצח את `NETSEC_NOTIFY_EMAIL` ב-`.env` (ברירת המחדל של מפעיל-יחיד).

מלאו את השורות האלה ב-`~/netsec/deploy/.env` ב-VM:

```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=<כתובת ה-gmail שלכם>
SMTP_PASS=<Gmail app-password, 16 תווים, לא סיסמת החשבון>
SMTP_FROM=NetSec Analyzer <כתובת ה-gmail שלכם>
NETSEC_NOTIFY_EMAIL=<נמען fallback אופציונלי>
N8N_WEBHOOK_URL=<אופציונלי; בשימוש רק כש-SMTP עצמו נכשל>
```

הפיקו Gmail app-password פעם אחת ב-
`https://myaccount.google.com/apppasswords` (דורש 2-Step Verification
מופעל). ואז בנו מחדש + אלצו recreate של ה-worker כדי שהסביבה החדשה
תיקלט - ‏`docker compose restart` משתמש בערכים האפויים הישנים:

```bash
ssh -i <key> ubuntu@<vm> '
cd ~/netsec/deploy
docker compose up -d --force-recreate worker
'
```

הפעילו העלאה טרייה עם הכתובת על הקו:

```bash
python3 tools/upload_pcap.py <capture.pcap> --email you@example.com
```

אשרו משלוח מ-worker log - שורה אחת לכל מנגנון שנוסה:

```
[worker] notify [smtp]: report sent to you@example.com
```

או בכישלון עם fallback:

```
[worker] notify FAILED [smtp]: SMTP authentication failed (535)...
[worker] notify [n8n_fallback]: n8n accepted (200)
```

## הפעלת פאנל השופט (דיון רב-מודלי)

`LLM_JUDGE_PANEL` ב-`.env` שולט אילו מודלים שופטים כל capture.
ריק = מצב שופט-יחיד (רק `OPENAI_COMPAT_MODEL` רץ). שניים או יותר
שופטים נותנים לכם "דיון ועדה" אמיתי - כל מודל מצביע באופן עצמאי,
חילוקי דעות מפעילים סבב debate, ו-transcript הפאנל נוחת בדוח
ה-markdown שהאימייל שולח.

פאנל בטוח של שני שופטי Groq שעובד גם כשמודל אחד נגמר ב-429 יומי:

```
LLM_JUDGE_PANEL=openai_compat:llama-3.3-70b-versatile,openai_compat:openai/gpt-oss-20b
```

לכל מודל יש מכסה חינמית משלו של 100k-token/יום, אז מודל אחד שנגמר
לא חוסם את השני. אלצו recreate של ה-worker אחרי העריכה:

```bash
ssh -i <key> ubuntu@<vm> 'cd ~/netsec/deploy && docker compose up -d --force-recreate worker'
```

## מעקב מכסת LLM של free-tier

אם תגדירו `LLM_JUDGE_QUOTA_DB=/srv/netsec/db/quota.db` ב-`.env`, כל
קריאת שופט מגדילה מונה. קראו את ההוצאה הנוכחית:

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

ה-free tier של Groq הוא 100k טוקנים/יום למשפחת 70B; אם תחצו אותו,
השופט מחזיר 429 שנרשם כשורת `judge failed` - התאימו את
`LLM_JUDGE_PANEL` או עברו ל-fallback של Ollama מקומי במקום
להעמיד פנים שהפאנל הצביע.

---

## הסרה / התחלה מחדש

```bash
ssh -i <key> ubuntu@<vm> '
cd ~/netsec/deploy
docker compose down -v            # הורגים containers + volumes בשם
sudo rm -rf /srv/netsec/data /srv/netsec/reports /srv/netsec/db
# שמרו או זרקו את הקוד:
# rm -rf ~/netsec
'
```

ה-`-v` ב-`down` מסיר גם את ה-volume של n8n - גבו אותו קודם אם אתם
רוצים לשמור את ה-workflows והאישורים שלכם.

</div>
