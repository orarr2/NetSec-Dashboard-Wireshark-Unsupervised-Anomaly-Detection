<div dir="rtl" align="right">

# הפעלת VM ניתוח משלכם - scaffolding של deployment

התיקייה הזאת מכילה את תבניות ה-deployment הגנריות וחסרות הסודות
כך שכל fork יוכל להעמיד את מערך הניתוח 24/7 על ה-VM שלו.
כל מה ש-fork צריך כדי להריץ את הצינור + שירותי המשתמש הפעילים-תמיד
(RAG, ‏Companion, ‏Portal, ‏Caddy) נמצא כאן או תחת
`../server/`, `../sensor/`, `../tools/`, `../companion/`.

## מה נשלח

| קובץ | מטרה |
|---|---|
| `.env.example` | כל משתנה סביבה שהמערך קורא, עם ברירת המחדל שלו מהקוד. |
| `docker-compose.yml` | שירותי docker: ‏n8n + ingest_api + worker + retention + ollama + caddy. כל אחד קשור ל-IP של Tailscale; ‏ollama על loopback. |
| `Dockerfile.ingest` | image של ingest API - `server/` + FastAPI, פורט 8766. |
| `Dockerfile.worker` | image של worker הניתוח - מריץ את צינור הזיהוי, כותב verdicts + דוחות HTML/PDF. |
| `Caddyfile` | קונפיגורציית reverse proxy: ‏TLS + basicauth + ניתוב path ל-Portal / RAG / Companion. |
| `install-caddy.sh` | מתקין חד-פעמי: כותב את אישורי ה-basicauth, מפעיל את Caddy, מתקין fail2ban עם jail של Caddy. דורש משתני סביבה BASIC_AUTH_USER + BASIC_AUTH_HASH. |
| `install-rag.sh` | מתקין את שירות ה-RAG (מודל Ollama embed + יחידת systemd + timer לקליטה). |
| `install-companion.sh` | מתקין את שירות Companion (venv ייעודי של Python עם dash + pypdf + python-docx, ‏tshark לקליטת PCAP, יחידת systemd). |
| `netsec-rag.service` + `-ingest.service` + `.timer` | יחידות systemd ל-RAG. |
| `netsec-companion.service` | יחידת systemd ל-Companion. |
| `netsec-tls-renew.service` + `.timer` | חידוש שבועי של תעודת Let's Encrypt שהונפקה דרך Tailscale. |
| `n8n_workflows/mvp_triage_email.json` | תהליך עבודה של n8n לייבוא: מקבל את ה-alert webhook של ה-worker ושולח אימייל כש-verdict הוא malicious/suspicious. |
| `create_sensor.py` | רושם sensor ב-DB ההיסטוריה ומדפיס את האישורים שלו פעם אחת. |
| `../server/` | סכמת DB היסטוריה, auth של העלאת HMAC, אחסון streaming, ושכבת ingest של FastAPI. |
| `../tools/netsec_rag.py` | מנוע RAG (retrieval + generation). ‏CLI + Python API. |
| `../tools/netsec_rag_web.py` | frontend של RAG Dash web, בנוי כמו Companion. |
| `../companion/companion.py` | AI Companion (‏Dash chat מעל Ollama מקומי, עם drag-and-drop של קבצים). |
| `../tools/upload_pcap.py` | העלאת streaming חתומה מכל מכונה - המחליף ללא תקרת-גודל לנתיב 25MB של GitHub. |
| `../tools/measure_pipeline_ratios.py` | מודד מחדש את יחסי הגדלים PCAP-מול-fields שעליהם בנויה התכנית, מול הקלטה ארוכה משלכם (המספרים של התכנית הגיעו מדוגמה אחת של 135 שניות). |
| `../server/retention.py` | אחזקה יומית (רץ כשירות compose של `retention`): גיבוי + גיזום של DB, מחיקת הגולמי אחרי 7 ימים עם backfill של אינדקס השדות הקבוע קודם, סימן מים של 85% דיסק, VACUUM חודשי. ‏`--once --dry-run` מראה מה הוא היה עושה. |
| `../tools/watchdog.py` | checker חיצוני עצמאי - העתיקו לכל מכונה פעילה תמיד **מחוץ** ל-VM, הפנו אותו ל-`http://<vm>:8766/healthz`, קבלו אימייל אחד לכל תקלה ואחד לכל התאוששות. אין מכונה שמנטרת את עצמה. |

## התחלה מהירה על VM טרי

```bash
# 1. ‏Clone של הריפו על ה-VM
git clone <repo> /home/ubuntu/netsec
cd /home/ubuntu/netsec/deploy

# 2. כתיבת .env עם הסודות שלכם (SMTP + מפתח הצפנת N8N + מפתחות LLM)
cp .env.example .env
$EDITOR .env

# 3. הפעלת שירותי docker (עדיין לא כולל caddy)
sudo docker compose up -d ingest_api worker retention ollama n8n

# 4. רישום sensor (מדפיס את סוד ה-HMAC פעם אחת - שמרו אותו)
python3 create_sensor.py my-laptop

# 5. התקנת שירותים הפונים למשתמש (systemd)
sudo cp ../deploy/netsec-portal.service /etc/systemd/system/    # (צרו את זה מתבנית אם לא קיים)
sudo systemctl enable --now netsec-portal
bash install-rag.sh
bash install-companion.sh

# 6. השגת תעודת HTTPS של Tailscale (דורש הפעלת HTTPS בקונסולת admin של tailscale פעם אחת)
sudo mkdir -p /etc/netsec-tls
sudo tailscale cert netsec-agent.<your-tailnet>.ts.net
sudo mv netsec-agent.*.crt netsec-agent.*.key /etc/netsec-tls/

# 7. הפעלת Caddy עם basicauth
BASIC_AUTH_USER=you \
BASIC_AUTH_HASH="$(sudo docker run --rm caddy:2 caddy hash-password --plaintext 'YOUR-PW')" \
    bash install-caddy.sh

# 8. מכל התקן Tailscale פתחו https://netsec-agent.<your-tailnet>.ts.net/
```

ברגע שהצעד האחרון מחזיר 200 יש לכם Portal + RAG + Companion + n8n +
הצינור כולם נגישים מכל התקן שמחובר לחשבון ה-Tailscale שלכם. ראו
`../docs/ARCHITECTURE.md` למפת הניתוב ו-`../docs/SECURITY_MODEL.md`
לשכבות ה-auth.

## דרישות

- כל VM של Ubuntu 22.04+, ‏x86-64 או ARM (‏aarch64 אומת - כל תלות
  pinned מפרסמת wheel של aarch64, ראו `docs/VM_DEPLOYMENT.md`).
  4GB RAM מינימום לצינור לבד; ‏16-24GB מומלץ אם אתם רוצים גם את
  שופט ה-Ollama המקומי החינמי.
- Oracle Always Free (4 OCPU / 24GB RAM / 100GB נפח boot) הוא
  נתיב ה-$0 המומלץ; ‏AWS / Azure / Hetzner או כל ספק עובד זהה.
  **להישאר חינם:** ה-tier החינמי מאפשר עד 200GB סה"כ אחסון בלוקים
  - שמרו על 100GB boot ו-**אל** תוסיפו volume שיחצה 200GB, אחרת
  תתחילו לשלם. ‏Retention (למטה) שומר על הדיסק חסום אז הוא לא יזלוג
  לנכס בתשלום.
- Docker + plugin של compose, ‏Tailscale, ו-chrony (‏NTP - נדרש על ידי
  פרוטוקול telemetry-reconciliation, ‏spec סעיף 12).
- שום דבר לא נחשף פומבית מלבד SSH: כל שירות נקשר ל-IP של Tailscale
  (החלטה IDX-08).

## Quickstart

1. התקנת Docker, ‏Tailscale ו-chrony על ה-VM; הצטרפו ל-tailnet שלכם:
   `sudo tailscale up --hostname=netsec-agent`.
2. יישום הערות ה-firewall מ-`docs/VM_DEPLOYMENT.md` (חוק
   ה-ACCEPT של `tailscale0` חייב לקדום ל-REJECT ה-catch-all של ה-image
   של הענן, וחייב להשתמר).
3. יצירת ה-data root על דיסק ה-boot - בלי volume נוסף, נשאר $0:
   `sudo mkdir -p /srv/netsec && sudo chown $USER /srv/netsec`
   (החלטות IDX-02+03; retention שומר אותו חסום). רק אם מאוחר יותר
   תצטרכו הקלטה רציפה 24/7, הוסיפו volume block של **לכל היותר 100GB**
   כך ש-boot + volume נשארים בתוך 200GB החינמיים.
4. ‏`git clone` של הריפו אל ה-VM ו-`cd deploy/`.
5. `cp .env.example .env` ומלאו ערכים - לפחות `TS_BIND`
   (ה-IP של Tailscale של ה-VM) ו-`N8N_ENCRYPTION_KEY`.
6. `docker compose up -d` - מפעיל את n8n ואת ingest API. אמתו ממכונה
   ב-tailnet שלכם (ואשרו שה-IP הציבורי לא עונה לכלום על אף פורט):
   `curl -s -o /dev/null -w "%{http_code}\n" http://$TS_BIND:5678/`
   `curl -s http://$TS_BIND:8766/healthz`
7. רשמו sensor והעתיקו את האישורים שהודפסו לסביבה של ה-sensor
   (מוצגים פעם אחת, לא ניתן לשחזר). הריצו את זה מתוך תיקיית
   `deploy/`; ה-containers יצרו את `db/netsec.db` כ-root, אז השתמשו
   ב-`sudo` וכוונו אותו ל-אותו data root:
   `sudo NETSEC_DATA_ROOT=/srv/netsec python3 create_sensor.py laptop`
8. העלאת capture מכל מכונה ב-tailnet - בלי תקרת גודל
   (הריצו מהשורש של הריפו, או התאימו את ה-path):
   `python3 tools/upload_pcap.py capture.pcapng`
   (דורש `NETSEC_INGEST_URL=http://<vm-tailscale-ip>:8766` בתוספת
   אישורי ה-sensor בסביבה). ה-session נכנס לתור, ה-worker מנתח אותו,
   ו-`verdicts.json` / `.md` / `report.html` / `report.pdf` נכתבים
   תחת `reports/<session_id>/`.
9. (אופציונלי) חיווט התראות n8n: פתחו את n8n ב-`http://<vm>:5678`,
   **‏Import from File** ← `deploy/n8n_workflows/mvp_triage_email.json`,
   צרפו אישור SMTP ל-node ‏*Send Email Alert*, ‏**הפעילו** אותו,
   והגדירו `N8N_WEBHOOK_URL` ב-`.env` ל-URL של אותו webhook כך
   שה-worker יפרסם לו כל verdict.

## פריסת האחסון (לפי התכנית המאושרת, ‏spec סעיף 8)

```
/srv/netsec/
├── data/pcap/      הקלטות גולמיות - נשמרות 7 ימים, אז מוסרות אוטומטית
├── data/fields/    ייצואי שדות gzipped - נשמרים לנצח (IDX-04)
├── reports/        verdicts.json / .md / .html / .pdf - נשמרים לנצח
└── db/             netsec.db (היסטוריית SQLite) + גיבויים ליליים
```

## הרצת sensor (מחשב נייד היום, ‏Raspberry Pi 5 מחר)

סוכן ה-capture (`sensor/capture_agent.py`) הוא Tier 0 - הוא מקליט PCAP
גולמי ב-מאגר טבעתי של tshark ומעלה כל חתיכה סגור ל-VM. זה אותו קוד
על מחשב נייד ועל Pi 5 (החלטה IDX-01, שלב J):
רק הסביבה שונה.

```bash
export NETSEC_INGEST_URL=http://<vm-tailscale-ip>:8766
export NETSEC_SENSOR_ID=laptop           # מ-deploy/create_sensor.py
export NETSEC_SENSOR_SECRET=...           # מ-deploy/create_sensor.py
export NETSEC_INFRA_DSTS=<vm-tailscale-ip>   # לא נכלל ב-capture
python3 sensor/capture_agent.py --interface wlan0
```

הערך `NETSEC_INFRA_DSTS` הוא מה ששומר על ההעלאות של הסוכן עצמו
מלהיתפס ולהסתמן מאוחר יותר כאנומליה או כ-beaconing (‏spec סעיף
12.2 שכבה 0): הסוכן בונה מסנן capture שמחריג בדיוק את היעד הזה
על פורט ההעלאה, ושום דבר אחר.

**‏Pi 5 כ-Tier 0 חלופי (שלב J).** ה-Pi מריץ את הסוכן הזהה;
הארכיטקטורה לא משתנה. שתי הערות ספציפיות ל-Pi:

- תנו ל-Pi שני נתיבים כדי שההעלאה לעולם לא תרוץ ברשת המנוטרת:
  capture ב-interface של Wi-Fi, העלאה דרך Ethernet. עם הפיצול הזה
  הטלמטריה יוצאת out-of-band ומסנן ה-capture הוא חגורה-ושלייקס
  במקום בעל-תפקיד.
- כרטיס 128GB מחזיק בערך תשעה ימים של גולמי בקצב הנמדד, אז הגדירו
  `NETSEC_RING_FILES` כדי לחסום את ה-ring המקומי למה שהכרטיס יכול
  לשאת (`files:N x duration:S` שניות של היסטוריה).

כל מה שבהמשך הצינור - קליטה, worker, היסטוריה, בייסליין, דוחות -
אינו משתנה: עבור ה-VM חתיכה של Pi ו-חתיכה של מחשב נייד הם אותה
העלאה חתומה.

## סודות

`deploy/.env` נמצא ב-gitignore - זה המקום היחיד שבו מפתחות API,
מפתח ההצפנה של n8n וסודות של sensors חיים על ה-VM. לעולם אל תעשו
לו commit, ולעולם אל תשימו סוד בשום קובץ בתוך התיקייה הזאת.

</div>
