<div dir="rtl" align="right">

# NetSec Automation Quickstart

הפריסה הייחוס רצה על VM קטן שבשליטתכם (‏Oracle Always Free ARM
הוא נתיב ה-$0 המומלץ) שאליו מגיעים דרך Tailscale. הדשבורד,
ה-notebook וה-CLI כולם יכולים לשלוח PCAP לתוכו; ה-worker מנתח כל
capture, כותב verdicts + דוחות HTML/PDF, ושולח את הדוח המוגמר
ישירות (‏SMTP) לכתובת שהמעלה סיפק. ‏workflow של n8n יכול להיות
מחווט כערוץ משלוח fallback כש-SMTP נכשל - ראו
[`VM_OPS.md`](VM_OPS.md#email-delivery-on-completion).

כל מה שה-VM צריך נמצא ב-`deploy/`. הקובץ הזה עובר על השאלות
הנפוצות שאנשים נתקלים בהן כשהם מקימים את זה. לצעדי הפריסה הייחוס
ראו [`deploy/README.md`](../deploy/README.md); לפרטי firewall /
Oracle Security-List / iptables, ראו [`VM_DEPLOYMENT.md`](VM_DEPLOYMENT.md).

‏notebook הדשבורד עובד בלי כלום מזה - נתיב ה-VM הוא המצב
"פעיל-תמיד", לא תלות נדרשת.

---

## מה נשלח ב-`deploy/`

ארבעה שירותי docker-compose + Dockerfile אחד לכל image של אפליקציה,
כולם קשורים ל-`TS_BIND` (ה-IP של Tailscale של ה-VM שלכם) כך
ששום דבר לא מאזין על interface ציבורי:

| שירות | פורט | מה הוא עושה |
|-------------|------|-----------------------------------------------------------------|
| `ingest_api`| 8766 | ‏endpoint להעלאת HMAC streaming חתום (`/v1/pcap`), ‏health + דוחות |
| `worker`    | -    | תופס sessions בתור, מריץ צינור זיהוי, כותב דוחות, שולח את ה-PDF המוגמר דרך SMTP |
| `retention` | -    | אחזקה יומית (מחיקת גולמי של 7 ימים, סימן מים של 85%, גיבוי DB, ‏VACUUM) |
| `n8n`       | 5678 | *אופציונלי* - מקבל את ה-fallback webhook של ה-worker כש-SMTP עצמו נכשל |

פריסת אחסון תחת `NETSEC_DATA_ROOT` (ברירת מחדל `/srv/netsec`):

```
data/pcap/YYYY/MM/DD/<sha8>_<orig>.pcap    הקלטות גולמיות - 7 ימים ואז מוסרות
data/fields/YYYY/MM/<sha8>.tsv.gz          ייצוא שדות gzipped - נשמר לנצח
reports/<session_id>/{verdicts.json,verdicts.md,report.html,report.pdf}
db/netsec.db (+ גיבויים מתוארכים)             היסטוריית SQLite
```

העלאת sensor → ‏ingest API מכניס session לתור → ‏worker מנתח →
‏verdicts + דוחות בדיסק → ‏SMTP של ה-worker שולח את ה-PDF לכתובת
שהייתה על `X-Notify-Email` (נופל ל-`NETSEC_NOTIFY_EMAIL`, אחר כך
ל-n8n webhook, אחר כך לרשומה log-only בלבד).

---

## דרישות קדם

התקינו על ה-VM:

1. **‏Docker Engine + plugin של Compose** (‏Ubuntu 22.04+, ‏x86-64
   או ARM). ‏`sudo apt-get install docker.io docker-compose-plugin`.
2. **‏Tailscale**. ‏`curl -fsSL https://tailscale.com/install.sh | sh &&
   sudo tailscale up --hostname=<name>`.
3. **‏chrony** (‏NTP - נדרש על ידי פרוטוקול telemetry-reconciliation,
   `docs/VM_ARCHITECTURE_HE.md` §13).

התקינו על כל מכונה שצריכה לדבר עם ה-VM:

- **‏Tailscale** (הצטרפו לאותו tailnet כמו ה-VM).
- **‏Wireshark** כולל `tshark` - נדרש רק איפה שאתם תופסים PCAPs,
  לא על ה-VM עצמו.

מפתחות API של LLM ב-free tier הם אופציונליים. נתיב אפס-מפתח הוא
`LLM_JUDGE_PROVIDER=ollama` עם daemon מקומי של Ollama; כל ספק
ב-`deploy/.env.example` כבוי כברירת מחדל ונדלק רק כשאתם מדביקים
מפתח.

---

## הגדרה פעם אחת

```bash
git clone <your-fork>
cd <repo>/deploy
cp .env.example .env
```

פתחו `.env` והגדירו לפחות:

- `TS_BIND` - ה-IP של Tailscale של ה-VM שלכם (`tailscale ip -4`).
- `N8N_ENCRYPTION_KEY` - 32 תווים אקראיים. כל אחד מאלה עובד:
  - Linux / Mac:
    `openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 32`
  - Windows PowerShell:
    `-join ((48..57)+(65..90)+(97..122) | Get-Random -Count 32 | ForEach-Object {[char]$_})`
  - **אובדן המפתח הזה מוחק כל אישור ששמרתם בתוך n8n.**
    גבו אותו מחוץ לריפו (מנהל סיסמאות, קובץ מוצפן).

כל השאר ב-`.env.example` נשלח עם ברירת מחדל עובדת מהקוד. ראו את
הקובץ עצמו למה שכל משתנה עושה; הדגשים:

- `NETSEC_DATA_ROOT` - איפה PCAPs, דוחות וה-DB חיים
  (`/srv/netsec` ברירת מחדל). ‏`retention` שומר על זה חסום, אז הוא
  לעולם לא יזלוג ל-volume בתשלום.
- `LLM_JUDGE_PANEL` - פאנל ברירת המחדל צריך מפתחות Groq + Gemini +
  Ollama מקומי. לריצת אפס-מפתח, השתמשו רק
  `LLM_JUDGE_PANEL=ollama:qwen2.5:14b,ollama:phi4:14b` או זרקו את
  הפאנל לגמרי והגדירו `LLM_JUDGE_PROVIDER=ollama`.
- `NETSEC_NOTIFY_EMAIL` ו-`N8N_WEBHOOK_URL` - משלוח אופציונלי
  פר-session. הגדירו את זה שאתם משתמשים בו; השאירו את השני ריק.
- `SMTP_USER` / `SMTP_PASS` - רק אם אתם משתמשים בנתיב האימייל הישיר
  (`llm_judge/send_report.py`) או `NETSEC_NOTIFY_EMAIL`.
  ‏Gmail App Passwords: הפעילו 2FA קודם, אחר כך הפיקו ב-
  <https://myaccount.google.com/apppasswords>.

`deploy/.env` ב-gitignore; אשרו עם `git status` לפני דחיפה.

---

## העלאת המערך

מ-`deploy/`:

```bash
sudo mkdir -p /srv/netsec && sudo chown $USER /srv/netsec
docker compose up -d
```

**ריצה ראשונה** (‏2-6 דק'): ‏Docker בונה את ה-images של `ingest_api`
ו-`worker` (מתקין `fastapi`, `numpy`, `pandas`, `scikit-learn`,
`torch`, `scapy`, `weasyprint`), מושך את `n8nio/n8n:latest`,
ומאתחל את ה-DB של SQLite של n8n.

**ריצות עוקבות**: שניות - כל ארבעת השירותים חוזרים למעלה במקום.

אשרו מכל מכונה ב-tailnet שלכם:

```bash
# ‏ingest API - אמור להחזיר {"status":"ok","schema":<n>}
curl -s http://<vm-tailscale-ip>:8766/healthz

# ‏n8n UI עונה (302 ל-/setup בביקור ראשון, 200 אחרי)
curl -s -o /dev/null -w "%{http_code}\n" http://<vm-tailscale-ip>:5678/
```

אשרו מהאינטרנט הציבורי ששום פורט לא עונה - רק peers של Tailscale
אמורים להגיע אליהם.

---

## רישום sensor

כל מעלה צריך סוד HMAC משלו. שמות sensor מזהים מעלה אחד (מחשב נייד,
‏Pi, ‏CI runner):

```bash
# מ-deploy/, כמשתמש שבעלים של /srv/netsec
sudo NETSEC_DATA_ROOT=/srv/netsec python3 create_sensor.py laptop
```

פלט (מודפס פעם אחת, לא ניתן לשחזור - ה-token נשמר hashed, סוד
ה-HMAC נשמר בטקסט פתוח כי אימות HMAC דורש את הסוד עצמו):

```
# sensor 'laptop' registered - shown ONCE, store safely
NETSEC_SENSOR_ID=laptop
NETSEC_SENSOR_SECRET=<64 hex chars>
NETSEC_API_TOKEN=<44-char urlsafe>
```

הדביקו את שלוש השורות האלה לסביבה של כל מכונה שתעלה PCAPs.
‏revocation של sensor שנפרץ הוא פקודת SQL אחת:

```sql
UPDATE sensors SET revoked_at = datetime('now') WHERE name = 'laptop';
```

אוטוריזציה בין sensors נאכפת: ‏bearer token יכול לקרוא רק את
ה-sessions והדוחות שלו. הגדירו `NETSEC_ADMIN_SENSOR=<name>` (שם
ה-sensor שהדשבורד המרכזי שלכם רושם איתו) אם אתם רוצים שה-token של
אותו sensor יקרא sessions של כל sensor.

---

## חיווט ה-workflow של התרעת n8n

פתחו `http://<vm-tailscale-ip>:5678` בדפדפן (הביקור הראשון מוביל
אתכם דרך יצירת חשבון owner - שמרו את האישור הזה בטוח;
`N8N_BASIC_AUTH_*` לא נתמך ב-n8n מודרני).

1. **‏Workflows** → **‏⋮ (import)** → **‏Import from File** → בחרו
   `deploy/n8n_workflows/mvp_triage_email.json`. זה נשלח כ-volume
   mounted ב-`/workflows` בתוך ה-container, אז אתם יכולים גם להריץ:
   ```bash
   docker compose exec n8n n8n import:workflow \
     --input=/workflows/mvp_triage_email.json
   ```
2. פתחו את ה-workflow המיובא (**‏NetSec Triage Alert**). לחצו על
   ה-node **‏Send Email Alert** וצרפו אישור SMTP - **‏+ Add
   Credential** → **‏SMTP**:

   | שדה     | ערך                                          |
   |----------|------------------------------------------------|
   | Name     | ‏`NetSec SMTP` (כל שם, אבל היו עקביים)    |
   | User     | תיבת הדואר המלאה שלכם                              |
   | Password | app password או סיסמת חשבון (פר-ספק) |
   | Host     | ה-host של ה-SMTP שלכם (למשל `smtp.gmail.com`)         |
   | Port     | `587`                                          |
   | SSL/TLS  | **כבוי** (‏STARTTLS על פורט 587)                 |

3. הגדירו את שדות `fromEmail` ו-`toEmail` על ה-node לכתובות שלכם.
   הפעילו **‏Active** (ימין למעלה) כך שה-webhook חי.
4. העתיקו את **‏Production URL** של ה-node ‏`Worker Webhook`
   (נראה כמו `http://<vm-ip>:5678/webhook/netsec-alert`) והדביקו
   ל-`N8N_WEBHOOK_URL` ב-`deploy/.env`, אחר כך
   `docker compose restart worker`.

זהו. ה-worker עושה POST של `{session_id, label, kind, sha256,
results, worst}` ל-webhook אחרי כל session; ה-node IF של
ה-workflow בודק ש-`worst` מתאים ל-`malicious|suspicious`;
‏sessions מתאימים יוצאים באימייל.

אישורים צריכים להיות מוזנים מחדש רק אם ה-volume בשם `n8n_data`
נהרס (`docker compose down -v`) או אם איבדתם את
`N8N_ENCRYPTION_KEY`.

---

## הפעלה אוטומטית ב-boot של host

כל ארבעת השירותים משתמשים ב-`restart: unless-stopped`, אז daemon
של Docker מחזיר אותם אוטומטית. הפעילו את ה-daemon עצמו:

```bash
sudo systemctl enable docker
```

יש race אחד ששווה לדעת: ‏`${TS_BIND}` היא כתובת `tailscale0`, אז
‏Docker יכול להתחיל לפני ש-`tailscaled` מקצה את ה-IP ולא לקשור
בהצלחה. ‏`restart: unless-stopped` מנסה שוב עם backoff, אז זה
מתכנס תוך דקה; הוסיפו drop-in של `After=tailscaled.service` לשירות
docker אם ההשהיה מפריעה לכם.

---

## אימות end-to-end

שלוש דרכים עצמאיות:

**א. העלאה עם ה-CLI** (בדיקת העשן הפשוטה ביותר):

```bash
export NETSEC_INGEST_URL=http://<vm-tailscale-ip>:8766
export NETSEC_SENSOR_ID=laptop
export NETSEC_SENSOR_SECRET=<מ-create_sensor>
python3 tools/upload_pcap.py attack_tests/pcaps/tcp_syn_scan.pcap
# מדפיס {"session_id": N, ...}. המתינו רגע ל-worker.
curl -s -H "Authorization: Bearer <token>" \
  http://<vm-tailscale-ip>:8766/v1/sessions/N
# {..., "status":"done", "n_pkts":2020, ...}
open http://<vm-tailscale-ip>:8766/v1/reports/N.html   # or .pdf, .json, .map
```

אם `N8N_WEBHOOK_URL` מוגדר, אימייל נוחת תוך כמה שניות מסיום
ה-worker.

**ב. מכפתור הדשבורד.** טענו PCAP ב-notebook. בסרגל הצד, הקלידו את
הכתובת שאליה אתם רוצים שהדוח ישלח, בחרו preset של פאנל LLM, ולחצו
**‏Send S1 to VM (mail report)**. הכפתור חותם על ה-capture ומזרים
אותו ל-ingest API מעל Tailscale (`server/dashboard_client.py`),
בדיוק כמו ש-`tools/upload_pcap.py` עושה מה-shell. הגדירו
`NETSEC_INGEST_URL` / `NETSEC_SENSOR_ID` / `NETSEC_SENSOR_SECRET`
ב-shell שמשיק את ה-notebook - עד שהם מוגדרים הכפתור מדווח
`set NETSEC_INGEST_URL` ולא שולח כלום.

ל-capture שה-VM כבר ניתח יש dedup לפי SHA-256: ההעלאה מחזירה את
ה-session הקיים במקום להכניס את אותה עבודה לתור פעמיים, והכפתור
אומר זאת.

**ג. ‏GitHub Actions אינו נתיב ingest.** ה-workflow ‏`analyze-pcap.yml`
שצפה בתיקיית `incoming/` נגרס - תקרת ההעלאה של 25MB של Actions
הפכה אותו לחסר תועלת ל-captures אמיתיים, ונתיב ה-VM מכסה כל מקרה
שהוא כיסה. מה שנשאר תחת `.github/` הוא `ci.yml`: בדיקות בתוספת
בדיקת סנכרון notebook-to-module. שום דבר על ניתוח captures שלכם
לא תלוי ב-GitHub.

---

## כיוון

שנו את אלה ב-`deploy/.env`, אחר כך `docker compose restart worker`
(או `n8n` אם השינוי נוגע באותו שירות):

- `LLM_JUDGE_PANEL` - אילו שופטים מצביעים. כל שופט שאתם מפרטים
  רץ וכל verdict חוזר (אין fallback אוטומטי שמחליף מודלים בשקט;
  שופט כושל מדווח).
- `LLM_JUDGE_MAX_CANDIDATES` - מועמדים מסומנים שנשפטים פר-PCAP.
  **ברירת מחדל `40`.** ‏Free tiers עם תקציבי טוקנים צפופים לדקה
  צריכים את זה נמוך יותר - נמדד על free tier של Groq 2026-08,
  התקרה לדקה היא 6,000 טוקנים ל-`llama-3.1-8b-instant` ו-
  8,000 למודלי `gpt-oss`, אז capture של 30 מועמדים מוציא את רוב
  זמן השעון בהמתנה ל-429s. הורידו ל-`10` על מפתח burst.
- `LLM_JUDGE_BATCH_SIZE` - מועמדים ארוזים לקריאה אחת.
  **ברירת מחדל `1`.** בקשה עולה `1675 + n x 720` טוקנים (ה-system
  prompt משולם פעם אחת לקריאה; כל blob מועמד הוא ~720). בתקרות
  לעיל, ‏`n=3` עולה 3,835 ונכנס בנוחות, בעוד `n=5` עולה 5,275 -
  88% מהדקה כולה של llama-8b בבקשה אחת, שכל קריאה מקבילה חונקת
  לנפילה פר-מועמד שהיא הייתה אמורה להחליף.
- `LLM_JUDGE_TIMEOUT_S` - timeout פר-בקשה בשניות. **ברירת מחדל
  `300`** בקוד; העלו ל-`600` כאשר מודל Ollama מקומי קר צריך לטעון
  לפני תשובתו הראשונה.
- `NETSEC_MAX_UPLOAD_GB` - תקרת גודל קובץ יחיד על endpoint
  הקליטה. ברירת מחדל `10`.
- `NETSEC_ENABLE_SHODAN=1` (בתוספת `SHODAN_API_KEY`) - חיפושי מוניטין
  של peer חיצוני. כבוי כברירת מחדל; כשמופעל, מפעיל את משקל ה-threat
  intel של השופט (`W_TI`).

כיוון בצד ה-sensor חי בסביבת ה-sensor
(`NETSEC_CHUNK_SECONDS`, `NETSEC_RING_FILES`, `NETSEC_SPOOL_CAP_GB`);
ראו `sensor/capture_agent.py`.

---

## גיבוי והתאוששות

**מה פרסיסטנטי:**

- `deploy/.env` - הסודות שלכם. גבו אותו מחוץ לריפו (מנהל סיסמאות,
  קובץ מוצפן באחסון אישי).
- `${NETSEC_DATA_ROOT}/db/` - היסטוריית SQLite + הגיבויים הליליים
  ששירות ה-retention כותב. העתיקו את התיקייה כולה לשמור על
  היסטוריה.
- `${NETSEC_DATA_ROOT}/reports/` - ‏HTML/PDF/JSON, נשמרים לנצח.
- ‏Volume בשם `n8n_data` של Docker - ‏SQLite DB של n8n, מחזיק את
  ה-workflow והאישורים. גבו על ידי ייצוא מה-container:
  ```bash
  docker compose exec n8n \
    tar -czf - -C /home/node/.n8n . > n8n_backup_$(date +%Y%m%d).tgz
  ```

**אם ה-DB של n8n אבד** (`docker compose down -v`, כשל דיסק, פגימת
volume): ייבאו מחדש את `mvp_triage_email.json` וצרו מחדש את אישור
ה-SMTP. קובץ ה-workflow נשלח עם הריפו אז הוא תמיד ניתן לשחזור;
האישור מוצפן עם `N8N_ENCRYPTION_KEY` ולא יכול להישלח בתוך ה-workflow.

**שום דבר לגבות:** ה-images של Docker שנבנו (`docker compose build`
יוצר אותם מחדש), ‏buffer הטבעת של ה-capture המקומי של ה-sensor
(מקור האמת הוא ה-VM ברגע שה-sensor העלה), ו-cache של שופט ה-LLM
(`llm_judge/cache/` - מתחולל מחדש בעצמו לפי דרישה).

---

## פתרון בעיות

- **‏`Cannot reach the automation stack on set NETSEC_REMOTE_HOST`
  תחת כפתור הדשבורד.** בדיקת הכפתור לא יכלה להגיע ל-`:8765`
  ו/או `:5678` כי `NETSEC_REMOTE_HOST` ריק. הגדירו את שלושת
  משתני `NETSEC_REMOTE_*` בתוספת `NETSEC_SSH_KEY` בסביבה שמתחילה
  את הדשבורד.
- **‏`sqlite3.OperationalError: unable to open database file` כש
  מריצים `create_sensor.py`.** ‏container ה-`ingest_api` יצר את
  `db/netsec.db` כ-root; הריצו את `create_sensor.py` דרך `sudo`,
  או השתמשו ב-`docker compose exec` כדי להריץ אותו כאותו משתמש
  שה-container משתמש בו.
- **‏`docker compose up -d` ראשון נראה תקוע דקות.** נורמלי -
  ‏image ה-`worker` מתקין torch, pandas, sklearn, weasyprint
  וחברים לתוך ה-image שנבנה. צפו בזה עם
  `docker compose logs -f worker`. קורה רק ב-rebuild.
- **אימייל מגיע עם `429 Too Many Requests` בפירוש.**
  מפתח LLM של free tier פגע בגבול הדקה שלו. הורידו את
  `LLM_JUDGE_MAX_CANDIDATES` ב-`.env` או עברו למודל קטן יותר /
  מקומי.
- **‏`HTTP 403 - error code: 1010`.** ‏Cloudflare חוסם את ה-User-Agent
  ברירת המחדל של Python. ‏`llm_judge/llm_clients.py` כבר שולח אחד
  מותאם; אם ערכתם את הקובץ הזה, שחזרו את ה-header של User-Agent.
- **ה-workflow של n8n רץ אבל אין אימייל.** פתחו את טאב ה-Executions
  של ה-workflow ב-n8n. הכישלון כמעט תמיד הוא אישור ה-SMTP (סיסמה
  שגויה, ‏2FA לא מופעל, פורט שגוי).
- **הדשבורד מראה `[Errno 22] Invalid argument` בטעינה.** ה-loader
  פגע ב-PCAP עם timestamp לפני 1970. השתמשו ב-capture שהוקלט
  אחרי 1970.

---

## מה מחוץ ל-scope של ה-quickstart הזה

- **‏Dify** (‏RAG + chat agent). לא חלק מה-ecosystem; אתם יכולים
  להריץ אותו בנפרד על אותו VM אם יש לכם RAM לחסוך (המערך של
  Dify הוא עוד 7 containers).
- **ניתוב רב-משתמשי.** הכל כרגע הולך למי שבבעלותו אישור ה-SMTP.
  הוסיפו ניתוב פר-sensor ב-workflow של n8n אם צריך - ה-payload של
  ה-webhook כולל `sha256`, `label` ו-`kind`.
- **טריגרים של capture בזמן אמת.** העיצוב הוא: ‏sensor דוחף על כל
  chunk סגור של ring-buffer; ‏latency של תור הקליטה היא שניות, לא
  מחזור poll של 60 שניות שהמערך המקומי-בלבד הקודם השתמש בו.

</div>
