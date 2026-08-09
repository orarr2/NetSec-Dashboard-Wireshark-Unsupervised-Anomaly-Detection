# סוכני AI אוטונומיים כאנליסטים - n8n / Dify על גבי Docker

> מסמך אפיון מלא בעברית, מותאם לפרויקט
> **NetSec-Dashboard-Wireshark-Unsupervised-Anomaly-Detection**.
> נכתב כדי לתת תמונה מקצה-לקצה: מה נדרש, איך מתכננים, איך בונים ואיך מפעילים
> סוכן/י AI אוטומטיים שמנתחים את פלטי ה־Dashboard וה־LLM Judge בזמן אמת.

---

## תוכן עניינים

1. [רקע: איפה נכנסים הסוכנים בפרויקט](#1-רקע-איפה-נכנסים-הסוכנים-בפרויקט)
2. [למה Docker דווקא, ולמה n8n או Dify](#2-למה-docker-דווקא-ולמה-n8n-או-dify)
3. [n8n מול Dify - השוואה מעשית](#3-n8n-מול-dify--השוואה-מעשית)
4. [דרישות תשתית ומערכת](#4-דרישות-תשתית-ומערכת)
5. [ארכיטקטורת יעד: זרימת מידע מקצה-לקצה](#5-ארכיטקטורת-יעד-זרימת-מידע-מקצה-לקצה)
6. [התקנת Docker Desktop / Engine - מדריך פרקטי](#6-התקנת-docker-desktop--engine--מדריך-פרקטי)
7. [n8n: פריסה מלאה ב־Docker Compose](#7-n8n-פריסה-מלאה-ב־docker-compose)
8. [Dify: פריסה מלאה ב־Docker Compose](#8-dify-פריסה-מלאה-ב־docker-compose)
9. [חיבור LLM חינמי או בתשלום](#9-חיבור-llm-חינמי-או-בתשלום)
10. [חשיפת ה־PCAP והפרויקט לסוכן](#10-חשיפת-ה־pcap-והפרויקט-לסוכן)
11. [תבניות זרימה (Workflows) לדוגמה](#11-תבניות-זרימה-workflows-לדוגמה)
12. [תבניות סוכן אוטונומי (Agentic Patterns)](#12-תבניות-סוכן-אוטונומי-agentic-patterns)
13. [אבטחת מידע, סודות ו־Hardening](#13-אבטחת-מידע-סודות-ו־hardening)
14. [ניטור, לוגים ודיאגנוסטיקה](#14-ניטור-לוגים-ודיאגנוסטיקה)
15. [עלויות ותקציב מעשי](#15-עלויות-ותקציב-מעשי)
16. [Checklist להשקה - מה חייב להיות מוכן](#16-checklist-להשקה--מה-חייב-להיות-מוכן)
17. [שאלות נפוצות ותקלות מוכרות](#17-שאלות-נפוצות-ותקלות-מוכרות)
18. [מפת דרכים להמשך](#18-מפת-דרכים-להמשך)

---

## 1. רקע: איפה נכנסים הסוכנים בפרויקט

הפרויקט כולל שני מסלולי ניתוח קיימים:

1. **Dashboard מקומי** - נוטבוק Jupyter/Dash שמריץ במקביל
   `IsolationForest`, `DBSCAN`, `LSTM` וגם שכבת חוקים דטרמיניסטיים על
   קובצי PCAPNG (או הקלטה חיה דרך `tshark`), ומפיק כ־9 מסכי ניתוח.
2. **LLM Judge** - תוסף עצמאי תחת `llm_judge/` שממזג את כלל הסיגנלים
   לכל מועמד (IP / flow / session) ל־JSON אחיד ומחזיר פסיקה מובנית:
   `benign | suspicious | malicious`, קטגוריה, ביטחון, ראיות והסבר.

הפרויקט מוגדר במפורש כך שה־Judge הוא **אופציונלי, מקבל את פלט הצינור**
ואינו פועל בשם המערכת (`recommended_action` הוא המלצה לאנליסט אנושי).

**הרעיון של המסמך הזה**: להוסיף לפרויקט **שכבת "אנליסט מדמה" אוטונומית**
שרצה בתוך Docker, מקבלת את פלטי ה־Dashboard וה־Judge, מפעילה LLM (מקומי
או ענן חינמי/בתשלום), מוציאה חוות דעת בשפה חופשית, ויודעת גם:

- לפתוח טיקט/Issue/מייל/הודעת Slack או Telegram,
- להריץ מחדש את ה־Judge עם פרמטרים אחרים,
- לבקש פרשנות שנייה מסוכן LLM אחר ("ועדת שופטים"),
- להעשיר מידע (WHOIS, GeoIP, Threat Intel חינמי) לפני קבלת החלטה,
- לתעד את כל השרשרת ב־Database מובנה.

הכל בלי לגעת בקוד הליבה של הפרויקט - הכל דרך **קבצי הפלט** (`verdicts.json`,
`verdicts.md`, לוגים) ו/או **HTTP webhooks** שנוסיף.

---

## 2. למה Docker דווקא, ולמה n8n או Dify

### למה Docker

- **בידוד מלא**: כלים כמו n8n או Dify דורשים Node, Python, Redis,
  Postgres, OpenSearch/Weaviate ועוד - התקנה מקומית "טבעית" תשבור לך את
  סביבת הפרויקט. Container מבודד כל אלה.
- **שחזוריות**: קובץ `docker-compose.yml` יחיד מגדיר את *כל* הפריסה.
  לעבור למכונה חדשה = `docker compose up -d`.
- **Volumes**: הסוכן צריך גישה לתיקיות PCAP, `incoming/`, `llm_judge/output/`.
  ב־Docker זה שורה אחת של `volumes:` - בלי להתקין לו Python.
- **רשת פנימית**: כל השירותים מתקשרים דרך רשת Compose סגורה,
  והחוצה חשופה רק פורטת ה־UI (`5678` ל־n8n, `80` ל־Dify).
- **גיבוי וניקוי**: `docker compose down -v` מנקה הכל; `docker compose
  down` שומר על ה־volumes וההגדרות.
- **תמיכה ב־Windows / Mac / Linux** דרך Docker Desktop או Docker Engine -
  זהה בכולם.

### למה n8n או Dify (ולא Zapier / Make / קוד ידני)

| נושא | n8n | Dify | קוד ידני |
|---|---|---|---|
| Self-hosted חינמי | כן (Community) | כן (Community) | כן |
| ממשק גרפי לזרימות | Node graph - עוצמתי מאוד | Node graph + Chatflow/Agent | אין |
| תמיכה מובנית ב־LLM | מספר nodes ל־LLM | ליבת המוצר - LLMs, RAG, Tools, Agents | מה שתכתוב |
| ניהול Prompts | קיים אבל בסיסי | מרכזי, עם גרסאות, טסטים ומדדים | מה שתכתוב |
| RAG / Knowledge base | דרך integrations | מובנה כליבת מוצר | מה שתכתוב |
| Cron / Webhook / Files | חזק מאוד | דרך API + כלים חיצוניים | מה שתכתוב |
| קימום זמן | דקות | דקות | ימים |
| מטרה טבעית | Automation Engine | AI Platform / AI-native app | תלוי |

**המלצה בפרויקט הזה**:

- אם המטרה היא **תזמור** - לצפות ב־`incoming/`, להריץ את ה־CLI של
  ה־Judge, לפרסר את ה־JSON, לשלוח Slack/Email, לפתוח Issue - **n8n**.
- אם המטרה היא **בניית סוכן חכם** עם RAG על המסמכים של הפרויקט,
  זיכרון שיחה, מספר Tools מובנים ו־UI לצ'אט עם האנליסט־AI - **Dify**.
- **הכי חזק**: להריץ את שניהם. n8n ידחוף אירועים; Dify יספק את המוח.

---

## 3. n8n מול Dify - השוואה מעשית

### 3.1 n8n

- **מהות**: Automation platform, "Zapier קוד־פתוח"; מתאים לעצב זרימות
  מ־trigger (Webhook / Cron / File / Kafka) דרך צעדי עיבוד ועד actions
  (Email, Slack, GitHub, HTTP).
- **סוכנים**: יש node בשם `AI Agent` שמאפשר להגדיר Tools דינמיים
  (HTTP Tool, Function Tool, Vector Store Retriever) ולתת ל־LLM לבחור
  איזה כלי להפעיל בכל צעד.
- **חוזק בפרויקט שלך**: קורא קבצי PCAPNG חדשים, מריץ `judge_cli.py`,
  ממתין לתוצאה, מנתח את `verdicts.json`, וקורא ל־LLM רק כשיש ממצא
  חשוד/זדוני. חוסך קריאות LLM ברוב הריצות.
- **חולשות**: לא מתמחה ב־LLMOps (אין A/B, אין eval אוטומטי, ניהול
  prompts בסיסי).

### 3.2 Dify

- **מהות**: פלטפורמת פיתוח לאפליקציות AI. משלבת Prompt Studio, Datasets
  (RAG), Tools ("Function calling"), Agents ו־Workflows.
- **סוכנים**: פרדיגמה מובנית: Agent שיודע לבחור Tool → להריץ →
  להעריך → לאסוף לזיכרון → להחליט אם לסיים. תומך ב־ReAct,
  Function Calling, Multi-agent, Iteration ו־Chatflow.
- **חוזק בפרויקט שלך**: אנליסט־AI עם זיכרון וגישה ל־knowledge base
  שמורכב מהמסמכים שלך (`docs/MODELS.md`, `docs/LLM_JUDGE_SPEC.md`,
  `docs/TRADEOFFS_EN.md`, `PROMPT_CHANGELOG.md`) → בכל שאלה הוא עונה
  מתוך המסמכים ולא ממציא.
- **חולשות**: יותר "כבד" מ־n8n (Postgres + Redis + Weaviate + Sandbox +
  API + Web), אינטגרציה עם קבצי מערכת פחות טריוויאלית מ־n8n.

### 3.3 חלוקת עבודה מומלצת (Hybrid)

```
File in incoming/ ──► n8n (trigger) ──► judge_cli.py (docker exec)
                                    └──► HTTP POST ל־Dify API
                                                       │
                                                       ▼
                                             Dify Agent (LLM + RAG + Tools)
                                                       │
                                                       ▼
                                           JSON verdict + reasoning
                                                       │
                        ┌──────────────────────────────┴───────────────┐
                        ▼                                              ▼
                n8n: Slack / Email / GitHub Issue          n8n: SQLite / Postgres audit log
```

---

## 4. דרישות תשתית ומערכת

### 4.1 חומרה מינימלית (מכונת פיתוח)

| רכיב | n8n בלבד | Dify בלבד | n8n + Dify + Ollama מקומי |
|---|---|---|---|
| CPU | 2 cores | 4 cores | 6+ cores |
| RAM | 2 GB | 6 GB | 16 GB (מודלים 7B-8B) / 32 GB (13B+) |
| דיסק | 5 GB | 20 GB | 60+ GB (מודלים) |
| GPU | לא חובה | לא חובה | מומלץ מאוד למודלים גדולים |

### 4.2 תוכנה חובה

- **Docker Desktop** ל־Windows/Mac או **Docker Engine + Compose plugin**
  ל־Linux (גרסה 24+).
- `docker compose` (V2, בפקודה אחת עם רווח - לא `docker-compose`).
- Git.
- **Wireshark / tshark** - כבר קיים בפרויקט; לא נדרש בתוך ה־container
  של ה־AI Platform, רק בסביבה שמייצרת את ה־PCAP.

### 4.3 תוכנה מומלצת

- **Ollama** - להרצת LLM מקומיים חינם (שימש בעבר ב־GitHub Actions
  עם `llama3.2`, ‏ב־workflow שהוצא משימוש). ניתן להריץ גם כ־container.
- **ngrok / Cloudflare Tunnel** - אם רוצים לחשוף Webhook החוצה מבלי
  לפתוח פורט בראוטר.
- **מפתחות API** לפי הבחירה שלך (Gemini, Groq, OpenAI-compatible וכו').
  כפי שנעשה ב־`llm_judge/`: מפתחות **לא נשמרים בגיט**, רק
  ב־`.env` המקומי.

---

## 5. ארכיטקטורת יעד: זרימת מידע מקצה-לקצה

```
┌─────────────────────────────────────────────────────────────────────┐
│                       VM (Ubuntu 22.04+, ARM/x86-64)                │
│                                                                     │
│   Sensor (‏laptop / Pi 5) ── HMAC over Tailscale ──► ingest_api      │
│                                                                     │
│   ┌─────────────────  Docker network: deploy_default  ───────────┐  │
│   │                                                              │   │
│   │   [ingest_api]  → SQLite queue → [worker]                   │   │
│   │        :8766          |            (מריץ analyze_and_judge   │   │
│   │                       |             + WeasyPrint report)     │   │
│   │                       ▼                                      │   │
│   │   [n8n] ← webhook ← [worker]                                 │   │
│   │     :5678                                                    │   │
│   │     │                                                        │   │
│   │     ├──HTTP──► [Dify API] (‏אופציונלי; RAG על verdicts)      │   │
│   │     │              │                    │                    │   │
│   │     │              ▼                    ▼                    │   │
│   │     │         [Postgres] [Weaviate] [Sandbox] [Redis]        │   │
│   │     │                                                        │   │
│   │     ├──HTTP──► [Ollama] (מודלים מקומיים)                     │   │
│   │     │                                                        │   │
│   │     └──HTTP──► [ספקי LLM חיצוניים דרך HTTPS]                 │   │
│   │                                                              │   │
│   └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│   פלטים: /srv/netsec/reports/<sid>/verdicts.json / verdicts.md      │
│           /srv/netsec/db/netsec.db (SQLite היסטוריה)                │
│           GitHub Issue / Slack / Telegram / Email                   │
└─────────────────────────────────────────────────────────────────────┘
```

**נקודות עיקריות**:

- Wireshark ממשיך לפעול כרגיל ב־Host.
- שירות אחד בלבד קורא מ־`incoming/` - n8n (עם `Local File Trigger`).
- ה־Judge רץ בקונטיינר משלו כדי לא לזהם את סביבת ה־Dashboard.
- Dify רץ כ־Stack משלו (מספר containers) - Postgres שלו לא מוגש
  ל־n8n.
- ה־LLM נבחר לפי משתנה סביבה, לא לפי קוד - בדיוק כמו בפרויקט הנוכחי.

---

## 6. התקנת Docker Desktop / Engine - מדריך פרקטי

### 6.1 Windows

1. הורדה: <https://docs.docker.com/desktop/install/windows-install/>
2. חובה להפעיל **WSL2** (`wsl --install`) ולוודא שהמערכת עדכנית.
3. אחרי התקנה: `docker --version` ו־`docker compose version`.
4. מומלץ להגדיר ב־Docker Desktop → Settings → Resources:
   - CPU: 4+
   - RAM: 8-16 GB
   - Disk: 50+ GB
5. הפעל **File Sharing** לתיקיית הפרויקט (אחרת ה־volumes יחזירו
   `permission denied`).

### 6.2 Linux (Ubuntu 22.04+)

```bash
# ניקוי גרסאות ישנות
sudo apt remove docker docker-engine docker.io containerd runc

# מפתח GPG והרפוזיטורי הרשמי
sudo apt install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
    sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
    sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# התקנה
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin

# להריץ בלי sudo
sudo usermod -aG docker $USER
newgrp docker
```

### 6.3 בדיקה

```bash
docker run --rm hello-world
docker compose version
```

---

## 7. n8n: פריסה מלאה ב־Docker Compose

### 7.1 מבנה תיקיות

התשתית עברה מ־`automation/` המקומית שהוצאה משימוש אל `deploy/` המוגדרת בריפו:

```
NetSec-Dashboard-Wireshark-Unsupervised-Anomaly-Detection/
├─ ... (הפרויקט הקיים)
└─ deploy/
   ├─ .env                       ← לא ב־git (יש להוסיף ל־.gitignore)
   ├─ .env.example               ← כל משתני הסביבה שהמערכת קוראת + ברירות מחדל
   ├─ docker-compose.yml         ← n8n + ingest_api + worker + retention
   ├─ Dockerfile.ingest          ← ה־image של ה־ingest API
   ├─ Dockerfile.worker          ← ה־image של ה־worker (מריץ גם את retention)
   ├─ n8n_workflows/
   │   └─ mvp_triage_email.json  ← ה־workflow ל־n8n (בריפו, ניתן ל־import)
   └─ create_sensor.py           ← רישום חיישן חדש והדפסת credentials פעם אחת
```

תוצרי ריצה נשמרים ב־`${NETSEC_DATA_ROOT}` (ברירת מחדל `/srv/netsec`):
`data/pcap/YYYY/MM/DD/*.pcap` (‏גולמי, 7 ימים), `data/fields/*.tsv.gz`
(‏אינדקס לתמיד), `reports/<session_id>/{verdicts.json,verdicts.md,report.html,report.pdf}`,
`db/netsec.db`.

### 7.2 קובץ `.env`

מבוסס על `deploy/.env.example` שכולל את כל המשתנים והברירות שהקוד באמת קורא.
מכתובת ה־Tailscale ועד תצורת ה־LLM - הכל שם, מתועד, וזה המקום היחיד שבו חיים
סודות:

```dotenv
# Core
TS_BIND=<vm-tailscale-ip>              # כתובת ה-Tailscale של ה-VM
NETSEC_DATA_ROOT=/srv/netsec
TZ=UTC

# n8n
N8N_ENCRYPTION_KEY=CHANGE_ME_32_CHAR_RANDOM_STRING
# הערה: N8N_BASIC_AUTH_* לא נתמכים ב-n8n המודרני - יוצרים owner account בדפדפן

# LLM providers (בחר את מה שרלוונטי לך)
LLM_JUDGE_PROVIDER=ollama              # claude | ollama | openai_compat
OLLAMA_HOST=http://ollama:11434
OLLAMA_MODEL=qwen2.5:14b
OPENAI_COMPAT_BASE_URL=
OPENAI_COMPAT_MODEL=
OPENAI_COMPAT_API_KEY=

# Dify (אופציונלי, לשילוב hybrid)
DIFY_API_BASE=http://dify-api/v1
DIFY_API_KEY=
```

### 7.3 `docker-compose.yml` - הסטאק שנשלח בריפו

הקובץ החי הוא `deploy/docker-compose.yml`. ארבע השירותים - `n8n`,
`ingest_api`, `worker`, `retention` - כולם קשורים ל־`${TS_BIND}` כך שרק
Tailscale-peers רואים אותם, ותצורתם נקבעת ב־`deploy/.env`:

(‏עותק מקוצר להמחשה - הקובץ הנוכחי מכיל 6 שירותים: נוספו `ollama` ו־`caddy`.)

```yaml
services:
  n8n:
    image: n8nio/n8n:latest
    restart: unless-stopped
    ports:
      - "${TS_BIND:-127.0.0.1}:5678:5678"
    environment:
      - N8N_HOST=${TS_BIND:-127.0.0.1}
      - N8N_ENCRYPTION_KEY=${N8N_ENCRYPTION_KEY}
      - GENERIC_TIMEZONE=${TZ:-UTC}
    volumes:
      - n8n_data:/home/node/.n8n
      # תבניות ה־workflow ניתנות ל־import מה־UI או דרך ה־CLI:
      #   docker compose exec n8n n8n import:workflow \
      #     --input=/workflows/mvp_triage_email.json
      - ./n8n_workflows:/workflows:ro

  ingest_api:
    build:
      context: ..
      dockerfile: deploy/Dockerfile.ingest
    restart: unless-stopped
    ports:
      - "${TS_BIND:-127.0.0.1}:8766:8766"
    environment:
      - NETSEC_DATA_ROOT=/srv/netsec
      - NETSEC_MAX_UPLOAD_GB=${NETSEC_MAX_UPLOAD_GB:-10}
    volumes:
      - ${NETSEC_DATA_ROOT:-/srv/netsec}:/srv/netsec

  worker:
    build:
      context: ..
      dockerfile: deploy/Dockerfile.worker
    restart: unless-stopped
    env_file: .env
    environment:
      - NETSEC_DATA_ROOT=/srv/netsec
    volumes:
      - ${NETSEC_DATA_ROOT:-/srv/netsec}:/srv/netsec

  retention:
    build:
      context: ..
      dockerfile: deploy/Dockerfile.worker
    restart: unless-stopped
    env_file: .env
    environment:
      - NETSEC_DATA_ROOT=/srv/netsec
    volumes:
      - ${NETSEC_DATA_ROOT:-/srv/netsec}:/srv/netsec
    command: ["python", "-m", "server.retention"]

volumes:
  n8n_data:
```

`ingest_api` מכיל את `server/ingest_api.py` (FastAPI, פורט 8766) +
`server/{auth,db,storage}.py`; `worker` מכיל את `server/worker.py` שקורא
מהתור, מריץ את הצינור המלא (‏`llm_judge/judge_cli.analyze_and_judge`),
כותב `verdicts.json` / `.md` + `report.html` (‏WeasyPrint) לדיסק וגם שולח
webhook אל n8n אם `N8N_WEBHOOK_URL` מוגדר. `retention` הוא אותו image
עם `command: server.retention` (‏ניקוי יומי + גיבוי DB).

Ollama רץ כשירות compose משלו (‏image ‏`ollama/ollama`; volume בשם
`ollama_models` שומר את המודלים בין restarts). קונטיינר `worker` פונה
אליו דרך `http://ollama:11434` ברשת הפנימית של docker.
אין `judge_runner` נפרד - כל הצינור חי בתוך `worker`, נגיש דרך התור, וללא
`docker exec` בזמן ריצה.

### 7.4 בניית ה־image של ה־worker

הקובץ הוא `deploy/Dockerfile.worker` בריפו. הוא מתקין tshark, WeasyPrint
(‏Pango + Cairo כדי לרנדר PDF), ואת כל תלויות הצינור והשופט. מוצג כאן
כמראה מקום, המקור בריפו:

```dockerfile
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark ca-certificates curl \
    libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt server/requirements.txt llm_judge/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
      -r server/requirements.txt -r llm_judge/requirements.txt \
      weasyprint

COPY server/ server/
COPY llm_judge/ llm_judge/
COPY app/ app/
COPY attack_tests/ attack_tests/

CMD ["python", "-m", "server.worker"]
```

אין `entrypoint.sh` שמריץ `pip install` על כל הפעלה - הכל בונים לתוך
ה־image, ‏`docker compose up -d` עולה תוך שניות בפעם השנייה.

### 7.5 הרמה ראשונה

```bash
cd deploy
cp .env.example .env      # מלא את TS_BIND ו־N8N_ENCRYPTION_KEY לפחות
docker compose up -d
docker compose logs -f n8n
```

- כתובת ה־UI של n8n: `http://${TS_BIND}:5678` (הביקור הראשון פותח
  אשף יצירת owner account - שמור את פרטי ההתחברות).
- מומלץ מיד: יצירת חשבון owner, ‏import של `n8n_workflows/mvp_triage_email.json`
  דרך ה־UI או ה־CLI (‏`docker compose exec n8n n8n import:workflow --input=/workflows/mvp_triage_email.json`),
  הצמדת credential SMTP לצומת המייל, ואקטיבציה של ה־workflow.

### 7.6 טעינת מודל ל־Ollama (שירות compose)

```bash
# ה־container של ollama עולה עם docker compose up -d; מושכים מודלים לתוכו:
docker exec deploy-ollama-1 ollama pull qwen2.5:3b     # שופט מקומי בפאנל
docker exec deploy-ollama-1 ollama pull granite3.3:2b  # השופט המקומי השני
```

הקונטיינר של ה־worker פונה ל־`http://ollama:11434` - שם השירות ברשת
הפנימית של docker; מה־host עצמו ניגשים דרך `127.0.0.1:11434`.

---

## 8. Dify: פריסה מלאה ב־Docker Compose

### 8.1 קבלת ה־Stack הרשמי

```bash
git clone https://github.com/langgenius/dify.git ../dify
cd ../dify/docker
cp .env.example .env
# ערוך .env: הגדר SECRET_KEY, INIT_PASSWORD, ולעיתים DB פנימי מספיק
docker compose up -d
```

מייצר את השירותים: `api`, `worker`, `web`, `db (postgres)`, `redis`,
`weaviate` (או Qdrant), `sandbox`, `ssrf_proxy`, `nginx`.

**הפעם הראשונה** תיקח 3-10 דקות (משיכת images + מיגרציות DB).

- Web UI: <http://localhost/> (או פורט לפי `.env`).
- API base: `http://localhost/v1` (לשימוש חיצוני), פנימית ל־Compose:
  `http://api:5001/v1`.

### 8.2 הגדרת ה־LLM ב־Dify

לאחר login: **Settings → Model Providers**.

הוספת ספק לפי בחירה:
- **Ollama** - לחיבור ל־Ollama המקומי: base URL `http://host.docker.internal:11434`
  ב־Windows/Mac, או שם השירות ב־Docker אם באותה רשת.
- **OpenAI-compatible** - כל endpoint שנותן פרוטוקול OpenAI (LM Studio /
  llamafile / vLLM / TGI / ספק ענן שתומך בכך).
- ספקים אחרים בעלי SDK רשמי ב־Dify (Gemini, Mistral, DeepSeek וכו').

### 8.3 יצירת Agent App

- **Studio → Create App → Agent**.
- הוסף Knowledge (RAG): העלה את `docs/*.md`, `llm_judge/README.md`,
  `PROMPT_CHANGELOG.md`. Dify יבצע chunking + embedding.
- Tools לדוגמה:
  - **HTTP** - קריאה ל־`ingest_api` (‏`POST http://ingest_api:8766/v1/pcap`)
    להפעלת ניתוח חדש, או ל־n8n webhook להזרמת אירוע נגזר.
  - **Function** - כלי מוגדר משתמש שכותב שורה ל־SQLite של audit.
  - **Web Search** - אם רלוונטי.
- **System Prompt** לדוגמה:

```
You are a network security triage analyst assistant.
You receive JSON verdicts produced by an IsolationForest + DBSCAN + LSTM +
rule-based pipeline over Wireshark captures, and you must:
1) explain each malicious/suspicious verdict in plain Hebrew (or English),
2) cross-reference the evidence against the project's docs,
3) ask for the raw signal blob when the evidence looks weak,
4) never issue block/quarantine actions - only recommendations.
```

### 8.4 שילוב עם n8n

- ב־Dify צור **API Key** ל־App (Settings → API).
- ב־n8n צור **HTTP Request** node ל־
  `POST http://dify-api:5001/v1/chat-messages`
  עם `Authorization: Bearer <API_KEY>` וגוף JSON:

```json
{
  "inputs": { "verdict_json": "{{ $json.verdictBlob }}" },
  "query": "Please review the attached batch and produce an analyst opinion.",
  "response_mode": "blocking",
  "user": "n8n-agent"
}
```

- **חיבור הרשתות**: אפשר לחבר את הרשת של Dify ל־`netsec_ai` באמצעות
  `external: true` ב־compose של n8n או להיפך; פשוט יותר להשאיר
  את שני ה־Stacks נפרדים ולפנות דרך `http://host.docker.internal:80/v1`.

---

## 9. חיבור LLM חינמי או בתשלום

### 9.1 חינמי לחלוטין (offline)

- **Ollama** עם `llama3.2`, `qwen2.5`, `gemma3:4b`, `mistral`,
  `phi3:mini`. פועל CPU-only, איטי אך מעולה לפיילוט. עובד ללא רשת.
- **LM Studio** / **llamafile** / **vLLM** / **Text-Generation-WebUI** -
  כולם חושפים API בפורמט OpenAI-compatible → משתמש באותה
  הגדרת provider.

### 9.2 חינמי דרך ענן (Free-tier / Freemium)

לפי בחירתך - הצטרפות עצמאית, המפתח נשמר ב־`.env` המקומי בלבד:

- ספק Gemini (רבדים חינמיים במגבלות דקה).
- ספקים דוגמת Groq / Together / OpenRouter (חלקם עם מפתחות דמו וחלקם
  עם מודלים חינמיים במגבלה יומית).
- ספקי אירופה/פתוחים דוגמת Mistral או DeepInfra ברמות חינמיות מוגבלות.

**חשוב**: כל הספקים הללו נבחרים דרך `LLM_JUDGE_PROVIDER=openai_compat`
ומשתני `OPENAI_COMPAT_BASE_URL`/`OPENAI_COMPAT_MODEL`/`OPENAI_COMPAT_API_KEY`
בדיוק לפי המנגנון שכבר קיים בפרויקט (`llm_judge/judge_config.py`).

### 9.3 בתשלום (Pay-as-you-go)

- מפתח פרטי לספק, קילומטרז' לפי צריכה. חיבור זהה: `openai_compat`
  עם `BASE_URL` מתאים או SDK רשמי ב־Dify.
- **טיפ עלות**: הפעל LLM חיצוני **רק ב־Judge/Analyst layer**, אחרי
  שהחוקים/ML כבר סיננו את רוב תעבורת הרעש. במדידה הפנימית של הפרויקט,
  PCAP טיפוסי מגיע ל־5-40 מועמדים בלבד ל־LLM, לא אלפים.

### 9.4 בחירת מודל לפי משימה

| משימה | דגם מתאים |
|---|---|
| סיווג קצר (verdict JSON) | מודל קטן/בינוני, טמפרטורה 0 |
| פירוט טקסטואלי בעברית | מודל בינוני-גדול עם תמיכה טובה בעברית |
| דיאלוג בצ'אט עם האנליסט | מודל מיטובי לצ'אט; RAG חובה |
| קריאה אוטומטית לכלים | מודל שתומך ב־Function Calling נאמן |

---

## 10. חשיפת ה־PCAP והפרויקט לסוכן

### 10.1 המנגנון היחיד שנשלח היום

הסוכן (‏n8n או Dify) **אינו** קורא PCAP מדיסק ואינו מריץ `docker exec`.
במקומו הצינור עצמו יוזם את הצעד הבא:

1. הסנסור מעלה PCAP ל־`ingest_api` (‏HMAC + Tailscale) - הצינור
   רץ אוטומטית על ה־worker.
2. עם סיום הצינור, ה־worker שולח POST ל־`N8N_WEBHOOK_URL` עם
   `{session_id, label, kind, sha256, results, worst}` (‏ראו
   `server/worker.py::_notify`).
3. ה־workflow ב־n8n מפעיל לוגיקה על ה־payload (סינון malicious/
   suspicious, שליחת מייל, בקשת RAG מ־Dify, וכו').
4. כאשר צריך את ה־HTML/PDF/JSON המלא, ה־workflow קורא ל־
   `GET /v1/reports/{session_id}.{html|pdf|json|map}` על ה־`ingest_api`
   ‏(‏עם bearer token של החיישן שיצר את הסשן; ראו `server/ingest_api.py`).

### 10.2 הרשאות ובידוד

- `n8n` יושב על אותה רשת פרטית של `deploy/docker-compose.yml`, אז הוא
  ניגש ל־`ingest_api` בשם ה־service (‏`http://ingest_api:8766`) בלי לצאת
  לרשת. אינו רואה את `/srv/netsec` ישירות בכלל.
- `worker` הוא היחיד שכותב ל־`/srv/netsec/reports/` ול־DB. אין `docker
  exec` שיוצא מהסוכן פנימה.
- ‏Bearer tokens נשמרים כ־hash ב־DB; ‏HMAC secrets בשל הגנת המערכת נשמרים
  בפורמט גלוי ומוגנים דרך הרשאות קובץ ה־DB.

### 10.3 שילוב Dify (אופציונלי)

כדי לתת ל־Dify RAG על ה־verdicts, ‏cron ב־n8n מייצא כל `verdicts.md`
חדש ל־Knowledge Base של Dify דרך ה־API שלו. Dify עצמו לא צריך גישה
ישירה ל־PCAP או ל־DB.

---

## 11. תבניות זרימה (Workflows) לדוגמה

### 11.1 Workflow #1 - "Auto-triage of new PCAP"

הצעדים ב־n8n מסתדרים מסביב ל־webhook שה־worker כבר שולח (אין file
trigger, כי הצינור רץ אוטומטית ברגע ש־PCAP מגיע ל־`ingest_api`):

1. **Webhook** על `/webhook/netsec-alert` (מקבל את payload ה־worker).
2. **IF** - אם `body.worst ∈ {malicious, suspicious}`:
   - **HTTP Request** → `GET http://ingest_api:8766/v1/reports/{body.session_id}.md`
     עם ה־bearer token של החיישן, לקבלת הדוח בפורמט Markdown.
   - **HTTP Request** → `POST /v1/chat-messages` של Dify (אופציונלי)
     עם ה־MD המלא ובקשה לסיכום מקוצר בעברית.
   - **Slack / Telegram / Email** - שליחת הסיכום + לינק ל־`report.html`.
   - **GitHub** node - פתיחת Issue אם ה־PCAP הועלה מ־fork ציבורי.
3. **PostgreSQL / SQLite** node אופציונלי לרישום audit
   (`ts, session_id, sha256, worst, results_count`). לפעולות אלה
   ה־worker כבר כותב ל־`sessions/verdicts/candidates` ב־`netsec.db`.
   ה־audit הנוסף רלוונטי רק אם רוצים לשמר לוג נפרד ב־n8n.

### 11.2 Workflow #2 - "Second opinion" (ועדת שופטים)

1. Trigger: Webhook שמקבל את `verdicts.json` הראשוני.
2. **פיצול** לכל מועמד `malicious`.
3. **HTTP Request** → LLM #1 (Ollama מקומי).
4. **HTTP Request** → LLM #2 (ספק ענן).
5. **Merge + Function**: אם השופטים חלוקים, סמן `needs_human_review=true`.
6. **Notify** רק את הפריטים המסומנים לבדיקת אדם.

### 11.3 Workflow #3 - "Chat with the analyst"

בצד Dify:
- Chatflow עם RAG על מסמכי הפרויקט + `verdicts.md` שהוזרמו אליו מ־n8n.
- כלי מובנה שמפעיל את `ingest_api` (‏`POST /v1/pcap`) אם המשתמש שואל
  "רוץ שוב על ה־PCAP האחרון" - זהה למסלול העלאה רגיל.
- Memory לשיחה שנשמר ב־Postgres של Dify.

### 11.4 Workflow #4 - "Threat Intel enrichment"

לפני שהסוכן פוסק:
- קריאת WHOIS/rDNS ל־IP.
- שאילתות ל־GeoIP חינמי (MaxMind GeoLite2 קונטיינר).
- ASN lookup.
- מיזוג הכל עם ה־JSON המקורי לפני שליחה ל־LLM.

**חשוב**: אל תפרסם אף מפתח או PCAP רגיש לרשתות ציבוריות.
כל שירות הרישום צריך להיות תחת domain שבבעלותך, לא לספק חיצוני.

---

## 12. תבניות סוכן אוטונומי (Agentic Patterns)

### 12.1 Router Agent

- סוכן שמקבל בקשה חופשית ומחליט איזה sub-flow להפעיל
  ("ניתוח PCAP" / "שאלה על הפרויקט" / "רצף אירועים").

### 12.2 ReAct Agent

- Reason → Act → Observe.
- כלים: `run_judge`, `whois`, `geoip`, `read_docs`, `write_ticket`.
- מסיים כשמגיע ל־`final_answer` או ל־תקרת צעדים
  (מומלץ: ≤ 6 צעדים / batch).

### 12.3 Multi-Agent (Debate / Committee)

- **Analyst-A**: מודל קטן ומהיר (Ollama) - מספק דעה ראשונה.
- **Analyst-B**: מודל בינוני/גדול - בודק את דעת A.
- **Judge**: מודל שלישי או אותו מודל בתפקיד "ראש צוות".
- כלל החלטה: רוב פשוט; במקרה של תיקו - הפניה לאדם.

### 12.4 Loop-until-quiet

- סוכן פועל בלולאה על תור מועמדים; יוצא רק אם N סבבים רצופים
  לא הפיקו מועמד חדש.

### 12.5 Guardrails (חובה)

- **Rule guardrail** - כבר קיים בפרויקט:
  אם חוק דטרמיניסטי נפל, `benign` נחסם. אין לבטל.
- **Rate limit** - n8n `Wait` + Dify concurrency limit.
- **Timeouts** - פר קריאה: 60-300 שנ' בהתאם למודל.
- **Cost cap** - n8n `IF` שסופר קריאות ליום ושובר את השרשרת.

---

## 13. אבטחת מידע, סודות ו־Hardening

### 13.1 סודות

- שום מפתח לא נכתב לקוד או ל־compose.
- כל המפתחות ב־`.env`; קובץ זה נמצא ב־`.gitignore`.
- ב־Dify: Model Provider keys נשמרים ב־Postgres שלו - הגדר גיבוי
  מוצפן; אל תעביר את ה־volume כמו שהוא.
- ב־n8n: Credentials מוצפנים עם `N8N_ENCRYPTION_KEY` - אבד = איבוד
  קרדנציאלים.

### 13.2 רשת

- הימנע מלחשוף פורטים החוצה למעט המינימום ההכרחי
  (`5678` ל־n8n, `80` ל־Dify).
- שים Reverse Proxy (Caddy / Nginx / Traefik) עם TLS ומגן BasicAuth
  אם רוצים לגשת מבחוץ.
- **אל תחשוף** את `ingest_api`, את `postgres` של Dify או את `ollama`
  לאינטרנט. הפרויקט קובע Tailscale-only כברירת מחדל (‏decision IDX-08).
- אם משתמשים ב־ngrok/Cloudflare Tunnel, הגדר Access Rules לפחות
  ברמת email/OAuth.

### 13.3 נתונים

- PCAPs עשויים להכיל מידע רגיש. תכנן את מדיניות שמירה:
  מחיקה אוטומטית מ־`incoming/` אחרי X ימים, מחיקת verdicts ישנים,
  אנונימיזציה של IPים בפלט לרשתות פנימיות.
- אם משתמשים ב־LLM ענני, שקול "PII redaction" לפני שליחה
  (`ipaddress` מספריה למחיקת מזהי המשתמש/מארח).

### 13.4 Container Hardening

- הגדר `read_only: true` היכן שאפשר.
- `cap_drop: [ALL]` והוסף רק Capabilities נחוצים.
- הרץ עם `user:` שאינו root כשיש תמיכה (n8n מריץ node כברירת מחדל).
- עדכן images תקופתית: `docker compose pull && docker compose up -d`.

### 13.5 גיבוי

- `n8n_data`, `ollama_data`, `dify_postgres` - לגבות תקופתית
  (rsync/borg). אחסון מחוץ למכונה.
- workflows של n8n גם ניתנים ליצוא כ־JSON וגם לגבותם ב־git פרטי
  (לא בפרויקט הפומבי הזה).

---

## 14. ניטור, לוגים ודיאגנוסטיקה

### 14.1 לוגים בסיסיים

```bash
docker compose logs -f n8n
docker compose logs -f ingest_api
docker compose logs -f worker
docker compose logs -f retention
# Ollama רץ כשירות compose (deploy-ollama-1):
docker compose logs -f ollama
# Dify (אם מותקן בנפרד):
docker compose -f ../dify/docker/docker-compose.yaml logs -f dify-api dify-worker
```

### 14.2 מדדים

- זמן ריצה של `judge_cli.py` פר PCAP - נמדד כבר בפרויקט; שמור
  ב־SQLite לצד ה־verdict.
- דיוק (Cohen's kappa) - כבר קיים; הרץ מחדש אחרי החלפת מודל
  (`llm_judge/calibration.py`).
- שיעור override של ה־guardrail - סימן שהמודל נבחר לא מתאים.

### 14.3 התראות

- `docker events` + Prometheus + Grafana לתפעול אמיתי.
- לפיילוט, מספיק חוקי n8n שסופרים כשלונות רצופים ומודיעים.

---

## 15. עלויות ותקציב מעשי

- **חינם לחלוטין**: n8n Community + Dify Community + Ollama מקומי.
  עלות = חשמל + חומרה שיש לך.
- **חינם ב־Cloud**: GitHub Actions ממשיך לתת אפס עלות ל־forks ציבוריים
  (‏ה־workflow הישן `analyze-pcap.yml` הוצא משימוש - כיום נשאר רק `ci.yml`).
- **ספק LLM חיצוני**: הפעל אותו רק על שלב ה־Analyst (5-40 קריאות
  ל־PCAP). Cache SQLite שמובנה ב־Judge → הרצות חוזרות = חינם.
- **טיפ עלות**: כפה `LLM_JUDGE_MAX_CANDIDATES=40` (ברירת מחדל)
  והפעל `RULE_GUARDRAIL=1` - מונע קריאות מיותרות.

---

## 16. Checklist להשקה - מה חייב להיות מוכן

- [ ] Docker + Compose מותקנים ורצים (`docker run hello-world`).
- [ ] `deploy/.env` מלא (`TS_BIND` = ה־IP של Tailscale, `N8N_ENCRYPTION_KEY`
      ייחודי; לא ברירת מחדל).
- [ ] `.gitignore` כולל `deploy/.env`, `llm_judge/cache/`,
      `llm_judge/output/`, ‏`dify/docker/volumes/`.
- [ ] Ollama רץ על ה־host, מודל אחד לפחות נמשך (`ollama pull qwen2.5:14b`).
- [ ] `docker compose up -d` ב־`deploy/` הפעיל את 4 השירותים
      (n8n, ingest_api, worker, retention).
- [ ] `curl -s http://${TS_BIND}:8766/healthz` מחזיר
      `{"status":"ok","schema":<n>}`.
- [ ] n8n עולה ב־`http://${TS_BIND}:5678`, יצרת owner account.
- [ ] ‏`n8n_workflows/mvp_triage_email.json` יובא ומופעל; ‏credential
      SMTP מצומד לצומת המייל; ‏`N8N_WEBHOOK_URL` ב־`.env` מצביע ל־
      Production URL של ה־Webhook, ו־`docker compose restart worker`
      רוענן את ה־worker.
- [ ] `python deploy/create_sensor.py <שם>` הריץ בהצלחה והדפיס
      את ה־credentials פעם אחת; שמרת אותם בסביבת החיישן.
- [ ] העלאת PCAP לדוגמה מסנסור אמיתי:
      `python3 tools/upload_pcap.py capture.pcapng` מחזירה
      `session_id`, ו־`GET /v1/sessions/{id}` מגיע ל־`status:"done"`
      עם `verdicts.json`/`.md`/`report.html` בדיסק.
- [ ] Dify (אופציונלי) עלה, App מסוג Agent הוגדר, RAG טעון עם
      `docs/*.md`.
- [ ] מפתחות ספק LLM (אם רלוונטי) נשמרים רק ב־`deploy/.env`, לא בגיט.
- [ ] Backup ל־`${NETSEC_DATA_ROOT}/db/` ול־`n8n_data` volume הוגדר.
- [ ] Notifications (Slack / Telegram / Email / GitHub) נבדקו קצה לקצה.
- [ ] קליברציה: הרצה של הנוטבוק `llm_judge/LLM_Judge_Notebook.ipynb`
      בסקציית ה־calibration (או שימוש ב־`llm_judge/calibration.py`
      מתוך קוד) עברה עם `kappa ≥ LLM_JUDGE_KAPPA_THRESHOLD` (ברירת
      מחדל 0.60).

---

## 17. שאלות נפוצות ותקלות מוכרות

### 17.1 "n8n לא מקבל אירוע webhook"

- ודא שה־workflow פעיל (Active מלמעלה-ימין) ושה־Webhook הוא מסוג
  Production, לא Test - ה־Test URL תקף לביקור ידני יחיד ואז נעלם.
- ודא ש־`N8N_WEBHOOK_URL` ב־`deploy/.env` מצביע לאותה כתובת של
  ה־Webhook, ושה־worker רוענן (`docker compose restart worker`).
- בדוק דרך `docker compose logs -f worker` שהוא באמת עושה POST ולא
  זורק חריגה.

### 17.2 "Ollama מחזיר timeout"

- הגדל `LLM_JUDGE_TIMEOUT_S=600` ב־`deploy/.env` (ברירת מחדל 300).
- ודא שהמודל **נמשך** (`ollama pull`) - הפעם הראשונה מורידה גיגה־בייטים.
- למחשב חלש: החלף ל־`gemma3:4b` או `phi4:14b` (הפחות תלוי-חומרה).
- ב־Docker Compose ה־worker פונה ל־`http://ollama:11434` (DNS פנימי של
  docker). בדוק שהשירות למעלה (`docker compose up -d ollama`) ושהמודל
  נמשך: `docker exec deploy-ollama-1 ollama pull qwen2.5:3b`.

### 17.3 "Dify לא מוצא את Ollama"

- ב־Windows/Mac: השתמש ב־`http://host.docker.internal:11434`.
- ב־Linux: או חבר את הרשתות (`external: true`) או השתמש בכתובת ה־IP של host.
- בדוק ש־Ollama מאזין על `0.0.0.0`: `OLLAMA_HOST=0.0.0.0:11434`.

### 17.4 "ה־LLM ממציא ראיות"

- ודא ש־RAG פעיל, וה־retriever מחזיר snippets מהמסמכים.
- הפעל את ה־guardrail (`LLM_JUDGE_RULE_GUARDRAIL=1`).
- הפחת temperature, בקש schema-strict.
- שקול מודל בינוני-גדול יותר לשלב ה־Analyst.

### 17.5 "אין דיסק"

- הגבל volumes ל־Ollama (מודלים גדולים תופסים 10-40GB כל אחד).
- נקה: `docker system prune -a`, `ollama rm <model>`.

### 17.6 "n8n נתקע אחרי restart"

- לרוב מפתח הצפנה שונה. שמור את `N8N_ENCRYPTION_KEY` - אין דרך לשחזר
  credentials בלעדיו.

---

## 18. מפת דרכים להמשך

שלבים המוצעים ליישום, מסודרים לפי סדר. שלבים 1-3 כבר יצאו לפועל
בגרסה הנוכחית של הפרויקט; שלבים 4-8 עדיין לפניכם.

1. ✅ **פיילוט מקומי** - `deploy/` על VM (Oracle Always Free ARM
   או כל Ubuntu 22.04+) עם n8n + `ingest_api` + `worker` + `retention`,
   Ollama על ה־host, workflow אחד (`mvp_triage_email.json`) שנשלח
   בריפו.
2. ✅ **פאנל שופטים הטרוגני** (‏במקום הקומיטה הישנה של שני שופטים):
   Groq + Gemini + Ollama, ‏panel debate עם צד fail-safe והצבעה
   ל־human review. מיושם ב־`llm_judge/judge_core.judge_candidates_panel`.
3. ✅ **חיבור OSINT** (‏Wigle + Shodan) - stage YA, ‏`W_TI` מופעל וה־
   priority score משוקלל מחדש.
4. **חיבור Dify** (‏אופציונלי) - הוספת Agent עם RAG על המסמכים.
5. **Threat-Intel Enrichment נוסף** - WHOIS / GeoIP / ASN לפני החלטה
   על מועמדים חיצוניים.
6. **התראות מובנות** - Slack / Telegram חיבורים מובנים ב־n8n מעבר
   ל־Email.
7. **Observability** - Prometheus/Grafana לצד המדדים של הפרויקט.
8. **Multi-tenant** - הפרדת נתיבים לפי משתמש/ארגון, סודות לפי משתמש.
9. **הרחבת CI Gate** - `tests/test_judge_kappa_regression.py` שיריץ
   גם את הזרימה החדשה על PCAP סינטטי כחלק מ־regression.

---

**המסמך הזה הוא המסגרת. כל מה שמפורט בו ניתן ליישום מיידי מעל
הפרויקט הקיים בלי לגעת בשורת קוד מקורית - כל האינטגרציה היא
"בצד" של הפרויקט: קבצי פלט, API עטיפה ומשתני סביבה שהוגדרו
כבר בפרויקט**.
