# סוכני AI אוטונומיים כאנליסטים — n8n / Dify על גבי Docker

> מסמך אפיון מלא בעברית, מותאם לפרויקט
> **NetSec-Dashboard-Wireshark-Unsupervised-Anomaly-Detection**.
> נכתב כדי לתת תמונה מקצה-לקצה: מה נדרש, איך מתכננים, איך בונים ואיך מפעילים
> סוכן/י AI אוטומטיים שמנתחים את פלטי ה־Dashboard וה־LLM Judge בזמן אמת.

---

## תוכן עניינים

1. [רקע: איפה נכנסים הסוכנים בפרויקט](#1-רקע-איפה-נכנסים-הסוכנים-בפרויקט)
2. [למה Docker דווקא, ולמה n8n או Dify](#2-למה-docker-דווקא-ולמה-n8n-או-dify)
3. [n8n מול Dify — השוואה מעשית](#3-n8n-מול-dify--השוואה-מעשית)
4. [דרישות תשתית ומערכת](#4-דרישות-תשתית-ומערכת)
5. [ארכיטקטורת יעד: זרימת מידע מקצה-לקצה](#5-ארכיטקטורת-יעד-זרימת-מידע-מקצה-לקצה)
6. [התקנת Docker Desktop / Engine — מדריך פרקטי](#6-התקנת-docker-desktop--engine--מדריך-פרקטי)
7. [n8n: פריסה מלאה ב־Docker Compose](#7-n8n-פריסה-מלאה-ב־docker-compose)
8. [Dify: פריסה מלאה ב־Docker Compose](#8-dify-פריסה-מלאה-ב־docker-compose)
9. [חיבור LLM חינמי או בתשלום](#9-חיבור-llm-חינמי-או-בתשלום)
10. [חשיפת ה־PCAP והפרויקט לסוכן](#10-חשיפת-ה־pcap-והפרויקט-לסוכן)
11. [תבניות זרימה (Workflows) לדוגמה](#11-תבניות-זרימה-workflows-לדוגמה)
12. [תבניות סוכן אוטונומי (Agentic Patterns)](#12-תבניות-סוכן-אוטונומי-agentic-patterns)
13. [אבטחת מידע, סודות ו־Hardening](#13-אבטחת-מידע-סודות-ו־hardening)
14. [ניטור, לוגים ודיאגנוסטיקה](#14-ניטור-לוגים-ודיאגנוסטיקה)
15. [עלויות ותקציב מעשי](#15-עלויות-ותקציב-מעשי)
16. [Checklist להשקה — מה חייב להיות מוכן](#16-checklist-להשקה--מה-חייב-להיות-מוכן)
17. [שאלות נפוצות ותקלות מוכרות](#17-שאלות-נפוצות-ותקלות-מוכרות)
18. [מפת דרכים להמשך](#18-מפת-דרכים-להמשך)

---

## 1. רקע: איפה נכנסים הסוכנים בפרויקט

הפרויקט כולל שני מסלולי ניתוח קיימים:

1. **Dashboard מקומי** — נוטבוק Jupyter/Dash שמריץ במקביל
   `IsolationForest`, `DBSCAN`, `LSTM` וגם שכבת חוקים דטרמיניסטיים על
   קובצי PCAPNG (או הקלטה חיה דרך `tshark`), ומפיק כ־9 מסכי ניתוח.
2. **LLM Judge** — תוסף עצמאי תחת `llm_judge/` שממזג את כלל הסיגנלים
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

הכל בלי לגעת בקוד הליבה של הפרויקט — הכל דרך **קבצי הפלט** (`verdicts.json`,
`verdicts.md`, לוגים) ו/או **HTTP webhooks** שנוסיף.

---

## 2. למה Docker דווקא, ולמה n8n או Dify

### למה Docker

- **בידוד מלא**: כלים כמו n8n או Dify דורשים Node, Python, Redis,
  Postgres, OpenSearch/Weaviate ועוד — התקנה מקומית "טבעית" תשבור לך את
  סביבת הפרויקט. Container מבודד כל אלה.
- **שחזוריות**: קובץ `docker-compose.yml` יחיד מגדיר את *כל* הפריסה.
  לעבור למכונה חדשה = `docker compose up -d`.
- **Volumes**: הסוכן צריך גישה לתיקיות PCAP, `incoming/`, `llm_judge/output/`.
  ב־Docker זה שורה אחת של `volumes:` — בלי להתקין לו Python.
- **רשת פנימית**: כל השירותים מתקשרים דרך רשת Compose סגורה,
  והחוצה חשופה רק פורטת ה־UI (`5678` ל־n8n, `80` ל־Dify).
- **גיבוי וניקוי**: `docker compose down -v` מנקה הכל; `docker compose
  down` שומר על ה־volumes וההגדרות.
- **תמיכה ב־Windows / Mac / Linux** דרך Docker Desktop או Docker Engine —
  זהה בכולם.

### למה n8n או Dify (ולא Zapier / Make / קוד ידני)

| נושא | n8n | Dify | קוד ידני |
|---|---|---|---|
| Self-hosted חינמי | כן (Community) | כן (Community) | כן |
| ממשק גרפי לזרימות | Node graph — עוצמתי מאוד | Node graph + Chatflow/Agent | אין |
| תמיכה מובנית ב־LLM | מספר nodes ל־LLM | ליבת המוצר — LLMs, RAG, Tools, Agents | מה שתכתוב |
| ניהול Prompts | קיים אבל בסיסי | מרכזי, עם גרסאות, טסטים ומדדים | מה שתכתוב |
| RAG / Knowledge base | דרך integrations | מובנה כליבת מוצר | מה שתכתוב |
| Cron / Webhook / Files | חזק מאוד | דרך API + כלים חיצוניים | מה שתכתוב |
| קימום זמן | דקות | דקות | ימים |
| מטרה טבעית | Automation Engine | AI Platform / AI-native app | תלוי |

**המלצה בפרויקט הזה**:

- אם המטרה היא **תזמור** — לצפות ב־`incoming/`, להריץ את ה־CLI של
  ה־Judge, לפרסר את ה־JSON, לשלוח Slack/Email, לפתוח Issue — **n8n**.
- אם המטרה היא **בניית סוכן חכם** עם RAG על המסמכים של הפרויקט,
  זיכרון שיחה, מספר Tools מובנים ו־UI לצ'אט עם האנליסט־AI — **Dify**.
- **הכי חזק**: להריץ את שניהם. n8n ידחוף אירועים; Dify יספק את המוח.

---

## 3. n8n מול Dify — השוואה מעשית

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
| RAM | 2 GB | 6 GB | 16 GB (מודלים 7B–8B) / 32 GB (13B+) |
| דיסק | 5 GB | 20 GB | 60+ GB (מודלים) |
| GPU | לא חובה | לא חובה | מומלץ מאוד למודלים גדולים |

### 4.2 תוכנה חובה

- **Docker Desktop** ל־Windows/Mac או **Docker Engine + Compose plugin**
  ל־Linux (גרסה 24+).
- `docker compose` (V2, בפקודה אחת עם רווח — לא `docker-compose`).
- Git.
- **Wireshark / tshark** — כבר קיים בפרויקט; לא נדרש בתוך ה־container
  של ה־AI Platform, רק בסביבה שמייצרת את ה־PCAP.

### 4.3 תוכנה מומלצת

- **Ollama** — להרצת LLM מקומיים חינם (כבר משמש אצלך ב־GitHub Actions
  עם `llama3.2`). ניתן להריץ גם כ־container.
- **ngrok / Cloudflare Tunnel** — אם רוצים לחשוף Webhook החוצה מבלי
  לפתוח פורט בראוטר.
- **מפתחות API** לפי הבחירה שלך (Gemini, Groq, OpenAI-compatible וכו').
  כפי שנעשה ב־`llm_judge/`: מפתחות **לא נשמרים בגיט**, רק
  ב־`.env` המקומי.

---

## 5. ארכיטקטורת יעד: זרימת מידע מקצה-לקצה

```
┌─────────────────────────────────────────────────────────────────────┐
│                       Host (Windows / Linux)                        │
│                                                                     │
│   Wireshark / tshark ── captures ──► ./incoming/*.pcapng            │
│                                                                     │
│   ┌─────────────────  Docker network: netsec_ai  ──────────────┐   │
│   │                                                              │   │
│   │   [n8n]   ──file trigger──►  [judge_runner]                  │   │
│   │     │                        (mini python container          │   │
│   │     │                         שמריץ judge_cli.py)            │   │
│   │     │                                                        │   │
│   │     ├──HTTP──► [Dify API]  ──► [Dify Agent + RAG + Tools]    │   │
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
│   פלטים: ./llm_judge/output/verdicts.json / verdicts.md             │
│           ./automation/db/audit.sqlite                              │
│           GitHub Issue / Slack / Telegram / Email                   │
└─────────────────────────────────────────────────────────────────────┘
```

**נקודות עיקריות**:

- Wireshark ממשיך לפעול כרגיל ב־Host.
- שירות אחד בלבד קורא מ־`incoming/` — n8n (עם `Local File Trigger`).
- ה־Judge רץ בקונטיינר משלו כדי לא לזהם את סביבת ה־Dashboard.
- Dify רץ כ־Stack משלו (מספר containers) — Postgres שלו לא מוגש
  ל־n8n.
- ה־LLM נבחר לפי משתנה סביבה, לא לפי קוד — בדיוק כמו בפרויקט הנוכחי.

---

## 6. התקנת Docker Desktop / Engine — מדריך פרקטי

### 6.1 Windows

1. הורדה: <https://docs.docker.com/desktop/install/windows-install/>
2. חובה להפעיל **WSL2** (`wsl --install`) ולוודא שהמערכת עדכנית.
3. אחרי התקנה: `docker --version` ו־`docker compose version`.
4. מומלץ להגדיר ב־Docker Desktop → Settings → Resources:
   - CPU: 4+
   - RAM: 8–16 GB
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

```
NetSec-Dashboard-Wireshark-Unsupervised-Anomaly-Detection/
├─ ... (הפרויקט הקיים)
└─ automation/
   ├─ .env                       ← לא ב־git (יש להוסיף ל־.gitignore)
   ├─ docker-compose.yml
   ├─ n8n_data/                  ← volume ל־n8n
   ├─ judge_runner/
   │   ├─ Dockerfile
   │   └─ entrypoint.sh
   └─ db/
       └─ audit.sqlite           ← נוצר בזמן ריצה
```

### 7.2 קובץ `.env`

```dotenv
# n8n
N8N_BASIC_AUTH_USER=admin
N8N_BASIC_AUTH_PASSWORD=CHANGE_ME_STRONG_PASSWORD
N8N_ENCRYPTION_KEY=CHANGE_ME_32_CHAR_RANDOM_STRING
N8N_HOST=localhost
N8N_PORT=5678
TZ=Asia/Jerusalem

# LLM providers (בחר את מה שרלוונטי לך)
LLM_JUDGE_PROVIDER=ollama            # ollama | openai_compat | ...
OLLAMA_HOST=http://ollama:11434
OLLAMA_MODEL=llama3.2
OPENAI_COMPAT_BASE_URL=
OPENAI_COMPAT_MODEL=
OPENAI_COMPAT_API_KEY=

# Dify (אופציונלי, לשילוב hybrid)
DIFY_API_BASE=http://dify-api/v1
DIFY_API_KEY=
```

### 7.3 `docker-compose.yml` — סטאק בסיסי (n8n + Ollama + judge runner)

```yaml
name: netsec-ai

networks:
  netsec_ai:
    driver: bridge

volumes:
  n8n_data:
  ollama_data:

services:
  n8n:
    image: n8nio/n8n:latest
    restart: unless-stopped
    ports:
      - "5678:5678"
    environment:
      - N8N_BASIC_AUTH_ACTIVE=true
      - N8N_BASIC_AUTH_USER=${N8N_BASIC_AUTH_USER}
      - N8N_BASIC_AUTH_PASSWORD=${N8N_BASIC_AUTH_PASSWORD}
      - N8N_ENCRYPTION_KEY=${N8N_ENCRYPTION_KEY}
      - N8N_HOST=${N8N_HOST}
      - N8N_PORT=${N8N_PORT}
      - GENERIC_TIMEZONE=${TZ}
      - TZ=${TZ}
    volumes:
      - n8n_data:/home/node/.n8n
      # חשיפת תיקיות הפרויקט לצורך trigger וקריאת פלטים
      - ../incoming:/data/incoming:ro
      - ../llm_judge/output:/data/output:rw
      - ./db:/data/db:rw
    networks: [netsec_ai]

  ollama:
    image: ollama/ollama:latest
    restart: unless-stopped
    volumes:
      - ollama_data:/root/.ollama
    ports:
      - "11434:11434"          # אפשר להסיר לחשיפה פנימית בלבד
    networks: [netsec_ai]
    # ל־GPU:
    # deploy:
    #   resources:
    #     reservations:
    #       devices:
    #         - capabilities: [gpu]

  judge_runner:
    build:
      context: ./judge_runner
    image: netsec/judge-runner:latest
    restart: "no"              # מופעל on-demand על ידי n8n
    environment:
      - LLM_JUDGE_PROVIDER=${LLM_JUDGE_PROVIDER}
      - OLLAMA_HOST=${OLLAMA_HOST}
      - OLLAMA_MODEL=${OLLAMA_MODEL}
      - OPENAI_COMPAT_BASE_URL=${OPENAI_COMPAT_BASE_URL}
      - OPENAI_COMPAT_MODEL=${OPENAI_COMPAT_MODEL}
      - OPENAI_COMPAT_API_KEY=${OPENAI_COMPAT_API_KEY}
    volumes:
      - ../:/workspace:rw       # כל הפרויקט (ל־judge_cli.py + PCAPs)
    networks: [netsec_ai]
    entrypoint: ["sleep", "infinity"]  # להשאיר בחיים כדי ש־n8n יריץ docker exec
```

### 7.4 `automation/judge_runner/Dockerfile`

```dockerfile
FROM python:3.11-slim

# tshark ומינימום כלים
RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    ca-certificates \
    curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# יותקן בזמן build פעם אחת; מוצג רק כדוגמה
# ההתקנה תרוץ ב־entrypoint אם תרצה, כדי לתפוס עדכונים ל־requirements
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
```

`entrypoint.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
cd /workspace
pip install --no-cache-dir -r requirements.txt
pip install --no-cache-dir -r llm_judge/requirements.txt || true
# n8n יבצע docker exec לפקודה בפועל; כאן נשארים בחיים
exec "$@"
```

### 7.5 הרמה ראשונה

```bash
cd automation
docker compose up -d
docker compose logs -f n8n
```

- כתובת ה־UI: <http://localhost:5678>
- מומלץ מיד: פתיחת workflow חדש, שמירת credentials, יצוא תקופתי של
  ה־workflows (זמין ב־Settings → Import/Export).

### 7.6 טעינת מודל ל־Ollama

```bash
docker exec -it netsec-ai-ollama-1 ollama pull llama3.2
docker exec -it netsec-ai-ollama-1 ollama pull qwen2.5:7b     # אלטרנטיבה
docker exec -it netsec-ai-ollama-1 ollama pull gemma3:4b      # קטן ומהיר
```

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

**הפעם הראשונה** תיקח 3–10 דקות (משיכת images + מיגרציות DB).

- Web UI: <http://localhost/> (או פורט לפי `.env`).
- API base: `http://localhost/v1` (לשימוש חיצוני), פנימית ל־Compose:
  `http://api:5001/v1`.

### 8.2 הגדרת ה־LLM ב־Dify

לאחר login: **Settings → Model Providers**.

הוספת ספק לפי בחירה:
- **Ollama** — לחיבור ל־Ollama המקומי: base URL `http://host.docker.internal:11434`
  ב־Windows/Mac, או שם השירות ב־Docker אם באותה רשת.
- **OpenAI-compatible** — כל endpoint שנותן פרוטוקול OpenAI (LM Studio /
  llamafile / vLLM / TGI / ספק ענן שתומך בכך).
- ספקים אחרים בעלי SDK רשמי ב־Dify (Gemini, Mistral, DeepSeek וכו').

### 8.3 יצירת Agent App

- **Studio → Create App → Agent**.
- הוסף Knowledge (RAG): העלה את `docs/*.md`, `llm_judge/README.md`,
  `PROMPT_CHANGELOG.md`. Dify יבצע chunking + embedding.
- Tools לדוגמה:
  - **HTTP** — קריאה ל־`judge_runner` דרך n8n webhook, או ישירות
    לשירות Python חשוף.
  - **Function** — כלי מוגדר משתמש שכותב שורה ל־SQLite של audit.
  - **Web Search** — אם רלוונטי.
- **System Prompt** לדוגמה:

```
You are a network security triage analyst assistant.
You receive JSON verdicts produced by an IsolationForest + DBSCAN + LSTM +
rule-based pipeline over Wireshark captures, and you must:
1) explain each malicious/suspicious verdict in plain Hebrew (or English),
2) cross-reference the evidence against the project's docs,
3) ask for the raw signal blob when the evidence looks weak,
4) never issue block/quarantine actions – only recommendations.
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
- **LM Studio** / **llamafile** / **vLLM** / **Text-Generation-WebUI** —
  כולם חושפים API בפורמט OpenAI-compatible → משתמש באותה
  הגדרת provider.

### 9.2 חינמי דרך ענן (Free-tier / Freemium)

לפי בחירתך — הצטרפות עצמאית, המפתח נשמר ב־`.env` המקומי בלבד:

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
  PCAP טיפוסי מגיע ל־5–40 מועמדים בלבד ל־LLM, לא אלפים.

### 9.4 בחירת מודל לפי משימה

| משימה | דגם מתאים |
|---|---|
| סיווג קצר (verdict JSON) | מודל קטן/בינוני, טמפרטורה 0 |
| פירוט טקסטואלי בעברית | מודל בינוני-גדול עם תמיכה טובה בעברית |
| דיאלוג בצ'אט עם האנליסט | מודל מיטובי לצ'אט; RAG חובה |
| קריאה אוטומטית לכלים | מודל שתומך ב־Function Calling נאמן |

---

## 10. חשיפת ה־PCAP והפרויקט לסוכן

### 10.1 גישות מומלצות

1. **Read-only mount** — ה־container של n8n רואה `incoming/` ב־`ro`
   (קריאה בלבד). כתיבה רק ל־`llm_judge/output/` ול־`db/`.
2. **API עטיפה** — הרם שירות Flask/FastAPI קטן ("judge_api") שנחשף רק
   בתוך רשת ה־Compose. הסוכן קורא לו במקום להריץ `docker exec`.
3. **File watcher בתוך container** — אלטרנטיבה ל־n8n Local File
   Trigger: script שרץ בתוך `judge_runner` וקורא ל־webhook של n8n.

### 10.2 דוגמת עטיפת API (אופציונלית)

```python
# automation/judge_api/app.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import subprocess, json, os, tempfile

app = FastAPI()

class Job(BaseModel):
    pcap_path: str        # תוך /workspace/incoming/
    provider: str | None = None
    model: str | None = None

@app.post("/analyze")
def analyze(job: Job):
    env = os.environ.copy()
    if job.provider: env["LLM_JUDGE_PROVIDER"] = job.provider
    if job.model:    env["LLM_JUDGE_MODEL"]    = job.model

    out_json = tempfile.NamedTemporaryFile(delete=False, suffix=".json").name
    out_md   = tempfile.NamedTemporaryFile(delete=False, suffix=".md").name
    cmd = [
        "python", "llm_judge/judge_cli.py", job.pcap_path,
        "--output", out_json, "--markdown", out_md,
    ]
    r = subprocess.run(cmd, cwd="/workspace", env=env,
                       capture_output=True, text=True, timeout=1800)
    if r.returncode != 0:
        raise HTTPException(500, f"judge_cli failed: {r.stderr[:500]}")
    with open(out_json) as f: verdict = json.load(f)
    with open(out_md) as f: md = f.read()
    return {"verdict": verdict, "report_md": md}
```

הוספה ל־compose:

```yaml
  judge_api:
    build:
      context: ./judge_runner
    working_dir: /workspace
    volumes:
      - ../:/workspace:rw
    environment:
      - LLM_JUDGE_PROVIDER=${LLM_JUDGE_PROVIDER}
      - OLLAMA_HOST=${OLLAMA_HOST}
      - OLLAMA_MODEL=${OLLAMA_MODEL}
    command: >
      bash -lc "pip install fastapi uvicorn && \
                uvicorn automation.judge_api.app:app --host 0.0.0.0 --port 8000"
    networks: [netsec_ai]
    # לא חושפים ל־host — רק ברשת הפנימית
```

מכאן, n8n או Dify Tool פונים ל־`http://judge_api:8000/analyze`.

---

## 11. תבניות זרימה (Workflows) לדוגמה

### 11.1 Workflow #1 — "Auto-triage of new PCAP"

צעדים ב־n8n:

1. **Local File Trigger** על `/data/incoming` בפילטר `*.pcap*`.
2. **Function** — מוציא את שם הקובץ ואת המסלול המלא בתוך הקונטיינר.
3. **HTTP Request** → `POST http://judge_api:8000/analyze` עם המסלול.
4. **IF** — אם `stats.malicious + stats.suspicious > 0`:
   - **HTTP Request** → `POST /v1/chat-messages` של Dify עם ה־JSON
     המלא ובקשה לסיכום מקוצר בעברית.
   - **Slack / Telegram / Email** — שליחת הסיכום + לינק לקובץ ה־MD.
   - **GitHub** node — פתיחת Issue אם ה־PCAP הועלה מ־fork ציבורי.
5. תמיד: **SQLite** node שכותב שורת audit
   (`ts, pcap, provider, model, verdict_counts, hash`).

### 11.2 Workflow #2 — "Second opinion" (ועדת שופטים)

1. Trigger: Webhook שמקבל את `verdicts.json` הראשוני.
2. **פיצול** לכל מועמד `malicious`.
3. **HTTP Request** → LLM #1 (Ollama מקומי).
4. **HTTP Request** → LLM #2 (ספק ענן).
5. **Merge + Function**: אם השופטים חלוקים, סמן `needs_human_review=true`.
6. **Notify** רק את הפריטים המסומנים לבדיקת אדם.

### 11.3 Workflow #3 — "Chat with the analyst"

בצד Dify:
- Chatflow עם RAG על מסמכי הפרויקט.
- כלי מובנה שמפעיל את `judge_api` אם המשתמש שואל
  "רוץ שוב על ה־PCAP האחרון".
- Memory לשיחה שנשמר ב־Postgres של Dify.

### 11.4 Workflow #4 — "Threat Intel enrichment"

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

- **Analyst-A**: מודל קטן ומהיר (Ollama) — מספק דעה ראשונה.
- **Analyst-B**: מודל בינוני/גדול — בודק את דעת A.
- **Judge**: מודל שלישי או אותו מודל בתפקיד "ראש צוות".
- כלל החלטה: רוב פשוט; במקרה של תיקו — הפניה לאדם.

### 12.4 Loop-until-quiet

- סוכן פועל בלולאה על תור מועמדים; יוצא רק אם N סבבים רצופים
  לא הפיקו מועמד חדש.

### 12.5 Guardrails (חובה)

- **Rule guardrail** — כבר קיים בפרויקט:
  אם חוק דטרמיניסטי נפל, `benign` נחסם. אין לבטל.
- **Rate limit** — n8n `Wait` + Dify concurrency limit.
- **Timeouts** — פר קריאה: 60–300 שנ' בהתאם למודל.
- **Cost cap** — n8n `IF` שסופר קריאות ליום ושובר את השרשרת.

---

## 13. אבטחת מידע, סודות ו־Hardening

### 13.1 סודות

- שום מפתח לא נכתב לקוד או ל־compose.
- כל המפתחות ב־`.env`; קובץ זה נמצא ב־`.gitignore`.
- ב־Dify: Model Provider keys נשמרים ב־Postgres שלו — הגדר גיבוי
  מוצפן; אל תעביר את ה־volume כמו שהוא.
- ב־n8n: Credentials מוצפנים עם `N8N_ENCRYPTION_KEY` — אבד = איבוד
  קרדנציאלים.

### 13.2 רשת

- הימנע מלחשוף פורטים החוצה למעט המינימום ההכרחי
  (`5678` ל־n8n, `80` ל־Dify).
- שים Reverse Proxy (Caddy / Nginx / Traefik) עם TLS ומגן BasicAuth
  אם רוצים לגשת מבחוץ.
- **אל תחשוף** את `judge_api`, את `postgres` או את `ollama` לאינטרנט.
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

- `n8n_data`, `ollama_data`, `dify_postgres` — לגבות תקופתית
  (rsync/borg). אחסון מחוץ למכונה.
- workflows של n8n גם ניתנים ליצוא כ־JSON וגם לגבותם ב־git פרטי
  (לא בפרויקט הפומבי הזה).

---

## 14. ניטור, לוגים ודיאגנוסטיקה

### 14.1 לוגים בסיסיים

```bash
docker compose logs -f n8n
docker compose logs -f dify-api dify-worker
docker compose logs -f judge_api
docker compose logs -f ollama
```

### 14.2 מדדים

- זמן ריצה של `judge_cli.py` פר PCAP — נמדד כבר בפרויקט; שמור
  ב־SQLite לצד ה־verdict.
- דיוק (Cohen's kappa) — כבר קיים; הרץ מחדש אחרי החלפת מודל
  (`llm_judge/calibration.py`).
- שיעור override של ה־guardrail — סימן שהמודל נבחר לא מתאים.

### 14.3 התראות

- `docker events` + Prometheus + Grafana לתפעול אמיתי.
- לפיילוט, מספיק חוקי n8n שסופרים כשלונות רצופים ומודיעים.

---

## 15. עלויות ותקציב מעשי

- **חינם לחלוטין**: n8n Community + Dify Community + Ollama מקומי.
  עלות = חשמל + חומרה שיש לך.
- **חינם ב־Cloud**: GitHub Actions (כפי שקיים ב־`.github/workflows/analyze-pcap.yml`)
  ממשיך לתת אפס עלות ל־forks ציבוריים.
- **ספק LLM חיצוני**: הפעל אותו רק על שלב ה־Analyst (5–40 קריאות
  ל־PCAP). Cache SQLite שמובנה ב־Judge → הרצות חוזרות = חינם.
- **טיפ עלות**: כפה `LLM_JUDGE_MAX_CANDIDATES=40` (ברירת מחדל)
  והפעל `RULE_GUARDRAIL=1` — מונע קריאות מיותרות.

---

## 16. Checklist להשקה — מה חייב להיות מוכן

- [ ] Docker + Compose מותקנים ורצים (`docker run hello-world`).
- [ ] `automation/.env` מלא (`N8N_ENCRYPTION_KEY` ייחודי; לא ברירת מחדל).
- [ ] `.gitignore` כולל `automation/.env`, `automation/db/`, `automation/n8n_data/`,
      `dify/docker/volumes/`, ו־`llm_judge/output/`, `llm_judge/cache/`
      (חלק כבר קיים).
- [ ] Ollama עלה, מודל אחד לפחות נמשך (`ollama pull llama3.2`).
- [ ] n8n עולה ב־`http://localhost:5678`, יצרת משתמש/סיסמה.
- [ ] Workflow #1 (Auto-triage) עלה, נבדק על PCAP קיים.
- [ ] `judge_api` (או `docker exec`) מחזיר `verdicts.json` תקין.
- [ ] Dify עלה, App מסוג Agent הוגדר, RAG טעון עם `docs/*.md`.
- [ ] מפתחות ספק LLM (אם רלוונטי) נשמרים רק ב־`.env`, לא בגיט.
- [ ] Backup לשני ה־Stacks הוגדר.
- [ ] Notifications (Slack / Telegram / Email / GitHub) נבדקו קצה לקצה.
- [ ] קליברציה: `python llm_judge/calibration.py` עברה עם kappa ≥ סף.

---

## 17. שאלות נפוצות ותקלות מוכרות

### 17.1 "n8n לא רואה קבצים חדשים ב־incoming/"

- ודא שה־mount הוא `../incoming:/data/incoming:ro` וה־Trigger מצביע
  על `/data/incoming`.
- ב־Windows יש לפעמים בעיות inotify — הגדר את ה־trigger כ־poller
  (ב־n8n: node "Read Binary Files" עם Cron).

### 17.2 "Ollama מחזיר timeout"

- הגדל `LLM_JUDGE_TIMEOUT_S=600` בסביבה של judge_runner.
- ודא שהמודל **נמשך** (`ollama pull`) — הפעם הראשונה מורידה גיגה־בייטים.
- למחשב חלש: החלף ל־`gemma3:4b` או `phi3:mini`.

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

- הגבל volumes ל־Ollama (מודלים גדולים תופסים 10–40GB כל אחד).
- נקה: `docker system prune -a`, `ollama rm <model>`.

### 17.6 "n8n נתקע אחרי restart"

- לרוב מפתח הצפנה שונה. שמור את `N8N_ENCRYPTION_KEY` — אין דרך לשחזר
  credentials בלעדיו.

---

## 18. מפת דרכים להמשך

שלבים המוצעים ליישום, מסודרים לפי סדר:

1. **פיילוט מקומי** — n8n + Ollama + `judge_api` בלבד. workflow יחיד.
2. **חיבור Dify** — הוספת Agent עם RAG על המסמכים.
3. **Second-opinion Committee** — ולידציה של פסיקה על ידי שני מודלים.
4. **Threat-Intel Enrichment** — WHOIS / GeoIP / ASN לפני החלטה.
5. **התראות + Ticketing** — Slack/Telegram + GitHub Issue אוטומטי.
6. **Observability** — Prometheus/Grafana לצד המדדים של הפרויקט.
7. **Multi-tenant** — הפרדת נתיבים לפי משתמש/ארגון, סודות לפי משתמש.
8. **CI Gate** — הרחבת `tests/test_judge_kappa_regression.py` שיריץ
   גם את הזרימה החדשה על PCAP סינטטי כחלק מ־regression.

---

**המסמך הזה הוא המסגרת. כל מה שמפורט בו ניתן ליישום מיידי מעל
הפרויקט הקיים בלי לגעת בשורת קוד מקורית — כל האינטגרציה היא
"בצד" של הפרויקט: קבצי פלט, API עטיפה ומשתני סביבה שהוגדרו
כבר בפרויקט**.
