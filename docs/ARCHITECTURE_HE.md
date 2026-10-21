<div dir="rtl">

# ארכיטקטורת NetSec

> גרסה עברית של [`ARCHITECTURE.md`](ARCHITECTURE.md).

המערך תוכנן מחדש סביב מודל פעיל-תמיד של VM יחיד. המחשב הנייד הוא
כעת אופציונלי: הכל חי על VM קטן של ARM (‏Oracle Always Free), עם
נקודת כניסה אחת של HTTPS + basic-auth, שאליה כל המכשירים שלכם
מגיעים דרך Tailscale.

## מה נמצא היכן

```
INTERNET ---(רק :22 פתוח, מוקשח מול brute-force)------------ VM public IP
    |
    x    (כל השאר REJECT'ד על ידי iptables + קשור ל-interface)
    |
    v (Tailscale WireGuard, מוצפן end-to-end)
                    +--------------------------+
[ iPhone ]  <-----> |                          |  <-----> [ Laptop ]
                    |    netsec-agent (VM)     |
                    |                          |
                    |  Caddy 443 (תעודת Let's Encrypt)
                    |     |                    |
                    |     +- basicauth (bcrypt)|
                    |     |                    |
                    |     +--> /       -> portal :8080
                    |     +--> /rag/   -> RAG   :5200  (Dash + Flask)
                    |     +--> /chat/  -> Companion :5100 (Dash)
                    |                          |
                    |  Ollama (loopback בלבד :11434)
                    |     +- nomic-embed-text  (ה-embedder של RAG)
                    |     +- qwen2.5:3b        (ברירת מחדל של Companion + RAG)
                    |     +- granite / gemma / llama / phi
                    |                          |
                    |  צינור NetSec            |
                    |     +- ingest_api :8766  (העלאות חתומות-HMAC)
                    |     +- worker            (תור -> ניתוח -> דיוור)
                    |     +- SQLite /srv/netsec/db/netsec.db
                    |     +- reports /srv/netsec/reports/<sid>/
                    |                          |
                    |  n8n :5678 (login משלו, אוטומציה של workflows)
                    +--------------------------+
```

**ה-URL היחיד שאתם צריכים לזכור**: `https://netsec-agent.tail37ac21.ts.net/`.
כל השאר הוא תת-נתיב תחתיו.

## משטח חשיפה פומבי

נגיש חיצונית מכל האינטרנט:

| פורט | שירות | Auth | הערות |
|---|---|---|---|
| 22 | SSH | רק מפתח ssh, בלי סיסמאות | 4-5k ניסיונות brute-force ליום - כולם נדחים; ראוי לשקול לסגור ל-Tailscale בלבד בסבב עתידי |

כל השאר קשור ל-`100.68.246.54` (ה-interface של Tailscale) או ל-
`127.0.0.1` (loopback) - לא נתב מהאינטרנט.

## נגיש דרך Tailscale (פרטי, מוצפן)

| URL | שירות | Auth | הערות |
|---|---|---|---|
| `https://netsec-agent.../` | Portal | Caddy basicauth | דף נחיתה עם כרטיסים לכל שירות |
| `https://netsec-agent.../rag/` | RAG UI | Caddy basicauth | ‏Dash chat על דוחות NetSec מאונדקסים + מסמכים שרירותיים |
| `https://netsec-agent.../chat/` | AI Companion | Caddy basicauth | ‏Dash chat על מודלי Ollama המקומיים עם file drop |
| `https://netsec-agent.../rag/ask` | RAG REST | Caddy basicauth | ‏POST `{"q":"..."}` עבור סקריפטים / cron |
| `http://netsec-agent:8766` | Ingest API | HMAC פר-upload | רק client הדשבורד פוגע בו |
| `http://netsec-agent:5678` | n8n | ה-login של n8n עצמו | ‏UI של אוטומציית workflows |

## מקומי בלבד (‏127.0.0.1 על ה-VM)

| פורט | שירות | הערות |
|---|---|---|
| 11434 | Ollama | ‏containers אחים (worker) מגיעים אליו דרך DNS של docker; שירותי RAG + Companion על ה-host מגיעים אליו ב-loopback |

## ארבע האפליקציות בחמש משפטים

- **‏Portal** הוא דף HTML סטטי שמציג כל שירות אחר עם badge סטטוס חי.
- **‏RAG** הוא QA מועשר-אחזור על דוחות NetSec שלכם בתוספת כל קבצים
  שאתם מאנדקסים (‏Dash UI תואם ל-Companion; תשובות streaming; מקורות
  ככרטיסים פתוחים).
- **‏Companion** הוא UI צ'אט על מודלי Ollama המקומיים עם פיצ'ר
  גרירת קבצים (text, PDF, DOCX, PCAP).
- **צינור NetSec** (ingest + worker) מנתח PCAPs שהועלו עם מגלים +
  פאנל שופט LLM ושולח את הדוח באימייל.
- **‏n8n** מריץ workflows של התרעה (משלוח Gmail, ‏Telegram וכו')
  על גבי פלט הצינור.

## זרימת נתונים: העלאת PCAP

1. הדשבורד על המחשב הנייד שלכם חותם על הקובץ בסוד HMAC של ה-sensor.
2. ‏POST ל-`http://netsec-agent:8766/v1/pcap` (מעל Tailscale).
3. ‏`ingest_api` מוודא את החתימה, כותב ל-`/srv/netsec/data/pcap/<year>/<month>/<day>/`, יוצר שורת `sessions`.
4. ‏`worker` מושך מהתור, טוען את ה-PCAP, מריץ חילוץ פיצ'רים (‏tshark), ‏ML (‏IsolationForest + DBSCAN), חוקים (‏scan/flood/amp/ARP/DNS), מנועים מתקדמים (‏beacon/DGA/DNS-tunnel/TLS/ARP-DHCP).
5. פאנל שופט LLM נותן ציון לכל מועמד. ‏Cache hits הם בחינם.
6. ‏Renderer הדוח כותב `verdicts.json`, `verdicts.md`, `report.html`, `report.pdf`, `summary.md` תחת `/srv/netsec/reports/<sid>/`.
7. ה-mailer שולח את הסיכום + קובץ PDF מצורף לנמען שנשמר על שורת ה-session.
8. ה-ingester התקופתי של RAG (כל 15 דקות דרך systemd timer) רואה את ה-session החדש ומוסיף את ה-chunks שלו ל-vector store, כך ששאלות כמו "אילו IPs סומנו בריצה האחרונה?" הופכות ניתנות למענה תוך דקות.

## זרימת נתונים: שאלת ה-RAG

1. דפדפן פוגע ב-`https://netsec-agent.../rag/` -> ‏Caddy מאמת basicauth -> ‏proxies לאפליקציית RAG Dash על 5200.
2. המשתמש מקליד שאלה. ה-callback של Dash יוצר שורת query ושורף worker thread.
3. ה-worker עושה embedding לשאלה עם `nomic-embed-text` (דרך Ollama ב-127.0.0.1:11434), מבצע top-K של cosine על SQLite vector store, ומזרים תשובה טוקן-אחרי-טוקן מ-`qwen2.5:3b`.
4. ה-UI עושה poll כל 300ms בזמן ה-streaming, ציור התשובה הגדלה.

## פרסיסטנטיות

| נתיב | תכנים |
|---|---|
| `/srv/netsec/db/netsec.db` | ‏DB של השרת: ‏sensors, ‏pcap_files, ‏sessions, ‏verdicts, ‏panel_audit, ‏compare_jobs |
| `/srv/netsec/data/pcap/**` | ‏PCAPs שהועלו |
| `/srv/netsec/reports/<sid>/` | דוחות פר-session |
| `/srv/netsec/reports/compare/<jid>/` | דוחות pair-compare |
| `/srv/netsec/rag/store.db` | ‏Vector store של RAG (‏chunks + embeddings + metadata) |
| `/srv/netsec/rag/queries.db` | היסטוריית queries של RAG (לסרגל הצד) |
| `/srv/netsec/companion/chats.db` | היסטוריית צ'אטים של Companion |
| `docker volume ollama_models` | מודלי Ollama שנמשכו |
| `docker volume n8n_data` | ‏workflows + אישורים של n8n |
| `docker volume caddy_data` | CA פנימי של Caddy + תעודות שהונפקו |
| `/etc/netsec-tls/*` | תעודת Let's Encrypt שהונפקה דרך Tailscale (מתחדשת שבועית על ידי netsec-tls-renew.timer) |

## פורטים

| פורט | קשור ל- | ‏Container / process |
|---|---|---|
| 22 | `0.0.0.0` | sshd |
| 443 | `100.68.246.54` | ‏Caddy (רשת host, על host ה-VM) |
| 8766 | `100.68.246.54` | deploy-ingest_api-1 |
| 5678 | `100.68.246.54` | netsec-n8n (container legacy, login משלו) |
| 5100 | `100.68.246.54` | netsec-companion.service (systemd) |
| 5200 | `100.68.246.54` | netsec-rag.service (systemd) |
| 8080 | `100.68.246.54` | netsec-portal.service (systemd) |
| 11434 | `127.0.0.1` | deploy-ollama-1 (חשיפת loopback ל-RAG + Companion) |

## הפיצול בין systemd ל-Docker

- **‏systemd** בבעלותו: ‏Caddy (דרך `docker compose`), ‏Companion, ‏RAG, ‏RAG ingest timer, ‏TLS renewal timer, ‏portal. אלה השירותים הפעילים-תמיד הפונים למשתמש.
- **‏Docker Compose** בבעלותו: ‏ingest_api, ‏worker, ‏retention, ‏ollama, ‏n8n, ‏caddy. אלה ה-containers של data-plane.

אם הכל הלך לחושך, ‏`sudo docker compose up -d` + `sudo systemctl start netsec-portal netsec-rag netsec-companion` מחזיר את המערך.

## התאוששות אוטומטית

- לכל שירות פונה-משתמש יש `Restart=on-failure` ביחידת ה-systemd שלו.
- ל-refresh של אינדקס RAG יש `Persistent=true` על ה-timer שלו, אז ריצה שהוחמצה נתפסת ב-boot הבא.
- תעודת ה-TLS מתחדשת שבועית (ראשון 03:00) דרך `netsec-tls-renew.timer`; ‏Caddy טוען מחדש את התעודה החדשה בלי restart.
- ל-containers של Ollama ו-n8n יש `restart: unless-stopped` ב-compose.

השרשרת היחידה שתישבר בשקט היא: ‏`Tailscale על המחשב הנייד` <-> ‏`Tailscale על ה-VM` (שניהם צריכים להיות למעלה כדי שהמשתמש יגיע ל-tailnet). ה-Tailscale של ה-VM רץ כשירות מערכת תחת systemd, אז הוא חוזר עם ה-VM.

## בנייה מחדש מאפס על VM טרי של Oracle

ראו `deploy/README.md` לפקודות המדויקות. בערך:

```
git clone <repo>
cd deploy
cp .env.example .env   # ‏SMTP creds, ‏N8N_ENCRYPTION_KEY, וכו'
sudo docker compose up -d ingest_api worker retention ollama caddy
bash install-rag.sh
bash install-companion.sh
sudo systemctl enable --now netsec-portal netsec-tls-renew.timer
BASIC_AUTH_USER=you BASIC_AUTH_HASH="$(docker run --rm caddy:2 caddy hash-password --plaintext YOURPW)" \
    bash install-caddy.sh
```

ואז חברו את ה-VM לחשבון ה-Tailscale שלכם (`sudo tailscale up`) והפעילו תעודות HTTPS בקונסולת ה-admin של Tailscale (`Enable HTTPS`). הפנו את ה-Tailscale של iPhone / המחשב הנייד שלכם לאותו חשבון. הגיעו למערך ב-`https://<hostname>.<your-tailnet>.ts.net/`.

</div>
