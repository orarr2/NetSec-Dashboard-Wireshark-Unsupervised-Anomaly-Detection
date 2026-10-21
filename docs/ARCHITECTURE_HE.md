<div dir="rtl" align="right">

# ארכיטקטורת NetSec

המערך תוכנן מחדש סביב מודל של VM יחיד שפעיל 24/7. המחשב הנייד
הפך לאופציונלי: הכל חי על מכונת ARM קטנה (‏Oracle Always Free),
עם נקודת כניסה אחת של HTTPS עם אימות בסיסי, שאליה כל המכשירים
שלכם מגיעים דרך Tailscale.

## מה נמצא היכן

```
INTERNET ---(רק :22 פתוח, מוקשח מול brute-force)------------ VM public IP
    |
    x    (כל השאר נדחה על ידי iptables, קשור ל-interface)
    |
    v (Tailscale WireGuard, מוצפן מקצה לקצה)
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
                    |     +- qwen2.5:3b        (ברירת מחדל ל-Companion ול-RAG)
                    |     +- granite / gemma / llama / phi
                    |                          |
                    |  צינור NetSec            |
                    |     +- ingest_api :8766  (העלאות חתומות ב-HMAC)
                    |     +- worker            (תור -> ניתוח -> דיוור)
                    |     +- SQLite /srv/netsec/db/netsec.db
                    |     +- reports /srv/netsec/reports/<sid>/
                    |                          |
                    |  n8n :5678 (אימות נפרד, אוטומציה של תהליכי עבודה)
                    +--------------------------+
```

**הכתובת היחידה שחשוב לזכור**: `https://netsec-agent.tail37ac21.ts.net/`.
כל השאר הוא תת-נתיב מתחתיה.

## משטח החשיפה הציבורי

נגיש חיצונית מהאינטרנט כולו:

| פורט | שירות | אימות | הערות |
|---|---|---|---|
| 22 | SSH | מפתח ssh בלבד, בלי סיסמאות | ‏4-5 אלף ניסיונות כוח גס ליום - כולם נדחים; שווה לשקול לסגור ל-Tailscale בלבד בשלב מאוחר יותר |

כל השאר קשור ל-`100.68.246.54` (ה-interface של Tailscale) או ל-
`127.0.0.1` (loopback) - לא ניתן להגיע אליו מהאינטרנט.

## נגיש דרך Tailscale (פרטי, מוצפן)

| כתובת | שירות | אימות | הערות |
|---|---|---|---|
| `https://netsec-agent.../` | Portal | ‏Caddy basicauth | דף נחיתה עם כרטיסים לכל שירות |
| `https://netsec-agent.../rag/` | ממשק RAG | ‏Caddy basicauth | ‏צ'אט Dash על דוחות NetSec באינדקס + מסמכים נוספים |
| `https://netsec-agent.../chat/` | AI Companion | ‏Caddy basicauth | ‏צ'אט Dash מעל מודלי Ollama מקומיים עם גרירת קבצים |
| `https://netsec-agent.../rag/ask` | ‏RAG REST | ‏Caddy basicauth | ‏POST של `{"q":"..."}` לסקריפטים ול-cron |
| `http://netsec-agent:8766` | ‏API של קליטה | ‏HMAC להעלאה | רק לקוח הדשבורד פונה אליו |
| `http://netsec-agent:5678` | n8n | אימות משלו | ממשק ניהול תהליכי עבודה |

## מקומי בלבד (‏127.0.0.1 על ה-VM)

| פורט | שירות | הערות |
|---|---|---|
| 11434 | Ollama | ‏containers אחים (worker) מגיעים אליו דרך DNS של docker; שירותי RAG ו-Companion על ה-host מגיעים אליו דרך loopback |

## ארבע האפליקציות בחמישה משפטים

- **‏Portal** הוא דף HTML סטטי שמציג כל שירות אחר עם תג סטטוס חי.
- **‏RAG** הוא QA מועשר-אחזור על דוחות NetSec שלכם ועוד קבצים
  שהוזנו לאינדקס (ממשק Dash זהה ל-Companion; תשובות זורמות;
  מקורות ככרטיסים ניתנים להרחבה).
- **‏Companion** הוא ממשק צ'אט מעל מודלי Ollama המקומיים עם גרירת
  קבצים (טקסט, ‏PDF, ‏DOCX, ‏PCAP).
- **צינור NetSec** (קליטה + worker) מנתח קבצי PCAP שהועלו באמצעות
  מגלים ופאנל שופטי LLM, ושולח את הדוח באימייל.
- **‏n8n** מריץ תהליכי התרעה (משלוח Gmail, ‏Telegram וכו') על גבי
  פלט הצינור.

## זרימת נתונים: העלאת קובץ PCAP

1. הדשבורד על המחשב הנייד שלכם חותם על הקובץ בסוד ה-HMAC של
   החיישן.
2. ‏POST ל-`http://netsec-agent:8766/v1/pcap` (מעל Tailscale).
3. ‏`ingest_api` מאמת את החתימה, כותב ל-
   `/srv/netsec/data/pcap/<year>/<month>/<day>/`, יוצר שורת
   `sessions`.
4. ה-`worker` מושך מהתור, טוען את הקובץ, מריץ חילוץ מאפיינים
   (‏tshark), למידת מכונה (‏IsolationForest + DBSCAN), חוקים
   (סריקה, הצפה, הגברה, ‏ARP, ‏DNS), מנועים מתקדמים (‏beacon, ‏DGA,
   מנהור DNS, ‏TLS, ‏ARP-DHCP).
5. פאנל שופטי LLM מדרג כל מועמד. פגיעות ב-cache הן בחינם.
6. מרנדר הדוח כותב `verdicts.json`, `verdicts.md`, `report.html`,
   `report.pdf`, `summary.md` תחת `/srv/netsec/reports/<sid>/`.
7. שרת הדואר שולח את הסיכום בתוספת ה-PDF המצורף לנמען שנשמר על
   שורת ה-session.
8. מנגנון הקליטה התקופתי של RAG (כל 15 דקות דרך timer של systemd)
   רואה את הסבב החדש ומוסיף את הקטעים שלו למאגר הווקטורי, כך
   ששאלות כמו "אילו כתובות IP סומנו בריצה האחרונה?" מקבלות
   מענה תוך דקות.

## זרימת נתונים: שאילת RAG

1. הדפדפן פונה ל-`https://netsec-agent.../rag/` ← ‏Caddy מאמת
   basicauth ← מפנה לאפליקציית Dash של RAG על 5200.
2. המשתמש מקליד שאלה. ה-callback של Dash יוצר שורת שאילתה
   ומריץ worker thread.
3. ה-worker מייצר embedding לשאלה עם `nomic-embed-text` (דרך
   Ollama על `127.0.0.1:11434`), מריץ top-K של דמיון קוסינוס על
   מאגר הווקטורים ב-SQLite, ומזרים תשובה טוקן-אחרי-טוקן מ-
   `qwen2.5:3b`.
4. הממשק עושה poll כל 300 אלפיות שנייה בזמן ההזרמה, ומצייר את
   התשובה שגדלה.

## שימור נתונים

| נתיב | תכנים |
|---|---|
| `/srv/netsec/db/netsec.db` | ‏DB השרת: חיישנים, קבצי PCAP, סבבים, פסיקות, audit של פאנל, עבודות השוואה |
| `/srv/netsec/data/pcap/**` | קבצי PCAP שהועלו |
| `/srv/netsec/reports/<sid>/` | דוחות לכל סבב |
| `/srv/netsec/reports/compare/<jid>/` | דוחות השוואה בין זוג סבבים |
| `/srv/netsec/rag/store.db` | מאגר הווקטורים של RAG (קטעים + embeddings + מטה-דאטה) |
| `/srv/netsec/rag/queries.db` | היסטוריית שאילתות של RAG (לסרגל הצד) |
| `/srv/netsec/companion/chats.db` | היסטוריית צ'אטים של Companion |
| `docker volume ollama_models` | מודלי Ollama שהורדו |
| `docker volume n8n_data` | תהליכי העבודה והאישורים של n8n |
| `docker volume caddy_data` | רשות CA פנימית של Caddy ותעודות שהונפקו |
| `/etc/netsec-tls/*` | תעודת Let's Encrypt שהונפקה דרך Tailscale (מתחדשת שבועית על ידי `netsec-tls-renew.timer`) |

## פורטים

| פורט | קשור ל- | ‏Container / תהליך |
|---|---|---|
| 22 | `0.0.0.0` | sshd |
| 443 | `100.68.246.54` | ‏Caddy (רשת host, על ה-VM) |
| 8766 | `100.68.246.54` | deploy-ingest_api-1 |
| 5678 | `100.68.246.54` | netsec-n8n (container legacy, אימות משלו) |
| 5100 | `100.68.246.54` | netsec-companion.service (systemd) |
| 5200 | `100.68.246.54` | netsec-rag.service (systemd) |
| 8080 | `100.68.246.54` | netsec-portal.service (systemd) |
| 11434 | `127.0.0.1` | deploy-ollama-1 (חשיפה ב-loopback ל-RAG ול-Companion) |

## הפיצול בין systemd ל-Docker

- **‏systemd** אחראי על: ‏Caddy (דרך `docker compose`), ‏Companion,
  ‏RAG, ‏timer הקליטה של RAG, ‏timer חידוש התעודה, ‏portal. אלה
  השירותים הפעילים-תמיד הפונים למשתמש.
- **‏Docker Compose** אחראי על: ‏ingest_api, ‏worker, ‏retention,
  ‏ollama, ‏n8n, ‏caddy. אלה ה-containers של שכבת הנתונים.

אם הכל ירד לחושך, הפקודות ‏`sudo docker compose up -d` ואחריהן
`sudo systemctl start netsec-portal netsec-rag netsec-companion`
מחזירות את המערך לחיים.

## התאוששות אוטומטית

- לכל שירות שפונה למשתמש יש `Restart=on-failure` ביחידת ה-systemd
  שלו.
- רענון האינדקס של RAG מוגדר עם `Persistent=true` ב-timer, כך
  שריצה שהוחמצה נתפסת ב-boot הבא.
- תעודת ה-TLS מתחדשת שבועית (יום ראשון 03:00) דרך
  `netsec-tls-renew.timer`; ‏Caddy טוען את התעודה החדשה חמה, בלי
  restart.
- ל-containers של Ollama ושל n8n יש `restart: unless-stopped`
  ב-compose.

השרשרת היחידה שעלולה להישבר בשקט היא: ‏Tailscale על המחשב הנייד
← Tailscale על ה-VM (שניהם חייבים להיות למעלה כדי שהמשתמש יגיע
ל-tailnet). ה-Tailscale של ה-VM רץ כשירות מערכת תחת systemd, אז
הוא חוזר יחד עם ה-VM.

## בנייה מחדש מאפס על VM טרי של Oracle

ראו `deploy_README.md` לפקודות המדויקות. בגדול:

```
git clone <repo>
cd deploy
cp .env.example .env   # ‏SMTP creds, ‏N8N_ENCRYPTION_KEY וכו'
sudo docker compose up -d ingest_api worker retention ollama caddy
bash install-rag.sh
bash install-companion.sh
sudo systemctl enable --now netsec-portal netsec-tls-renew.timer
BASIC_AUTH_USER=you BASIC_AUTH_HASH="$(docker run --rm caddy:2 caddy hash-password --plaintext YOURPW)" \
    bash install-caddy.sh
```

לאחר מכן, חברו את ה-VM לחשבון ה-Tailscale שלכם (`sudo tailscale up`)
והפעילו הנפקת תעודות HTTPS בקונסולת ה-admin של Tailscale (לחיצה על
`Enable HTTPS`). הפנו גם את ה-Tailscale של האייפון או המחשב הנייד
לאותו חשבון. גשו למערך בכתובת
`https://<hostname>.<your-tailnet>.ts.net/`.

</div>
