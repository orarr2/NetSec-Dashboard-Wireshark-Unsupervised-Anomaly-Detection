# הנדסת נתונים ב-NetSec: מפקטה ברשת עד ל-verdict במייל

מסמך זה מפרט את כל המסלול שהדאטה עוברת בפרויקט - מהרגע שחבילת רשת
עוברת ב-NIC של הלפטופ שלך ועד לרגע שהדוח נשלח לתיבת המייל שלך. הוא
מיועד לקורא שמכיר Python ברמה סבירה אבל לא בהכרח מכיר את הפרויקט
לעומק. כל שלב מלווה בקובץ הרלוונטי בריפו כדי שתוכל לפתוח ולראות
בעצמך.

הפרק כתוב בשלושה חלקים:

1. **אקוויזיציה** - איך תופסים ומייצרים את הראו-דאטה
2. **טרנספורמציה** - איך הופכים חבילות ל-features מבניים
3. **צריכה** - איך הפייפליין ב-VM אוכל את הדאטה ומייצר החלטות

בסוף יש טבלה קצרה של הקבצים המרכזיים והמסלולים.


## חלק 1: אקוויזיציה - איפה הדאטה נולד

### 1.1 הלכידה עצמה

הלב זה `tshark`, ה-CLI של Wireshark. ב-NetSec יש שני מסלולים שמפעילים
אותו, ושניהם יוצרים את אותו סוג פלט (קובץ `.pcapng`):

**מסלול א - הקלטה חיה מהדשבורד**
בנוטבוק `app/Network_Security_Dashboard.ipynb` יש כפתור "Live
Recording". לחיצה עליו מפעילה instance של `LiveCaptureWorker`
(מאותחל בתאי הנוטבוק) שמריץ:

```
tshark -i <interface> -w <label>_chunk_<ts>_<n>.pcap -l \
    -T fields -E header=n -E separator=| -E occurrence=f -E quote=n \
    -e <fields...>
```

הפרמטרים:
- `-i <interface>` - הכרטיס לסניפור (למשל `Wi-Fi` או `Ethernet`)
- `-w` - כותב chunk של pcap לדיסק; כל Pause/Resume פותח chunk חדש,
  וב-Stop & Save כל ה-chunks מתמזגים לקובץ אחד עם `mergecap`
- `-l -T fields -E separator=|` - במקביל לכתיבה, tshark פולט שדות
  חיים ל-stdout עבור המונים החיים בדשבורד

הקבצים נופלים לתיקייה `netsec_sessions/` שהיא **מקומית ולא נכנסת
לגיט** (מסודר ב-`.gitignore`).

**מסלול ב - קובץ pcap קיים**
גוררים קובץ `.pcap` או `.pcapng` לדפדפן של הנוטבוק. שום הקלטה חדשה -
פשוט טוענים קובץ שכבר יש לך (בדיקות מוקדמות, קבצים ציבוריים כמו
`attack_tests/pcaps/*`, וכו').

**חשוב להבין:** `tshark` בשני המסלולים לא מנתח כלום עדיין. הוא רק
מייצר את קובץ ה-pcapng הבינארי, כמו הקלטת וידיאו של הרשת שלך. כל
הפרשנות באה בשלב הבא.


### 1.2 חתימה והעברה ל-VM (אם רוצים)

אם רוצים שה-VM ינתח את הקובץ בענן ולא הלפטופ, יש CLI קטן:
`tools/upload_pcap.py`. הוא:

1. פותח את הקובץ ב-streaming (לא טוען הכל לזיכרון - קבצים גדולים
   עובדים)
2. מחשב HMAC-SHA256 על התוכן עם מפתח סודי שרשום ב-DB של ה-VM לחיישן
   הספציפי
3. POST-שולח ל-`http://netsec-agent:8766/v1/pcap` עם ה-signature
   ב-header
4. ה-VM בודק את החתימה מול הרשומה של החיישן, ורק אז מקבל

זו לא חתימה קריפטוגרפית של אמת (זה HMAC משותף עם הצד השני), אבל היא
מונעת שמישהו לא-מורשה ב-tailnet יעלה קבצים. ה-secret נוצר פעם אחת
בזמן `deploy/create_sensor.py`.


## חלק 2: טרנספורמציה - מ-pcapng לטבלה של פיצ'רים

זו הליבה של פיסת הנדסת הנתונים. הקוד המרכזי חי ב-`app/dashboard_module.py`
(עצמו אוטו-מייצור מהנוטבוק) וב-`attack_tests/run_pipeline.py` (מהדורה
CLI נקייה של אותו קוד).

### 2.1 חילוץ שדות מ-tshark

השלב הראשון: לוקחים את ה-pcapng ומריצים עליו:

```
tshark -r <file.pcapng> -n -T fields \
    -E header=n -E separator=| -E occurrence=f \
    -e frame.time_epoch -e frame.len \
    -e eth.src -e eth.dst \
    -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst \
    -e _ws.col.Protocol \
    -e tcp.srcport -e tcp.dstport -e tcp.flags \
    -e udp.srcport -e udp.dstport \
    -e dns.qry.name -e dns.flags.rcode -e dns.flags.response \
    -e arp.src.proto_ipv4 -e arp.src.hw_mac -e arp.opcode \
    -e http.host -e tls.handshake.extensions_server_name
```

הפלט: טקסט מופרד ב-`|` עם שורה לכל חבילה, עמודה לכל שדה שביקשנו. שדות
שלא קיימים בחבילה נשארים ריקים.

**למה 22 שדות ולא הכל?** כי pcapng הוא בינארי כבד. ה-fields
שאנחנו רוצים תופסים ~2% מנפח ה-pcap המקורי (מדדנו את זה עם
`tools/measure_pipeline_ratios.py`). כל ניתוח הבא רץ על השדות
המחולצים, לא על ה-binary.

ב-`run_pipeline.py` הפלט של tshark מוזרם ישירות מ-stdout ל-pandas,
ב-chunks במקום הכל בבת אחת:

```python
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, ...)
reader = pd.read_csv(proc.stdout, sep="|", header=None, names=COLS,
                     dtype=str, na_filter=False, chunksize=CHUNK_ROWS)
for df in reader:
    ...
```

עמודות כמו `ts` ו-`len` מקבלות המרה מספרית; עמודות שיש בהן גם IPv4
וגם IPv6 עוברות coalesce ל-`ip_src`/`ip_dst` יחידים.


### 2.2 אגרגציה per-IP - איך `ip_features` נבנה

מהטבלה של חבילות בונים טבלה של **IP-ים** (כל שורה = IP אחד):

- `mean_len` - ממוצע גודל חבילה שיצא מה-IP
- `std_len` - סטיית תקן של גודל חבילה
- `count` - כמה חבילות בסך הכל
- `burst_score` - מדד שמנסה לתפוס פרצי פעילות (packet spikes)
- `unique_dsts` - כמה יעדים שונים דיבר איתם
- `syn_count`, `rst_count`, `fin_count`, `null_count`, `xmas_count` -
  מונים של דגלי TCP שונים; קריטיים לזיהוי סריקות
- `bytes_src`, `bytes_dst` - בייטים ששלח וקיבל

זו הטבלה שכל ה-ML רץ עליה. כל השאר עובד גם על ה-DataFrame המקורי (למשל
כללי DNS, ARP) אבל ה-ML צריך vector אחד לכל אובייקט.


### 2.3 קטגוריזציה של מכשירים (device classification)

לפני שיש verdict, נחמד לדעת "IP 192.168.1.42 זה מדפסת או טלפון". יש
מנוע 3-שלבי:

1. **hostname / OUI / port rules** - `app/device_rules.json` (261
   כללים). מסתכל על שם המכשיר, על יצרן ה-MAC (OUI), ועל אילו פורטים
   הוא פותח, ומצליב עם רשימה
2. **DNS fingerprints** - `app/dns_fingerprints.json` (217 חתימות).
   מסתכל אילו domain-ים המכשיר שאל (Xbox, Ring, Alexa הם ידועים)
3. **heuristics התנהגותיים** - במקרה של אין תשובה מהשניים הקודמים,
   מכריע לפי דפוסים (למשל: הרבה DNS + הרבה HTTPS = "browser device")

תוצאה: לכל IP יש קטגוריה מ-12 האפשרויות (`camera`, `tv`, `iot`,
`computer`, `mobile`, `printer`, `gaming`, `voice-assistant`, `smart-
home`, `router`, `nas`, `unknown`).

זה לא רק תיאורי - זה משפיע על ההחלטה של ה-Judge (מדפסת שסורקת פורטים
זה חשוד; מחשב שלוקח DNS זה נורמלי).


### 2.4 שלוש שכבות זיהוי במקביל

על ה-DataFrame וה-ip_features רצות במקביל:

**שכבת ML**
- **IsolationForest** על ה-ip_features. contamination קבוע ב-0.10,
  200 trees, seed 42. הפלט: `anomaly` (0/1) ו-`iso_score` לכל IP
- **DBSCAN** - clustering על אותם פיצ'רים; IP שלא נופל באף cluster
  נחשב outlier
- **LSTM** - מיוחד. הופך את הטריאס של חבילות למסדרה של-1-שנייה-bin
  (`packet size per second`), מאמן LSTM לחזות את ה-bin הבא, ומדד
  שגיאה גדולה = אנומליה. **דורש לפחות 20 bins - קבצים קצרים
  מ-20 שניות מדלגים**

**שכבת כללים דטרמיניסטיים** (הזיהוי החזק ביותר בפועל)
- Port scan: SYN לחוד/FIN לחוד/NULL/Xmas > 50 חבילות עם (> 20 יעדים
  שונים וגם ratio > 0.25) או ratio > 0.7
- SYN flood: הרבה SYN במקביל מכתובות רבות (spoofed sources)
- DNS amplification: הרבה תשובות מ-UDP/53 עם גודל ממוצע גדול
- ARP spoofing: IP שלה יותר מ-MAC אחד
- DNS long queries: query name חשוד

**שכבת advanced engines** (6 מנועים ב-`app/advanced_engines.py`)
- ARP/DHCP: rogue DHCP, arp_ip_multi_mac (עם gratuitous reply),
  arp_mac_many_ips
- DNS tunneling: 20+ subdomains ייחודיים תחת דומיין אחד, אנטרופיה
  גבוהה, ratio ייחודי גבוה
- DGA: מודל bigram על labels של DNS מנסה למצוא labels אלגוריתמיים
- Beaconing: TCP-SYN periodic ליעד חיצוני, ציון סדירות
- TLS: rare JA3, SNI-less connections לכתובות חיצוניות, sni-vs-ip
  mismatch (domain fronting)
- Fusion: מתאם בין המנועים בחלון 15 דקות → device risk score

כל שלוש השכבות מייצרות רשימת candidates - כל candidate הוא dict עם
כל הפיצ'רים, ההיסטוריה, הקונטקסט, וההצבעות של הגלאים על ה-IP הזה.


## חלק 3: צריכה - איך ה-VM מעבד את הכל 24/7

### 3.1 השירותים שרצים ב-VM

ה-VM (Oracle ARM אולטרה חינם, 4 vCPU 24GB RAM) מריץ שלושה שירותים
עיקריים ב-Docker Compose (הגדרה: `deploy/docker-compose.yml`):

- **`deploy-ingest_api-1`** - FastAPI ב-port 8766, מקבל את ה-uploads.
  קוד: `server/ingest_api.py`
- **`deploy-worker-1`** - עובד רקע שסורק את התור, מנתח, כותב דוחות.
  קוד: `server/worker.py`
- **`deploy-retention-1`** - ניקוי יומי (backup, prune, VACUUM). קוד:
  `server/retention.py`

חוץ מזה יש `deploy-ollama-1` (מודלים לוקאליים ל-RAG וCompanion),
`netsec-n8n` (אוטומציה של אלרטים במייל), ו-`deploy-caddy-1`
(reverse-proxy עם HTTPS + basicauth).


### 3.2 המסע של קובץ pcap ב-VM - צעד-אחר-צעד

**שלב א' - הגעה** (`server/ingest_api.py::upload_pcap`):
```python
@app.post("/v1/pcap")
async def upload_pcap(request, x_sensor_id: str, x_hmac: str,
                      x_notify_email: str = None):
    body = await request.body()
    verify_hmac(x_hmac, body, sensor_secret_from_db(x_sensor_id))
    sha = hashlib.sha256(body).hexdigest()
    dest = f"/srv/netsec/data/pcap/{year}/{month}/{day}/{sha[:8]}_{orig}.pcapng"
    open(dest, "wb").write(body)
    pcap_id = db.register_pcap(conn, sha, orig_name, size, sensor_id, dest)
    session_id = db.create_session(conn, pcap_id, label, "prod",
                                   notify_email=x_notify_email)
    return {"session_id": session_id, "status": "queued"}
```

הקובץ נשמר בדיסק בסידור year/month/day. שני רשומות נכנסות ל-SQLite:
`pcap_files` (הקובץ עצמו) ו-`sessions` (עבודת ניתוח חדשה בסטטוס
`queued`).

**שלב ב' - התור** (`server/worker.py::run_once`):
worker בלולאה אינסופית קורא ל-`db.claim_next_job()` שמבצע `SELECT ...
FOR UPDATE` פייתוני (transactional): מוצא סשן בסטטוס queued, מסמן אותו
running, מחזיר את הרשומה. שני workers במקביל לא יכולים לתפוס את אותה
עבודה.

**שלב ג' - הניתוח** (`server/worker.py::process_job`):
```python
out, assembled, client, context, S, findings = analyze_fn(
    pcap_path, job.get("label"),
    baseline_conn=conn, current_session_id=sid,
    panel_override=panel_override)
```

`analyze_fn` = `judge_cli.analyze_and_judge`. זה מריץ את כל הצנרת של
חלק 2 בסדר: extract → aggregate → 3 detection layers → build candidate
blobs → send to LLM panel.

**שלב ד' - LLM Panel** (חלק אופציונלי אבל ברירת המחדל):
במקום מודל אחד, שולחים כל candidate ל-3-6 מודלים במקביל (Groq
llama-8b, gpt-oss-20b, gemini-flash, וכו'). כל אחד מחזיר verdict
(malicious/suspicious/benign) + confidence + reasoning. יש resolver
שמכריע:

- הסכמה מלאה = מקבלים את זה
- מחלוקת = פותחים "debate round" שבו כל מודל רואה את התשובות של האחרים
  ומקבל הזדמנות לשנות דעה
- אחרי הדיון: הצבעה, במקרה שוויון בוחרים את החמור יותר (fail-safe)

הקוד: `llm_judge/judge_core.py::judge_candidates_panel`.

**שלב ה' - guardrail**:
לפני שהתשובה נכנסת לדוח, יש guardrail שאם קוד דטרמיניסטי אמר "port
scan" ו-LLM אמר "benign", הguardrail מדליק את התשובה של הקוד. שירותי-
תוכנה אנושיים לא תמיד יבינו את זה נכון (הם מנסים להיות "מוגנים לא
לפגוע"), אבל למידה חד-משמעית של port scan דטרמיניסטי גוברת.

**שלב ו' - כתיבה** (`server/results.py::write_all`):
כל תוצאה נכנסת ל-3 מקומות במקביל:
1. שורה בטבלת `verdicts` ב-SQLite (rich schema)
2. שורה ב-`panel_audit` (מי הצביע מה, זמן, אם השתנתה דעה)
3. קובץ `/srv/netsec/reports/<sid>/verdicts.json` - JSON גדול עם כל
   הפרטים כולל `evidence` projection (device, packets, ports וכו')

**שלב ז' - Rendering** (`llm_judge/judge_cli.py::_render_markdown`
ו-`server/compare_report.py::render`):
מהדאטה בונים דוחות human-friendly:
- `verdicts.md` - markdown, קלקסי לקריאה
- `report.html` - עטוף בטמפלייט CSS יפה
- `report.pdf` - weasyprint (אם מותקן, אחרת מדלגים)
- `summary.md` - סיכום קצר, מתאים לגוף מייל

**שלב ח' - Delivery** (`server/notify.py::deliver`):
נשלח למייל דרך SMTP (Gmail app-password ברירת מחדל). fallback ל-n8n
webhook אם ה-SMTP נפל.


### 3.3 היסטוריה - מה קורה אחרי שהסשן נגמר?

הדאטה של הסשן נשארת ב-3 מקומות:

1. **SQLite** (`/srv/netsec/db/netsec.db`) - הרשומה של הסשן, כל
   ה-verdicts, כל ה-panel audits
2. **קובץ pcap** - נשמר 7 ימים (retention.py) ואז נמחק, אבל
3. **field-index** (החילוץ של tshark) - נשמר תמיד. גם אחרי שה-pcap
   נמחק, יש לך את הטבלה של החבילות. הצנרת יכולה לרוץ מחדש בלי הקובץ
   המקורי


### 3.4 האינטגרציה עם RAG - איך הדאטה הופך לחיפוש

זה החלק החדש. כל 15 דקות הטיימר `netsec-rag-ingest.timer` מריץ:

```
python3 tools/netsec_rag.py ingest-netsec /srv/netsec/reports
```

הסקריפט:
1. סורק את `/srv/netsec/reports/<sid>/verdicts.json` לכל סשן
2. לכל result בונה טקסט קריא: "Session 24, IP 172.10.146.42 was
   judged malicious, category port_scan, device Intel pc-lab,
   confidence 0.93, reasoning ..."
3. שולח את הטקסט ל-Ollama עם המודל `nomic-embed-text` → מקבל וקטור
   768-מימדי
4. שומר את (טקסט + וקטור + מטאדאטה) ב-`store.db` (SQLite עם ה-vector
   כ-BLOB float32)
5. deduplication לפי `content_hash` - אותו טקסט לא נכנס פעמיים

כשמישהו שואל שאלה ב-RAG:
1. השאלה נכנסת גם ל-`nomic-embed-text` → וקטור
2. cosine top-K מול המטריצה (brute force ב-numpy - מהיר על 302
   chunks)
3. K הקטעים העליונים נשלחים כקונטקסט למודל צ'אט (`qwen2.5:3b`) שמנסח
   תשובה, מצטט [1], [2]...


## חלק 4: הפעולות הקטנות שרצות בשקט

מלבד ה-worker הראשי, יש מספר "microservices" קטנים בפייתון שרצים
כ-systemd timers ב-VM. הם קטנים בכוונה - כל אחד עושה דבר אחד:

| Timer | מריץ | מה עושה |
|---|---|---|
| `netsec-rag-ingest.timer` | `tools/netsec_rag.py ingest-netsec` | מוסיף סשנים חדשים ל-RAG store |
| `netsec-tls-renew.timer` | `tailscale cert netsec-agent.tail37ac21.ts.net` | מרענן את תעודת Let's Encrypt |
| `netsec-portal-latest.timer` | `write-latest-json.py` + `write-sessions-json.py` | מייצר את `/latest.json` ו-`/sessions.json` שהפורטל קורא |
| `netsec-retention` (docker service) | `server/retention.py` | ניקוי יומי: pcap-ים ישנים מ-7 יום, VACUUM חודשי, watermark של 85% דיסק |

כל אחד מהם רץ עצמאית, ואם אחד נופל, השאר עובדים.


## חלק 5: מפת קבצים

הנה הקבצים המרכזיים במסלול הדאטה, לפי סדר המסע:

| קובץ | תפקיד |
|---|---|
| `app/Network_Security_Dashboard.ipynb` | הלוח הראשי; מפעיל `LiveCaptureWorker` להקלטה חיה |
| `app/dashboard_module.py` | ייצוא אוטומטי של הנוטבוק לספרייה שאפשר לייבא (אל תערוך ידנית) |
| `attack_tests/run_pipeline.py` | CLI נקי שמריץ בדיוק את אותה צנרת בלי UI |
| `app/advanced_engines.py` | 6 המנועים המתקדמים (beacon, DGA, DNS tunnel, ARP, TLS, fusion) |
| `tools/upload_pcap.py` | חתימת HMAC + streaming upload ל-VM |
| `server/ingest_api.py` | FastAPI endpoint שמקבל את ה-upload |
| `server/worker.py` | לוקח סשן מהתור, קורא ל-analyze, כותב את הכל |
| `llm_judge/judge_cli.py::analyze_and_judge` | הפונקציה הראשית - צנרת מלאה |
| `llm_judge/judge_core.py::judge_candidates_panel` | פאנל של מודלים עם debate |
| `server/results.py` | כתיבה ל-DB (verdicts, panel_audit) + לקובץ JSON |
| `server/compare_report.py` | דוח השוואה S1 מול S2 |
| `server/notify.py` | שליחת מייל / fallback ל-n8n |
| `tools/netsec_rag.py` | האינדקסינג של הדוחות ל-RAG store |
| `deploy/brand/write-latest-json.py` | מייצר את הכרטיס "הסשן האחרון" בפורטל |
| `deploy/brand/write-sessions-json.py` | מייצר את רשימת כל הסשנים ל-Reports Browser |


## הערה על ה-Data Engineering כדיסציפלינה בפרויקט הזה

הרבה שיטות אמת של data engineering נמצאות פה בקטן: schema קפדני
(pandas dtypes, sqlite `NOT NULL` + `CHECK`), idempotency
(dedup לפי sha256 של pcap, לפי content_hash של chunk), separation of
concerns (extract vs transform vs load), streaming (upload בלי לטעון
לזיכרון), retention policies, monitoring (`/healthz`, systemd
`Restart=on-failure`), auditability (`panel_audit` שומרת גם את
ההצבעות שהוחלפו בדיון, לא רק את הסופיות).

ההבדל מ-data engineering תעשייתי (Kafka + Spark + data lake) הוא רק
בסקאלה. פה DB אחד של SQLite, workers חד-קונטיינריים, אין distributed
computing - אבל **הצורה** של הזרימה זהה: source → ingest → validate
→ transform → analyze → store → notify → archive.
