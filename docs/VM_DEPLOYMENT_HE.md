<div dir="rtl" align="right">

# פריסת VM - הרצת מערך הניתוח 24/7

הרצת מערך הניתוח בן ארבעת השירותים (`deploy/docker-compose.yml`)
על VM קטן שבבעלותכם, שנגיש רק דרך רשת Tailscale פרטית.
הפריסה הייחוס משתמשת ב-instance ARM חינמי של Oracle Cloud;
כל VM של Ubuntu 22.04+ עם 4GB RAM עובד זהה. `deploy_README.md`
מכסה את ה-quickstart המינימלי; הקובץ הזה נכנס לעומק של תאימות ARM64,
מודל הרשת של Tailscale-only, הקמה ראשונית, ואימות שנתיב הניתוח
בפועל ביצע קריאת LLM.

> כל הכתובות ונתיבי המפתח בקובץ הזה הם placeholders - החליפו
> בערכים של ה-VM שלכם. שום דבר כאן לא מזהה מכונה חיה.

---

## למה VM

| | מחשב נייד | Always Free VM |
|---|---|---|
| זמינות | רק כשאתם משאירים אותו דלוק | 24/7 |
| עלות | חינם | חינם (‏Always Free tier, בלי חיוב כרטיס) |
| RAM זמין למערך | משותף עם כל השאר | 24GB ייעודי (‏tier ‏ARM) |
| ליבות | משותפות | 4 ייעודיות |

ההבדל המעשי: ‏PCAP שהועלה ב-3 לפנות בוקר מנותח ב-3 לפנות בוקר.
היסטוריית session, בייסליין פר-התקן, ‏beaconing על פני ימים - כל אלה
הופכים משמעותיים רק כשמכונת הניתוח פעילה תמיד.

---

## מכונת הייחוס (‏Oracle Always Free ARM)

| מאפיין | ערך |
|---|---|
| צורה | `VM.Standard.A1.Flex` |
| משאבים | 4 OCPU / 24GB RAM / 100GB נפח boot |
| OS | Ubuntu 22.04 או 24.04 LTS, **aarch64** |
| IP ציבורי | `<vm-public-ip>` (‏SSH בלבד) |
| IP של Tailscale | `<vm-tailscale-ip>` (כל השאר) |
| נתיב פרויקט | `<repo>/deploy` |
| שורש נתונים | `/srv/netsec` |

`VM.Standard.A1.Flex` ב-4 OCPU / 24GB צורך את כל הקצאת ARM של
Always Free עבור ה-tenancy (3,000 OCPU-hours ו-18,000 GB-hours
לחודש). לא ניתן ליצור instance שני של A1 לצידו.

**להישאר $0.** המגבלות ש-Oracle בפועל אוכפת ב-free tier: אחסון
block סה"כ ≤ 200GB (instance שני של A1 גם חסום). שמרו על
100GB נפח ה-boot; אל תוסיפו volume block שיחצה 200GB. שירות
ה-`retention` שומר על `/srv/netsec` חסום, אז הדיסק לעולם לא
יזלוג לנכס בתשלום.

כל ספק אחר (‏AWS, ‏Azure, ‏Hetzner, ‏Pi 5 שמוריצים בעצמכם, ‏NAS ביתי)
עובד באותה דרך ברגע ש-Docker + Tailscale + chrony מותקנים.

התחברות ב-SSH עם:

```bash
ssh -i <path-to-your-ssh-key> ubuntu@<vm-public-ip>
```

---

## תאימות ARM64

ה-Always Free VM הוא aarch64, לא x86-64. הסיכון העיקרי בכניסה היה
ש-`worker` ו-`ingest_api` מתקינים את `requirements.txt` של הפרויקט
בתוך ה-image, ו-wheel חסר אומר קומפילציה של ספריות נומריות ממקור
(איטי ורעב ל-RAM על 4 ליבות).

זה לא נושא. כל תלות pinned מפרסמת wheel של manylinux aarch64:

| חבילה | wheel |
|---|---|
| `numpy==2.4.6` | `manylinux_2_27_aarch64` |
| `pandas==3.0.3` | `manylinux_2_24_aarch64` |
| `scikit-learn==1.9.0` | `manylinux_2_27_aarch64` |
| `scipy==1.17.1` | `manylinux_2_27_aarch64` |
| `torch==2.12.1` | `manylinux_2_28_aarch64` |
| `fastapi==0.115.6` / `uvicorn==0.32.1` / `httpx==0.28.1` | pure-python |

רק `manuf==1.1.5` הוא ממקור בלבד, והוא Python טהור שבונה תוך שניות
מול ה-`gcc` שכבר נוכח ב-image של ה-builder. ‏WeasyPrint (מותקן בתוך
`Dockerfile.worker`) יש לו wheels של aarch64 בנויים מראש דרך חבילות
apt של ‏`libpango`/`libcairo` שה-Dockerfile מושך.

לבדוק מחדש אחרי bump של תלות, בלי להתקין כלום:

```bash
docker run --rm -v $PWD/requirements.txt:/req.txt python:3.11-slim \
  bash -c "pip install --dry-run --only-binary=:all: -r /req.txt"
```

`n8nio/n8n:latest` מפרסם image native של arm64, אז הוא לא צריך
טיפול מיוחד.

---

## מודל רשת: Tailscale בלבד

אף אחד מארבעת השירותים לא נחשף לאינטרנט. הפורט היחיד שנגיש
על ה-IP הציבורי הוא 22.

```
המחשב הנייד שלכם  ──(Tailscale, WireGuard)──►  vm
<laptop-tailscale-ip>                     <vm-tailscale-ip>:5678  n8n
                                          <vm-tailscale-ip>:8766  ingest_api

האינטרנט ────────────────────────►    <vm-public-ip>:22    ‏SSH בלבד
                                          <vm-public-ip>:5678  אין listener
                                          <vm-public-ip>:8766  אין listener
```

‏`worker` ו-`retention` לא מפרסמים פורטים בכלל - הם צורכים את תור
ה-DB ואת מערכת הקבצים.

שלושה דברים נדרשים כדי שזה יחזיק, והיעדר אחד מהם שובר את זה בשקט.

### 1. קשירת הפורטים המפורסמים ל-IP של Tailscale

`deploy/docker-compose.yml` כבר קושר כל פורט ל-`${TS_BIND}`:

```yaml
services:
  n8n:
    ports:
      - "${TS_BIND:-127.0.0.1}:5678:5678"
  ingest_api:
    ports:
      - "${TS_BIND:-127.0.0.1}:8766:8766"
```

הגדירו `TS_BIND` ב-`deploy/.env` ל-IP של Tailscale של ה-VM.
ברירת המחדל של loopback היא בכוונה - `.env` שגוי נכשל סגור, קושר
רק ל-`127.0.0.1` במקום לכל מקום.

### 2. לתת לתעבורת Tailscale לעבור את ה-firewall המקומי

ה-image של Ubuntu של Oracle נשלח עם שרשרת INPUT של `iptables`
שמסתיימת ב-REJECT catch-all, אז פקטות שמגיעות ב-`tailscale0`
מופלות למרות שה-interface עצמו למעלה. הכניסו את החריגים לפני
ה-REJECT הזה והשרו אותם:

```bash
sudo iptables -I INPUT 5 -i tailscale0 -j ACCEPT
sudo iptables -I INPUT 5 -p udp --dport 41641 -j ACCEPT
sudo apt-get install -y iptables-persistent
sudo netfilter-persistent save
```

UDP 41641 מאפשר ל-Tailscale להקים חיבור peer ישיר. בלעדיו ה-tunnel
עדיין עובד, אבל כל פקטה מועברת דרך שרת DERP - התנהגות נכונה,
latency גבוה יותר.

שימו לב ש-`-I INPUT 5` שביר: המיקום המדויק תלוי בכמה חוקים ה-image
כבר נשלח איתם. אמתו את השרשרת שנוצרה עם
`sudo iptables -L INPUT --line-numbers` והתאימו את המיקום כך שה-ACCEPTs
יישבו *לפני* ה-REJECT בסוף.

### 3. השאירו את Security List של Oracle בשקט

ה-security list ברירת המחדל של ה-VCN מאפשר רק ingress על 22. אל
תפתחו 5678 או 8766 שם. הפורטים המפורסמים של Docker עוקפים את
שרשרת INPUT דרך DNAT, אז החוק ברמת הענן הוא רשת הביטחון שחשובה
אם ה-bind בצעד 1 פעם יהיה שגוי.

אמתו שני הכיוונים אחרי כל שינוי:

```bash
# IP של Tailscale - עונה
curl -s -o /dev/null -w "%{http_code}\n" http://<vm-tailscale-ip>:5678/
curl -s -o /dev/null -w "%{http_code}\n" http://<vm-tailscale-ip>:8766/healthz

# IP ציבורי - חייב להיות ריק / connection refused / timeout
curl -s -o /dev/null -w "%{http_code}\n" http://<vm-public-ip>:5678/
curl -s -o /dev/null -w "%{http_code}\n" http://<vm-public-ip>:8766/healthz
```

ה-curl ל-IP הציבורי אמור להדפיס `000` (אין תשובה). אם הוא מחזיר
קוד HTTP כלשהו, חזרו לצעד 1.

---

## פריסה מאפס

מניח instance טרי של Always Free ARM שמריץ Ubuntu 22.04+.

### 1. Docker

```bash
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=arm64 signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER
sudo systemctl enable --now docker
```

`systemctl enable` בתוספת `restart: unless-stopped` שהוגדר על כל
שירות ב-`deploy/docker-compose.yml` אומר שהמערך חוזר בעצמו אחרי
reboot. אין שום דבר נוסף להריץ ב-boot.

יש race אחד ששווה להזכיר: ‏`${TS_BIND}` היא כתובת `tailscale0`,
אז Docker יכול להתחיל לפני ש-`tailscaled` מקצה את ה-IP ולא לקשור
בהצלחה. ‏`restart: unless-stopped` מנסה שוב עם backoff, אז זה
מתכנס; הוסיפו drop-in של `After=tailscaled.service` לשירות docker
אם ההשהיה חשובה:

```bash
sudo mkdir -p /etc/systemd/system/docker.service.d
sudo tee /etc/systemd/system/docker.service.d/tailscale.conf <<'EOF'
[Unit]
After=tailscaled.service
Requires=tailscaled.service
EOF
sudo systemctl daemon-reload
```

### 2. Tailscale + chrony

```bash
curl -fsSL https://tailscale.com/install.sh | sudo sh
sudo tailscale up --hostname=<vm-hostname>
sudo apt-get install -y chrony        # ‏NTP - נדרש ל-anti-replay של HMAC
```

ואז יישמו את חוקי ה-firewall מהסקשן למעלה.

### 3. הפרויקט

‏Clone של ה-fork (כל ה-deployment נשלח בריפו עכשיו - אין משהו נוסף
להעתיק):

```bash
git clone <your-fork>
cd <repo>/deploy
cp .env.example .env
# ערכו את .env - לפחות TS_BIND (ה-IP של Tailscale שלכם) ו-
# N8N_ENCRYPTION_KEY. כל משתנה אחר נשלח עם ברירת מחדל עובדת
# מהקוד.
```

הכינו את שורש הנתונים פעם אחת:

```bash
sudo mkdir -p /srv/netsec
sudo chown $USER /srv/netsec
```

### 4. העלאה

```bash
docker compose up -d
```

ההפעלה הראשונה לוקחת 2-6 דק' בזמן ש-Docker בונה את ה-images של
`ingest_api` ו-`worker` ומושך את `n8nio/n8n:latest`. הפעלות מחדש
עוקבות הן שניות. אשרו עם:

```bash
docker compose ps            # ארבעה שירותים Up
curl -s http://<vm-tailscale-ip>:8766/healthz   # {"status":"ok","schema":<n>}
```

### 5. רישום sensor

כל מעלה צריך סוד HMAC משלו. ‏`deploy/create_sensor.py` כותב לתוך
ה-DB שה-containers יצרו, אז הריצו אותו תחת אותו משתמש שבעלים של
`/srv/netsec` (או דרך `sudo` עם אותו `NETSEC_DATA_ROOT`):

```bash
# מ-deploy/
sudo NETSEC_DATA_ROOT=/srv/netsec python3 create_sensor.py laptop
# משורש הריפו, אותו helper הוא:
sudo NETSEC_DATA_ROOT=/srv/netsec python3 deploy/create_sensor.py laptop
```

העתיקו את שלוש השורות המודפסות
(`NETSEC_SENSOR_ID`, `NETSEC_SENSOR_SECRET`, `NETSEC_API_TOKEN`)
לסביבה של כל מכונה שתעלה.

אוטוריזציה בין sensors נאכפת: ‏bearer טוקנים יכול לקרוא רק את
ה-sessions והדוחות שלו. הגדירו `NETSEC_ADMIN_SENSOR=<name>` אם
אתם רוצים שה-טוקנים של sensor אחד יקרא sessions של כל sensor
(טיפוסי לחשבון דשבורד מרכזי).

---

## ייבוא ה-תהליך עבודה התרעת n8n

שני נתיבים, שניהם עובדים. התבנית נשלחת כ-volume mounted ב-
`/workflows` בתוך container ה-n8n, אז ייבוא CLI לא צריך העתקת קובץ:

```bash
docker compose exec n8n n8n import:workflow \
  --input=/workflows/mvp_triage_email.json
docker compose exec n8n n8n list:workflow
```

או דרך ה-UI: פתחו `http://<vm-tailscale-ip>:5678/`, צרו חשבון owner
(הביקור הראשון דורש זאת - שמרו את האישור הזה בטוח; `N8N_BASIC_AUTH_*`
אינו נתמך ב-n8n מודרני), ואז **‏Workflows** → **⋮** → **‏Import
from File** → `deploy/n8n_workflows/mvp_triage_email.json`.

ה-תהליך עבודה מיובא **‏inactive**. פתחו אותו, לחצו על node ‏**Send Email
Alert**, צרפו אישור SMTP (ראו את הסעיף הבא), הגדירו את כתובות
from/to, ואז הפעילו **‏Active** (ימין למעלה).

העתיקו את **‏Production URL** של node ‏*Worker Webhook*
(`http://<vm-ip>:5678/webhook/netsec-alert`) ל-`N8N_WEBHOOK_URL` ב-
`deploy/.env`, ואז `docker compose restart worker`.

---

## אישורים

גרסאות n8n מודרניות מתעלמות מ-`N8N_BASIC_AUTH_ACTIVE` וחברים.
הביקור הראשון ב-`http://<vm-tailscale-ip>:5678` דורש חשבון owner
במקום. צרו אותו שם; למשתני הסביבה בקובץ compose אין השפעה.

את אישור ה-SMTP ניתן להזין שוב ידנית
(ראו ‏`AUTOMATION_QUICKSTART.md` לערכי השדות), או להעביר מ-instance
קיים של n8n. ההגירה עובדת רק כי שתי ה-instances קוראות את אותו
`N8N_ENCRYPTION_KEY` מאותו `.env` שהועתק - ‏n8n מצפין אישורים
במנוחה עם המפתח הזה, אז ייצוא מאחד מתייבא נקי לשני בלי לפענח את
הסוד:

```bash
# ב-instance המקור
docker compose exec n8n \
  n8n export:credentials --all --output=/tmp/creds.json
docker compose cp n8n:/tmp/creds.json ./creds.json

# ביעד
docker compose cp ./creds.json n8n:/tmp/creds.json
docker compose exec n8n \
  n8n import:credentials --input=/tmp/creds.json
```

מחקו את `creds.json` הביניים אחר כך. הוא מוצפן, לא בטקסט פתוח,
אבל זה עדיין קובץ אישור שיושב בדיסק.

**אם `N8N_ENCRYPTION_KEY` שונה בין שתי ה-instances, הייבוא מצליח
והאישור בלתי שמיש.** ‏n8n לא מזהיר על זה.

---

## כפתור הדשבורד מעלה ל-VM

הדשבורד רץ על המכונה שלכם, אבל הוא כבר לא צריך daemon של Docker
מקומי לשום דבר. הכפתור **‏Send S1 to VM (mail report)** חותם על
PCAP של ה-session ומזרים אותו ל-API הקליטה מעל Tailscale - אותו
נתיב חתום-HMAC ש-`tools/upload_pcap.py` משתמש בו, אז אין תקרת גודל
ואין `scp` מעורב.

לצד הכפתור אתם מקלידים את הכתובת שאליה הדוח המוגמר ישלח ובוחרים
preset של פאנל LLM; שניהם רוכבים כ-headers של בקשה
(`X-Notify-Email`, `X-Judge-Panel`).

שלושה משתני סביבה שולטים ביעד. **כולם נשלחים ריקים** כברירת מחדל;
הכפתור מדווח "set NETSEC_INGEST_URL" עד שהם מוגדרים, אז fork
טרי לא יכול בשקט להעלות ל-VM של מישהו אחר (`deploy/.env.example`
מתעד אותם):

| משתנה | ערך לדוגמה |
|---|---|
| `NETSEC_INGEST_URL` | `http://<vm-tailscale-ip>:8766` |
| `NETSEC_SENSOR_ID` | `laptop` (מ-`deploy/create_sensor.py`) |
| `NETSEC_SENSOR_SECRET` | הסוד שאותו הסקריפט הדפיס פעם אחת |

ל-capture שה-VM כבר ניתח יש dedup לפי SHA-256: ההעלאה מחזירה את
ה-session הקיים במקום להכניס את אותה עבודה לתור פעמיים, והכפתור
אומר זאת במקום לרמוז לריצה טרייה.

אותה העלאה מ-shell, למכונה בלי notebook:

```bash
python3 tools/upload_pcap.py capture.pcapng --email you@example.com
```

שני המסלולים נוחתים ב-API הקליטה - חתום-HMAC, ‏streaming, בלי תקרת
גודל, מנותח אוטומטית בהגעה:

```bash
python3 tools/upload_pcap.py capture.pcapng
```

נתיב ה-scp קיים כי הוא עובד על כל OS בלי תלויות מעבר ל-ssh, וכי
הוא ממפה נקי לעידן של desktop מקומי. נתיב ה-HTTP הוא מה שסוכן
ה-sensor משתמש בו בפרודקשן.

**שום דבר מהניתוח כבר לא רץ מקומית** בנתיב הכפתור. הצינור, המודלים,
וכל קריאת LLM קורים ב-VM. ‏Docker Desktop יכול להישאר סגור, או
להסרה.

---

## אימות נתיב ה-LLM, לא ה-cache

`llm_judge/cache/judge_cache.sqlite` ממופתח לפי פיצ'רי מועמד,
גרסת prompt ומזהה מודל - לא לפי שם קובץ PCAP. ‏cache שהועתק
ממכונה אחרת יענה עבור PCAPs שאותה מכונה מעולם לא ניתחה. בפריסות
קודמות, שתי ריצות בדיקה "מוצלחות" רצופות החזירו `cache_hits: N`
ולא ביצעו קריאת API בכלל.

כל בדיקה שאמורה להוכיח שהספק עובד חייבת להזיז את ה-cache הצידה
קודם:

```bash
mv <repo>/llm_judge/cache/judge_cache.sqlite /tmp/
# הריצו PCAP אחד דרך ה-CLI (או העלו אחד וקראו /v1/reports/N.json)
python3 llm_judge/judge_cli.py capture.pcap \
  --output /tmp/verdicts.json --markdown /tmp/verdicts.md
grep '"cache_hits"' /tmp/verdicts.json                 # מצפים ל-"cache_hits": 0
mv /tmp/judge_cache.sqlite <repo>/llm_judge/cache/
```

ריצה חיה אמיתית מדווחת `"cache_hits": 0`. זה חל גם על כל benchmark
עתידי של latency, עלות טוקנים או איכות שופט - עם ה-cache במקום
אתם מודדים SQLite.

ה-תהליך עבודה ‏`analyze-pcap.yml` של GitHub Actions שנגרס עשה את זה
נכון בחינם (כל ריצה התחילה על runner טרי בלי cache); הוא נגרס
לטובת צינור ה-VM כנתיב האוטונומי.

---

## פתרון בעיות

| סימן | סיבה |
|---|---|
| `address already in use` ב-`docker compose up` | תהליך אחר (או מערך compose ישן) כבר קושר `${TS_BIND}:5678` או `:8766`. `sudo lsof -i :5678` כדי למצוא. |
| ‏n8n לא נגיש מעל Tailscale, ‏SSH בסדר | חוק ACCEPT של `tailscale0` חסר או אבד אחרי reboot (‏`netfilter-persistent save` לא רץ) |
| `docker compose up -d` נכשל רק מיד אחרי reboot | `${TS_BIND}` עדיין לא הוקצה - ‏Tailscale לא סיים להתחיל. `restart: unless-stopped` מכסה; drop-in של `After=tailscaled.service` לעיל נמנע מהרעש. |
| `NOT NULL constraint failed: workflow_entity.id` | שימוש בייבוא של גרסת n8n ישנה; ה-תהליך עבודה שנשלח כולל `id` מפורש. אם ערכתם אותו, הוסיפו אחד. |
| אישור מתייבא אבל ה-node עדיין נותן שגיאה | `N8N_ENCRYPTION_KEY` שונה בין מקור ליעד |
| ‏Verdicts חוזרים מידית עם `cache_hits` > 0 | ‏`judge_cache.sqlite` שהועתק או ישן; הזיזו הצידה |
| ‏Prompt של basic auth לעולם לא מופיע | צפוי - ‏n8n מודרני משתמש בחשבונות owner, לא ב-`N8N_BASIC_AUTH_*` |
| `sqlite3.OperationalError: unable to open database file` מ-`create_sensor.py` | `db/netsec.db` בבעלות המשתמש של ה-container; הריצו עם `sudo` ו-`NETSEC_DATA_ROOT` מתאים |
| לדוחות אין שדה `.pdf` אבל `.html` עובד | ‏WeasyPrint נכשל בייבוא ב-image של `worker`; בדקו `docker compose logs worker` לשגיאה הספציפית של ספריית מערכת (`libpango` / `libcairo`) |

</div>
