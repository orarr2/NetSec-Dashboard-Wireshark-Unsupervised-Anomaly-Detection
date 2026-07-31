# מדריך העלאת VM חדש - מ-Ubuntu טרי ל-NetSec Analyzer פעיל

מסמך זה מסביר איך להרים מ-**אפס** מכונה וירטואלית חדשה שתריץ את
מערכת ה-NetSec, אם ה-VM הנוכחי נופל, אם רוצים להעביר לספק ענן אחר,
או אם רוצים למסור למישהו את המרשם.

יש **שני מסלולים**:

- **מסלול אוטומטי** - סקריפט אחד (`bootstrap.sh`) שעושה הכל, ~10-25
  דקות תלוי בקצב ה-network של הספק. מומלץ אם המכונה היא Ubuntu 22.04+.
- **מסלול ידני** - כל שלב בנפרד, מוסבר לעומק. מומלץ אם משהו נכשל
  במסלול האוטומטי, או אם המכונה היא distribution אחר (‏CentOS, Debian
  ישן וכו').

---

## תוכן העניינים

1. [מה תזדקק לו לפני שמתחילים](#1-מה-תזדקק-לו-לפני-שמתחילים)
2. [מסלול אוטומטי - `bootstrap.sh`](#2-מסלול-אוטומטי---bootstrapsh)
3. [מסלול ידני - שלב אחר שלב](#3-מסלול-ידני---שלב-אחר-שלב)
4. [הגדרות ספק-ספציפיות](#4-הגדרות-ספק-ספציפיות)
5. [בדיקות פוסט-התקנה](#5-בדיקות-פוסט-התקנה)
6. [Troubleshooting](#6-troubleshooting)
7. [שחזור מ-VM ישן שנפל](#7-שחזור-מ-vm-ישן-שנפל)

---

## 1. מה תזדקק לו לפני שמתחילים

### VM טרי

| דרישה | פירוט |
|---|---|
| מערכת הפעלה | Ubuntu 22.04 LTS ומעלה, x86_64 או ARM64 |
| RAM | 8 GB מינימום (‏24 GB מומלץ, במיוחד עם Ollama) |
| דיסק | 40 GB מינימום, 80 GB+ מומלץ |
| רוחב פס | לא קריטי - הזרימה קטנה יחסית (‏PCAPs 10-100 MB) |
| שער SSH | פורט 22 חייב להיות פתוח בחומת האש של הספק |
| משתמש | משתמש `sudo` (‏לא צריך root ישיר) |

### שירותים חיצוניים חינמיים

- **חשבון Tailscale** ‏(‏[tailscale.com](https://tailscale.com)) - חינם עד
  100 מכשירים. השירות מייצר רשת פרטית מוצפנת בין המחשבים שלך.
- **מפתח Groq API** ‏(‏[console.groq.com/keys](https://console.groq.com/keys)) - חינם
  עם 100k tokens/day per model. נדרש אם רוצים לרוץ בLLM Judge.
- **חשבון Gmail** - אופציונלי, לשליחת דוחות. דורש
  [app password](https://myaccount.google.com/apppasswords) בן 16 תווים.

### עצות לבחירת ספק חינם (‏אם אין לך VM עדיין)

| ספק | תוכנית חינם | הערות |
|---|---|---|
| **Oracle Cloud** | 4 OCPU ARM + 24 GB RAM + 100 GB דיסק, **לתמיד** | הכי נדיב. הגישה קשה - הרשמה דורשת כרטיס אשראי לאישור, ולפעמים לוקח שבועות עד שיאשרו לך VM ARM. **המומלץ.** |
| Hetzner | ~€4/חודש ל-CX22 | 4 GB RAM, לא חינם אבל זול |
| DigitalOcean | $200 credit ל-60 יום, אז $6/חודש | נוח, אבל מוגבל בזמן |
| AWS EC2 | t3.micro חינם לשנה | 1 GB RAM - לא מספיק לנו |

---

## 2. מסלול אוטומטי - `bootstrap.sh`

### תרחיש הבסיסי

1. התחבר ל-VM חדש שלך ב-SSH:
   ```bash
   ssh ubuntu@<your-vm-ip>
   ```

2. הרץ את הסקריפט ישירות מ-GitHub ‏(‏clone לא-פעיל בשלב זה):
   ```bash
   curl -fsSL https://raw.githubusercontent.com/orarr2/NetSec-Dashboard-Wireshark-Unsupervised-Anomaly-Detection/main/deploy/bootstrap.sh | bash
   ```

3. הסקריפט **מתקין וברור מה קורה בכל שלב**. הוא ידרוש התערבות שלך
   רק ב-**Tailscale login** (‏אם עדיין לא עשית):

   הסקריפט יעצור עם הודעה כזו:
   > Tailscale is installed but not logged in
   > run this and re-run the script:
   >   `sudo tailscale up --hostname=netsec-agent`

   בצע את הפקודה - היא תדפיס URL, פתח אותו בדפדפן שלך, אשר את
   ההצטרפות לתיקנטה שלך, ואז הרץ מחדש את bootstrap:
   ```bash
   sudo bash ~/netsec/deploy/bootstrap.sh
   ```

4. הסקריפט ישאל אותך על מפתחות ‏(‏Groq, Gmail app-password) - אתה יכול
   ללחוץ Enter כדי להשאיר ריק ולמלא מאוחר יותר ב-`~/netsec/deploy/.env`.

5. בסוף הסקריפט תראה **credentials של sensor שיצר** - שמור אותם! זה
   מוצג פעם אחת בלבד:
   ```
   NETSEC_SENSOR_ID=laptop
   NETSEC_SENSOR_SECRET=e23f8c...
   NETSEC_API_TOKEN=lM9obV...
   ```

6. סופר-מהיר: בקש healthz מהמכונה:
   ```bash
   curl http://<tailscale-ip>:8766/healthz
   ```
   צריך להחזיר `{"status":"ok","schema":4}`.

### תרחיש אוטומטי-לגמרי (‏CI, unattended)

אם רוצים סקריפט שלא ידרוש שום התערבות:

```bash
export TAILSCALE_AUTHKEY="tskey-auth-..."   # מ-login.tailscale.com/admin/settings/keys
export TAILSCALE_HOSTNAME="netsec-agent"
export NETSEC_SENSOR_NAME="laptop"

curl -fsSL https://raw.githubusercontent.com/orarr2/NetSec-Dashboard-Wireshark-Unsupervised-Anomaly-Detection/main/deploy/bootstrap.sh | bash
```

הסקריפט יעשה tailscale up אוטומטית, יזלג על שאלות אינטראקטיביות, ויסיים.

### מה הסקריפט עושה בדיוק (‏מה שאתה בעצם רואה)

1. **apt install** - חבילות בסיס: `curl git jq chrony netfilter-persistent iptables-persistent`
2. **Docker Engine + Compose plugin** - דרך הסקריפט הרשמי `get.docker.com`
3. **Tailscale** - התקנה + `tailscale up` (עם auth key או אינטראקטיבית)
4. **git clone** של הריפו ל-`~/netsec/`
5. **`.env`** - מייצר מ-`.env.example` עם `TS_BIND` = כתובת ה-Tailscale
   של ה-VM, ‏`NETSEC_ENCRYPTION_KEY` אקראית, ומבקש (אופציונלי) מפתחות.
6. **iptables** - כותב את הכללים ל-`/etc/iptables/rules.v4` (רק SSH+Tailscale),
   מפעיל `netfilter-persistent` כדי שהם יחזרו אחרי reboot.
7. **`docker compose build`** - בונה את ה-images של `worker` ו-`ingest_api`
   (‏PyTorch, tshark, וכו' - ~15 דק' על ARM). קפה טוב.
8. **`docker compose up -d`** - מרים את `ingest_api`, `worker`, `retention`.
9. **`create_sensor.py`** - יוצר sensor ראשון עם שם `laptop` ומדפיס credentials.
10. **בדיקת healthz** - מוודא ש-`http://<tailscale-ip>:8766/healthz` עונה.

---

## 3. מסלול ידני - שלב אחר שלב

אם הסקריפט האוטומטי נכשל, או שאתה על distribution שאינו Ubuntu/Debian,
או שאתה רוצה להבין בדיוק מה קורה. כל שלב מוסבר מדוע.

### שלב 1: הגדרות מערכת בסיסיות

```bash
sudo apt update
sudo apt install -y curl git jq chrony netfilter-persistent iptables-persistent
sudo systemctl enable --now chrony
```

**למה chrony?** ‏NTP - סנכרון שעון. ה-ingest API בודק שה-timestamp בבקשת
ההעלאה נמצא בטווח ±5 דקות מהשעה של ה-VM (‏מנגנון אנטי-replay). בלי
chrony, ה-VM עלול לצבור סטייה של דקות ובקשות תקינות יידחו.

### שלב 2: Docker Engine + Compose plugin

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo apt install -y docker-compose-plugin
sudo usermod -aG docker $USER
# תצא ותחזור ל-SSH כדי לרשום את ה-group החדש (או `newgrp docker`)
```

**בדיקה:**
```bash
docker --version         # אמור להיות 24.0+
docker compose version   # אמור להיות v2.20+
```

### שלב 3: Tailscale

```bash
curl -fsSL https://tailscale.com/install.sh | sudo sh
sudo tailscale up --hostname=netsec-agent
```

הפקודה תדפיס URL. פתח בדפדפן שלך (‏על מחשב אחר בו אתה מחובר ל-Tailscale
account שלך) → אשר. ה-VM יופיע ברשימת המכשירים ב-`login.tailscale.com`.

**בדיקה:**
```bash
tailscale status         # אמור להראות את ה-VM כ-"active"
tailscale ip -4          # אמור להחזיר 100.x.x.x
```

**שמור את הכתובת** - נשתמש בה כ-`TS_BIND` בהמשך.

### שלב 4: הורדת הריפו

```bash
git clone --depth 1 https://github.com/orarr2/NetSec-Dashboard-Wireshark-Unsupervised-Anomaly-Detection.git ~/netsec
cd ~/netsec/deploy
cp .env.example .env
```

### שלב 5: `.env` - מילוי משתני סביבה

ערוך את `.env`:

```bash
nano ~/netsec/deploy/.env
```

**חובה למלא:**

| משתנה | ערך | הערה |
|---|---|---|
| `TS_BIND` | הכתובת מ-`tailscale ip -4` (‏למשל `100.68.246.54`) | כתובת ה-Tailscale של ה-VM |
| `NETSEC_DATA_ROOT` | `/srv/netsec` | ‏(‏ברירת מחדל) |
| `NETSEC_INFRA_DSTS` | הכתובת מ-`tailscale ip -4` (‏אותה) | לזיהוי תעבורת המערכת עצמה |
| `N8N_ENCRYPTION_KEY` | ‏32 בייטים random hex, למשל `openssl rand -hex 32` | אפילו אם לא משתמשים ב-n8n, ה-container דורש את זה |

**מומלץ למלא (‏אם רוצים LLM Judge):**

| משתנה | ערך | ‏מאיפה מקבלים |
|---|---|---|
| `GROQ_API_KEY` | `gsk_...` | ‏[console.groq.com/keys](https://console.groq.com/keys) - חינם |
| `OPENAI_COMPAT_API_KEY` | אותו ערך כמו `GROQ_API_KEY` | הצינור משתמש בזה בפועל |
| `LLM_JUDGE_PANEL` | `openai_compat:llama-3.1-8b-instant,openai_compat:openai/gpt-oss-20b` | פאנל של 2 שופטים מוכחים |

**אופציונלי (‏אם רוצים מייל):**

| משתנה | ערך |
|---|---|
| `SMTP_USER` | כתובת ה-Gmail שלך |
| `SMTP_PASS` | app password של 16 תווים מ-[myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords) |
| `SMTP_FROM` | ‏(‏אופציונלי) `"Your Name <you@gmail.com>"` |

### שלב 6: iptables - חומת אש

השלב הכי חשוב מבחינת אבטחה. אנחנו מגדירים שרק SSH ‏(פורט 22) יכול להיכנס
מהאינטרנט הפתוח, וכל שאר השירותים יגיעו רק מ-Tailscale.

```bash
sudo nano /etc/iptables/rules.v4
```

תוכן:
```
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
-A INPUT -p udp -m udp --dport 41641 -j ACCEPT
-A INPUT -i tailscale0 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp-host-prohibited
COMMIT
```

הסבר של כל שורה:
- `RELATED,ESTABLISHED ACCEPT` - תעבורת חזרה (‏למשל תגובה של Google לבקשה
  שלנו) מותרת
- `icmp ACCEPT` - `ping` וכו' מותר (‏שגרתי)
- `lo ACCEPT` - loopback (‏שירות שלנו מדבר עם עצמו) מותר
- `dport 22` - SSH מותר מכל מקום (‏מוגן על ידי מפתח פרטי)
- `dport 41641` - הפורט של Tailscale (‏WireGuard) - חובה כדי להיות חלק
  מהתיקנטה
- `tailscale0` - כל תעבורה מהinterface של Tailscale מותרת
- `REJECT` - כל השאר נדחה עם הודעת "prohibited"

הפעלה:
```bash
sudo netfilter-persistent reload
sudo systemctl enable netfilter-persistent
```

**בדיקה:**
```bash
sudo iptables -L INPUT -n --line-numbers
# צריך להראות 8 שורות: 6 accept + reject
```

### שלב 7: הכנת תיקיות נתונים

```bash
sudo mkdir -p /srv/netsec/{data,db,reports,spool}
sudo chown -R $USER:$USER /srv/netsec
```

### שלב 8: בניית ה-images

```bash
cd ~/netsec/deploy
docker compose build ingest_api worker retention
```

זה הצעד הכי ארוך - **~15-25 דקות** בהתקנה ראשונה כי צריך להוריד PyTorch,
tshark, ו-Python packages. Docker cache-ing יעשה שריצות עתידיות יהיו מהירות.

### שלב 9: הפעלת ה-services

```bash
docker compose up -d ingest_api worker retention
```

**בדיקה:**
```bash
docker compose ps
# צריך להראות שלושה שירותים כ-Up
```

### שלב 10: יצירת sensor ראשון

```bash
cd ~/netsec/deploy
sudo NETSEC_DATA_ROOT=/srv/netsec python3 create_sensor.py laptop
```

הפקודה מדפיסה 3 שורות **פעם אחת בלבד**:
```
NETSEC_SENSOR_ID=laptop
NETSEC_SENSOR_SECRET=<64 chars>
NETSEC_API_TOKEN=<43 chars>
```

**שמור אותן!** אם אבדת - חייבים ליצור sensor חדש (‏עם שם אחר) ולעדכן את
הלקוחות. אין דרך לשלוף את הסוד מ-DB.

### שלב 11: בדיקת שהכל עובד

```bash
curl http://$(tailscale ip -4 | head -1):8766/healthz
# צריך להחזיר {"status":"ok","schema":4}
```

הרם לוגים:
```bash
docker compose logs -f worker
# צריך לראות: [worker] polling every 10s (db=/srv/netsec/db/netsec.db)
# לחץ Ctrl+C לצאת
```

**הצלחת!** ה-VM מוכן לקבל PCAP-ים. חזור ל-[docs/VM_OPS.md](VM_OPS.md)
לפקודות יומיומיות.

---

## 4. הגדרות ספק-ספציפיות

### Oracle Cloud

- **Security List** של ה-VCN (‏Virtual Cloud Network): ‏Oracle **חוסמת
  כל תעבורה נכנסת חוץ מ-SSH** ברירת מחדל. וודא שלא הוספת כללים שפותחים
  יותר - אנחנו רוצים בדיוק את זה.
- **תמונת אתחול**: בחר "Canonical Ubuntu 22.04" (‏Minimal). לא Oracle
  Linux.
- **Shape**: "VM.Standard.A1.Flex" (‏ARM Ampere), 4 OCPU, 24 GB RAM.
  זה הfree tier ‏[הנדיב.
- **SSH key**: הורד את המפתח בסוף היצירה - יורד כתיקייה על Windows,
  לא כקובץ. השתמש בקובץ `.pem` שבתוכה.

### AWS EC2

- **Security Group**: הכן חוק שמתיר רק SSH (‏TCP 22) inbound. אל תפתח
  שום פורט אחר - אנחנו לא חושפים כלום ל-internet.
- **תמונת AMI**: "Ubuntu Server 22.04 LTS" (‏HVM, SSD).
- **Instance type**: לצורך זה, `t3.medium` (‏2 vCPU, 4 GB) מספיק ל-ingest+worker.
  לא מספיק ל-Ollama.
- **Elastic IP**: אופציונלי - Tailscale לא צריך IP חיצוני. חסוך עלות אם
  אין קליינטים חיצוניים.

### Hetzner

- **Firewall**: יש UI נוח. חוק אחד: TCP 22 inbound מ-anywhere. סגור הכל
  השאר.
- **תמונת שרת**: "Ubuntu 22.04".
- **Shape**: CX22 (~€4/חודש, 2 vCPU, 4 GB) - זול, מספיק ל-ingest+worker.

### DigitalOcean

- **Firewall (Cloud Firewalls)**: allow SSH (TCP 22). Block everything
  else inbound.
- **Droplet**: Basic Regular, 2 vCPU / 4 GB / 80 GB SSD (~$24/month).

### Home server (Proxmox / bare metal)

- **Port forwarding on your router**: SSH (22) if you want external
  access, otherwise skip (Tailscale gives you access from anywhere).
- Otherwise identical to Ubuntu install.

---

## 5. בדיקות פוסט-התקנה

### 1. Tailscale-only exposure

```bash
sudo ss -tlnp | grep -v "127.0.0" | grep -v "$(tailscale ip -4 | head -1)"
```

אמור להראות **רק** את פורט 22 (SSH). אם יש עוד משהו על 0.0.0.0 - בעיה.

### 2. iptables שורד reboot

```bash
sudo iptables -L INPUT -n | wc -l
# 8 שורות (headers + 6 accept + 1 reject)
sudo reboot
# חזור אחרי דקה
ssh ...
sudo iptables -L INPUT -n | wc -l
# עדיין 8 שורות - shrivived
```

### 3. Ingest API עובד

```bash
curl -sS http://$(tailscale ip -4 | head -1):8766/healthz
# {"status":"ok","schema":4}
```

### 4. Worker פועל

```bash
cd ~/netsec/deploy
docker compose logs --tail=5 worker
# צריך להראות "polling every 10s"
```

### 5. End-to-end upload

מהלפטופ שלך (‏אחרי ‏Tailscale up):

```bash
export NETSEC_INGEST_URL="http://<vm-tailscale-ip>:8766"
export NETSEC_SENSOR_ID="laptop"
export NETSEC_SENSOR_SECRET="<the secret from create_sensor>"

python3 tools/upload_pcap.py attack_tests/pcaps/arpspoof.pcap
# אמור להדפיס: session_id=1
```

צפה בעבודה:
```bash
ssh ubuntu@<vm> 'cd ~/netsec/deploy && docker compose logs -f worker'
# אמור לראות "[worker] session 1 done (10 verdicts)" תוך 2-4 דקות
```

---

## 6. Troubleshooting

### הסקריפט נפל בשלב Docker

```bash
sudo systemctl status docker
# אם "inactive" - `sudo systemctl start docker`
```

### `curl /healthz` timeout

```bash
tailscale status
# האם הלפטופ מחובר?
sudo iptables -L INPUT -n | grep 8766
# אין שם כלום? זה בסדר - הפורט לא צריך ipt-rule כי הוא נכנס דרך tailscale0
sudo ss -tlnp | grep 8766
# אמור להראות 100.x.x.x:8766, לא 0.0.0.0:8766
```

### שגיאת "cannot connect to Docker daemon"

```bash
groups
# האם יש 'docker' בפלט?
# אם לא - הוסף: `sudo usermod -aG docker $USER`, ואז logout+login
```

### `docker compose build` נכשל עם "no space left"

```bash
df -h /
# אם >90% - נקה: `docker system prune -a --volumes -f`
```

### Sensor lost secret

חייבים ליצור sensor חדש עם שם אחר:
```bash
cd ~/netsec/deploy
sudo NETSEC_DATA_ROOT=/srv/netsec python3 create_sensor.py laptop-v2
# עדכן את הלקוחות עם ה-credentials החדשים
```

הסנסור הישן נשאר ב-DB אבל לא יעבוד. אפשר לנטרל אותו:
```bash
docker compose exec -T ingest_api python3 -c "
from server import db
c = db.connect()
c.execute('UPDATE sensors SET revoked_at=DATETIME(\"now\") WHERE name=?', ('laptop',))
c.commit()
"
```

---

## 7. שחזור מ-VM ישן שנפל

אם ה-VM הקודם נעלם (‏Oracle סגר את הfree tier, קרש דיסק וכו'), התהליך זהה
להתקנה טרייה, עם 3 נקודות שיפור:

1. **אל תשתמש באותו שם sensor** - אם ליצרת בעבר "laptop", עכשיו קרא לו
   "laptop-v2". זה מונע בלבול בקבצים הישנים.

2. **מפתחות API - יש להשיג מחדש** ‏(אם היו לך): ‏Groq, Gemini, וכו'.
   הם אישיים ל-VM אבל הם למעשה מפתחות לחשבון שלך אצל הספק, ולכן זהים.
   פשוט העתק מ-`.env` הישן (אם יש לך גיבוי).

3. **סנכרון היסטוריית ניתוחים**: אם היה לך גיבוי של `/srv/netsec/db/netsec.db`
   מה-VM הישן:
   ```bash
   scp old-vm:/srv/netsec/db/netsec.db new-vm:/srv/netsec/db/
   sudo docker compose restart ingest_api worker
   ```
   ה-schema migration יריץ אוטומטית אם צריך.

**מה שלא תשחזר:** ה-PCAPs הגולמיים (‏מהחודש האחרון) - הם בהיקף גדול,
לא במסלול הגיבוי. אבל דוחות + verdicts + adv_signals - כן.

---

*המסמך משלים את [docs/VM_ARCHITECTURE_HE.md](VM_ARCHITECTURE_HE.md) (מה יש על
ה-VM) ו-[docs/VM_OPS.md](VM_OPS.md) (פקודות יומיומיות).*
