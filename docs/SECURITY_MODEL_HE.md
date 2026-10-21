<div dir="rtl" align="right">

# מודל האבטחה

ארבע שאלות, ארבע תשובות.

## 1. מי יכול להגיע למערך מהאינטרנט?

רק SSH (פורט 22). כל השאר קשור ל-interface של Tailscale
(`100.68.246.54`) או ל-loopback (`127.0.0.1`). חומת האש של
Oracle Cloud דוחה כל ניסיון להגיע לפורטי האפליקציה דרך
ה-interface הציבורי (אומת בסריקת פורטים חיצונית: 22 חוזר
"פתוח", ואילו 443, 5200, 8080, 5678, 8766 ו-11434 כולם
מסוננים).

## 2. מי יכול להגיע למערך דרך Tailscale?

כל מי שהמכשיר שלו מחובר לחשבון ה-Tailscale שלכם. ל-tailnet
יש כרגע:
- `netsec-agent` (ה-VM)
- `iphone-13-mini`
- `or-pc-1` (המחשב הנייד)
- `or-pc` (לא מחובר)

הוספת מכשיר מצריכה סיסמה של Tailscale + אימייל + אימות דו-שלבי,
או מפתח auth שהונפק בקונסולת ה-admin.

## 3. איזה אימות שומר על כל שירות?

| שירות | כתובת / פורט | אימות | מצב כשל |
|---|---|---|---|
| Portal | `/` על 443 | ‏Caddy basicauth (bcrypt) | 401 |
| RAG | `/rag/` על 443 | ‏Caddy basicauth (bcrypt) | 401 |
| Companion | `/chat/` על 443 | ‏Caddy basicauth (bcrypt) | 401 |
| n8n | 5678 | אימות משלו של n8n (אימייל + סיסמה) | 401 |
| העלאה ל-ingest API | 8766 | ‏HMAC-SHA256 לכל בקשה | 401 |
| בריאות ingest API | 8766 `/healthz` | ללא אימות | 200 |
| Ollama | 11434 (loopback) | ללא אימות | לא נגיש מחוץ ל-host של ה-VM |
| SSH | 22 | מפתח ציבורי בלבד, בלי סיסמאות | החיבור נופל |

## 4. מה קורה בכשלי אימות חוזרים?

**‏SSH:** ‏`sshd` מקבל רק מפתח ציבורי; ‏`PasswordAuthentication no`.
ניסיונות כוח גס נדחים מיידית (אין סיסמה לנחש). כרגע כ-5000
ניסיונות ליום מכ-100 כתובות IP שונות. המשך רצוי: לסגור את 22
ל-Tailscale בלבד (נדחה כרגע - צריך לתעד נתיב התאוששות דרך
Oracle Console לפני).

**‏Caddy basicauth:** ‏`fail2ban` עוקב ביומן ה-systemd של Caddy
אחרי `msg:"auth provider returned error"`. חמישה כשלים בתוך 10
דקות מפעילים חסימה של שעה ב-iptables לכתובת IP המקורית. ב-tailnet
זה כמעט לא נדלק (האימות נשמר לכל סבב דפדפן), אבל זה הגנה מפני חבר
tailnet שנפרץ ומנסה לפרוץ את ה-basicauth.

**‏n8n:** ל-n8n יש הגבלת קצב ונעילת חשבון משלו.

**‏HMAC של ingest API:** כל בקשה חייבת לשאת header בשם
`X-Signature`: ‏HMAC-SHA256 מעל ההודעה
`"<sha256>:<sensor>:<timestamp>"`, חתום בסוד הפרטי של החיישן
שנשמר ב-DB. חתימה שגויה מחזירה 401 בלי לרמוז לנכונה; אין מכסת
"סיסמה שגויה" כי אין סיסמה בכלל.

## מודל התעודות

התעודה שעל פורט 443 היא Let's Encrypt שהונפקה דרך Tailscale (הם
הבעלים של הדומיין `*.tail<id>.ts.net` ויש להם חשבון ACME אליו).
התעודה קצרת-מועד (90 יום) ומתחדשת שבועית על ידי
`netsec-tls-renew.timer` שקורא ל-`tailscale cert`. ‏Caddy טוען
אותה חמה בלי downtime.

ה-SAN של התעודה הוא רק `netsec-agent.tail37ac21.ts.net`. גישה
למערך דרך ה-IP הגולמי או השם הקצר עדיין עובדת, אבל מראה אזהרת
דפדפן (שם התעודה לא תואם).

## סודות על ה-VM

| קובץ | תוכן | הרשאה |
|---|---|---|
| `/etc/default/netsec-caddy` | `BASIC_AUTH_USER=`, `BASIC_AUTH_HASH=` | 600, root |
| `/home/ubuntu/netsec/deploy/.env` | ‏Compose קורא `BASIC_AUTH_*`, ‏`N8N_ENCRYPTION_KEY`, ‏`SMTP_*`, מפתחות API של ספקים | 600, ubuntu |
| `/etc/netsec-tls/*.key` | המפתח הפרטי של Let's Encrypt | 600, root |
| `~/.ssh/authorized_keys` | המפתחות הציבוריים שלכם | 600, ubuntu |
| `/srv/netsec/db/netsec.db` ← טבלת `sensors` | סוד HMAC לכל חיישן | הקובץ: 644 root, קריאה דרך ה-API |
| volume של docker `n8n_data` | כל האישורים שהגדרתם ב-n8n (סיסמת אפליקציה של Gmail וכו') | volume של root docker |

לעולם לא ב-git: ‏`.env`, ‏`netsec-tls/`, ערכי `sensors.hmac_secret`,
‏`n8n_data`.

## נתונים במנוחה

- קבצי SQLite הם דיסק לא מוצפן.
- Volumes של Docker הם דיסק לא מוצפן.
- דיסק ה-VM עצמו מנוהל על ידי Oracle (מוצפן במנוחה על ידי Oracle).

אם מישהו השיג root על ה-VM, הוא יראה את כל נתוני NetSec בתוספת
ה-hash של Caddy (לא את הסיסמה הגלויה). הוא לא יגיע לחשבון
ה-Tailscale שלכם ולא למחשב הנייד שלכם.

## איומים שמנוטרלים

- **סריקת פורטי אפליקציה מהאינטרנט.** נחסמת על ידי קשירת ה-interface
  וחומת האש.
- **‏Brute-force של ה-Portal.** מוגבל בקצב על ידי fail2ban.
- **לחיצה אקראית על כתובת ה-Portal מהאינטרנט.** בלתי אפשרית: שם
  ה-DNS מתפרש רק ב-tailnet שלכם.
- **טלפון גנוב עם Tailscale לא נעול.** מגיע ל-Portal אבל נתקל
  ב-basicauth. אם הסיסמה ידועה לגנב - הוא יראה את נתוני NetSec
  (סיכון מקובל בעיצוב; הסירו את הטלפון מה-tailnet בקונסולת ה-admin
  אם אבד).
- **שרת זדוני באותו subnet.** אין איום ישיר: ‏Tailscale הוא peer-to-peer
  מעל WireGuard; ה-subnet המקומי אינו ה-tailnet.
- **נוזקה על המחשב הנייד.** צריכה לתפוס את מפתח ה-SSH ואת האישורים
  של Tailscale כדי להגיע ל-VM. מפתח ה-SSH מוגן בסיסמת מפתח (מומלץ).

## איומים שאינם מנוטרלים

- **חשבון Tailscale שנפרץ.** כל ה-tailnet הופך נגיש לתוקף. הפעילו
  אימות דו-שלבי בקונסולת ה-admin של Tailscale.
- **הזרקת prompt ל-Ollama.** ה-Companion מריץ בשמחה כל prompt
  שתשלחו. אין בידוד בין ה-context של צ'אטים שונים (אף שכל צ'אט
  הוא thread משלו על המודל - צ'אט אחד לא יכול לראות היסטוריה של
  צ'אט אחר דרך prompt).
- **קובץ PCAP זדוני שתוכנן להפיל את tshark.** ‏tshark הוא parser
  גדול שהיו לו CVE בעבר. ה-worker רץ בתוך container של docker,
  אבל CVE של memory corruption עדיין יכול להתפשט בתוך ה-container.
  המיתון: עדכנו את tshark (`sudo apt upgrade`).
- **קובץ זדוני שהושלך ל-Companion.** מחלץ הקבצים קורא בייטים;
  לספריות PDF/DOCX היו CVE בעבר. צרפו רק קבצים שאתם סומכים עליהם.
  החילוץ רץ בתוך ה-venv של Companion אבל התהליך רץ בשם `ubuntu`;
  בריחה מלאה הייתה דורשת באג kernel.

</div>
