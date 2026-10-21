<div dir="rtl">

# מודל האבטחה

> גרסה עברית של [`SECURITY_MODEL.md`](SECURITY_MODEL.md).

ארבע שאלות, ארבע תשובות.

## 1. מי יכול להגיע למערך מהאינטרנט?

‏SSH בלבד (פורט 22). כל השאר קשור ל-interface של Tailscale
(`100.68.246.54`) או ל-loopback (`127.0.0.1`). ה-firewall של
Oracle Cloud דוחה (‏REJECT) כל מה שינסה להגיע לפורטי האפליקציה
מה-interface הציבורי (אומת בסריקת פורטים חיצונית; 22 חוזר כפתוח,
‏443/5200/8080/5678/8766/11434 כולם מסוננים).

## 2. מי יכול להגיע למערך דרך Tailscale?

כל מי שההתקן שלו מחובר לחשבון ה-Tailscale שלכם. ל-tailnet
יש כרגע:
- `netsec-agent` (ה-VM)
- `iphone-13-mini`
- `or-pc-1` (מחשב נייד)
- `or-pc` (לא מחובר)

הוספת התקן דורשת או סיסמת Tailscale + אימייל + 2FA, או מפתח auth
שהונפק מקונסולת ה-admin.

## 3. איזה auth שוכב על כל שירות?

| שירות | URL / פורט | Auth | מצב כישלון |
|---|---|---|---|
| Portal | `/` על 443 | Caddy basicauth (‏bcrypt) | 401 |
| RAG | `/rag/` על 443 | Caddy basicauth (‏bcrypt) | 401 |
| Companion | `/chat/` על 443 | Caddy basicauth (‏bcrypt) | 401 |
| n8n | 5678 | login של n8n (email+password) | 401 |
| Ingest API upload | 8766 | HMAC-SHA256 פר-בקשה | 401 |
| Ingest API health | 8766 `/healthz` | אין | 200 |
| Ollama | 11434 (loopback) | אין | לא נגיש מחוץ ל-host של ה-VM |
| SSH | 22 | pubkey בלבד, בלי סיסמאות | החיבור נופל |

## 4. מה קורה בכישלונות חוזרים?

**SSH:** ‏`sshd` מקבל pubkey בלבד; ‏`PasswordAuthentication no`. ניסיונות
brute-force נדחים מידית (אין סיסמה לנחש). כרגע ~5,000 ניסיונות ליום
מ-~100 IPs. המשך אידיאלי: לסגור את 22 ל-Tailscale בלבד (כרגע נדחה -
צריך לתעד קודם נתיב התאוששות של Oracle Console).

**Caddy basicauth:** ‏`fail2ban` צופה ב-systemd journal של Caddy
אחרי `msg:"auth provider returned error"`. חמישה כישלונות בתוך 10
דקות מפעיל ban של שעה ב-iptables ל-IP המקור. ב-tailnet זה נדלק
לעתים נדירות (ה-auth נזכר פר-session של דפדפן), אבל זה מגן מפני חבר
tailnet שנפרץ שינסה brute-force של basicauth.

**n8n:** ל-n8n יש rate-limiter משלו ונעילת חשבון.

**Ingest API HMAC:** כל בקשה חייבת לשאת header ‏`X-Signature`:
‏HMAC-SHA256 על ההודעה `"<sha256>:<sensor>:<timestamp>"`, עם המפתח
שהוא הסוד הפר-sensor ב-DB. חתימה שגויה מחזירה 401 בלי לדלוף את
הנכונה; אין מכסה של "סיסמה שגויה" כי אין סיסמה.

## מודל התעודות

‏TLS על 443 משתמש בתעודת Let's Encrypt שהונפקה על ידי Tailscale
(הם הבעלים של הדומיין ‏`*.tail<id>.ts.net` והם חשבון ACME עבורו).
התעודה היא קצרת-טווח (90 ימים) ומתחדשת שבועית על ידי
`netsec-tls-renew.timer` שקורא ל-`tailscale cert`. ‏Caddy טוען אותה
במקום ללא downtime.

ה-SAN של התעודה הוא רק `netsec-agent.tail37ac21.ts.net`. גישה
למערך דרך ה-IP הגולמי או ה-hostname הקצר עדיין עובדת אבל מציגה
אזהרת דפדפן (שם התעודה לא תואם).

## סודות על ה-VM

| קובץ | תוכן | הרשאה |
|---|---|---|
| `/etc/default/netsec-caddy` | `BASIC_AUTH_USER=`, `BASIC_AUTH_HASH=` | 600, root |
| `/home/ubuntu/netsec/deploy/.env` | ‏Compose קורא `BASIC_AUTH_*`, `N8N_ENCRYPTION_KEY`, `SMTP_*`, מפתחות API של ספקים | 600, ubuntu |
| `/etc/netsec-tls/*.key` | המפתח הפרטי של Let's Encrypt | 600, root |
| `~/.ssh/authorized_keys` | ה-pubkeys שלכם | 600, ubuntu |
| `/srv/netsec/db/netsec.db` -> טבלת `sensors` | סוד HMAC פר-sensor | קובץ: 644 root, קריאה דרך API |
| volume של docker ‏`n8n_data` | כל אישורים שהגדרתם ב-n8n (‏Gmail app-password וכו') | volume של root docker |

אף פעם לא ב-git: ‏`.env`, ‏`netsec-tls/`, ערכים של ‏`sensors.hmac_secret`, ‏`n8n_data`.

## נתונים במנוחה

- קבצי SQLite הם דיסק לא מוצפן.
- Volumes של Docker הם דיסק לא מוצפן.
- דיסק ה-VM עצמו מנוהל על ידי Oracle (מוצפן במנוחה על ידי Oracle).

אם מישהו השיג root על ה-VM הוא יראה את כל נתוני NetSec בתוספת ה-hash
של Caddy (לא הסיסמה בטקסט פתוח). הוא לא ישיג גישה לחשבון ה-Tailscale
שלכם או למחשב הנייד שלכם.

## איומים שמנוטרלים

- **סריקת פורטי אפליקציה מצד האינטרנט.** נחסם על ידי binding ל-interface + firewall.
- **‏Brute-force של ה-Portal.** מוגבל קצב על ידי fail2ban.
- **כל אחד באינטרנט שלוחץ על ה-URL של ה-Portal.** בלתי אפשרי: שם ה-DNS מתפרש רק ב-tailnet שלכם.
- **טלפון גנוב עם Tailscale לא נעול.** הם מגיעים ל-Portal אבל פוגעים ב-basicauth. אם הם יודעים את הסיסמה הם יראו את נתוני NetSec (סיכון מקובל בעיצוב - הסירו את הטלפון מה-tailnet בקונסולת ה-admin אם אבד).
- **שרת זדוני על ה-subnet שלכם.** אין איום ישיר: ‏Tailscale הוא peer-to-peer מעל WireGuard; ה-subnet המקומי אינו ה-tailnet.
- **Malware על המחשב הנייד.** היה צריך לתפוס את מפתח ה-SSH ואת האישורים של Tailscale כדי להגיע ל-VM. מפתח SSH מוגן בסיסמת-מפתח (מומלץ).

## איומים שאינם מנוטרלים

- **חשבון Tailscale שנפרץ.** כל ה-tailnet הופך נגיש לתוקף. הפעילו 2FA בקונסולת ה-admin של Tailscale.
- **Prompt injection ב-Ollama.** ה-Companion מריץ בשמחה כל prompt שתשלחו. אין בידוד בין contexts של chats שונים (אם כי כל chat הוא thread משלו על המודל - chat אחד לא יכול לראות היסטוריה של chat אחר דרך prompt).
- **PCAP זדוני שעובד כדי להקריס את tshark.** ‏Tshark הוא parser גדול והיו לו CVEs. ה-worker רץ בתוך container של docker, אבל CVE של memory corruption עדיין יכול להתפשט בתוך ה-container. מיטיגציה: שמרו את tshark מעודכן (‏`sudo apt upgrade`).
- **קובץ זדוני שהושלך ל-Companion.** מחלץ הקבצים קורא בייטים; לספריות PDF/DOCX היו CVEs. צרפו רק קבצים שאתם סומכים עליהם. החילוץ רץ בתוך ה-venv של Companion אבל התהליך רץ כ-`ubuntu`; בריחה מלאה הייתה דורשת באג kernel.

</div>
