<div dir="rtl" align="right">

# בדיקות שפיות על הקלטות של תקיפות

ה-notebook של הדשבורד (`app/Network_Security_Dashboard.ipynb`) בנוי
עבור הקלטות של גלישה ברשת ביתית. התיקייה הזו מספקת לו חמש הקלטות
תקיפה אמיתיות ו-CLI עצמאי שמחקה את התאים 8, 12, 16 ו-22-26 כדי
לוודא שכל שכבת זיהוי נדלקת על המחלקה שלה.

## הרצה

```
python3 attack_tests/run_pipeline.py \
    attack_tests/pcaps/<S1.pcap> attack_tests/pcaps/<S2.pcap>
```

הסקריפט `run_pipeline.py` הוא תת-קבוצה נאמנה של ה-notebook - חילוץ
מאפיינים ב-tshark, ‏IsolationForest עם ה-`contamination` הקבוע 0.10
(סריקת היציבות בוטלה - ראו `docs/TRADEOFFS_EN.md` §7), ‏DBSCAN
במרפק של k-NN עם שומרים נגד הצפות מזויפות, סט החוקים לזיהוי
FTP / SMTP / SYN / FIN / NULL / Xmas / RST / ARP / DNS, חוק
ההגברה של תשובות DNS, ו-LSTM על הגודל הממוצע של חבילה לכל שנייה.
אין Dash UI; כל השאר זהה.

## ההקלטות המצורפות

| קובץ | מקור | חבילות | תקיפה |
|---|---|---:|---|
| `tcp_syn_scan.pcap` | markofu/pcaps EvilFingers NMAP | 2 020 | nmap `-sS` SYN scan |
| `xmas_scan.pcap`    | markofu/pcaps EvilFingers NMAP | 2 000 | nmap `-sX` סריקת stealth |
| `arpspoof.pcap`     | researcher111/ARP-pcap-files   | 16 285 | הרעלת מטמון ARP, 9 דקות |
| `synflood.pcap`     | pvrmza/DDoS-packet-captures    | 37 841 | הצפת TCP SYN מזויפת (37,623 כתובות מקור) |
| `dns_amp.pcap`      | pvrmza/DDoS-packet-captures    | 12 000 | הגברת DNS-ANY |

## מה הריצות מוודאות

### `tcp_syn_scan.pcap` ← ‏ARP-spoof (`run_synscan_arpspoof.log`)

- IsolationForest מסמן את `192.168.1.10` (1,002 ‏SYN מתוך 1,007 חבילות).
- חוק הסריקה האופקית מדליק `*** SCAN ***` על אותה כתובת עם
  `SYN ratio=1.00`.
- חוק זיוף ה-ARP מסמן את `192.168.1.1` שנתבעת על ידי שתי כתובות MAC
  (`08:00:27:2d:f8:5a` ו-`08:00:27:5e:01:7c`) - מתכון קלאסי של MITM.
- DBSCAN מפצל נקי את S2 לחמישה אשכולות, ‏silhouette 0.63.

### `xmas_scan.pcap` ← ‏`dns_amp.pcap` (`run_xmas_dnsamp.log`)

- סריקת Xmas (‏`FIN | PSH | URG` ‏=0x29 על `192.168.1.10`,
  1,000 חבילות) מדליקה כעת את אותו `*** SCAN ***`. בעבר הייתה
  סמויה.
- הקלטת הגברת DNS: ‏IsolationForest מסמן את ארבעת ה-reflectors
  שאמור לסמן (`8.8.8.8`, `8.8.4.4`, `212.8.51.69`, `1.1.1.1`),
  ובנוסף חוק ההגברה מצד התגובות נדלק על 8 כתובות reflector
  ששולחות תגובות ממוצעות של כ-1,100 בייט (למשל
  `212.8.51.69 responses=250 mean_size=1090.1`, כולן
  `*** AMP REFLECTOR ***`).

### `synflood.pcap` ← ‏`arpspoof.pcap` (`run_synflood_arpspoof.log`)

- 37,623 כתובות IP מקור מזויפות ייחודיות. בעבר: ‏DBSCAN קרס עם
  9.8 GB של RSS ולא הסתיים. כעת: קריסת ה-eps לאפס מזוהה
  (`eps collapsed to 0; using mean k-dist=0.050`), ו-DBSCAN מדלג
  עם ההודעה `DBSCAN skipped: 37,623 IPs > cap 5,000 (spoofed-flood pattern)`.
  IsolationForest עדיין מסמן 218 כתובות. הדשבורד לא נתקל ב-OOM.

## מה שינויי ה-notebook מכסים

חמישה תיקונים שולבו חזרה ל-notebook מתוך הריצות האלה:

1. **תא 8** - מוני TCP flags חדשים ל-FIN-only, ‏NULL (ללא flags)
   ו-Xmas (`FIN | PSH | URG`) לכל כתובת מקור. נוספו כעמודות
   `fin_count`, `null_count`, `xmas_count` באגרגציה לכל כתובת IP.
2. **תא 8** - אגרגציה חדשה `dns_amp_per_src`: לכל כתובת מקור -
   ספירה, סך הבייטים והגודל הממוצע של *תגובות* DNS שיוצאות מ-UDP/53.
3. **תא 12** - מטריצת המאפיינים של IsolationForest הורחבה עם שלושת
   מוני סריקות ה-stealth; קריסת ה-eps-מהמרפק לאפס מזוהה ומוחלפת
   ב-k-distance הממוצע; ‏DBSCAN מדלג כש-`|IPs| > 5,000` כדי שהצפות
   מזויפות לא יפוצצו את הזיכרון.
4. **תא 16** - חוק הסריקה האופקית הורחב מ-SYN-only לכלול גם
   FIN-only, ‏NULL ו-Xmas עם אותם ספים: ‏יותר מ-50 חבילות, וגם
   (יותר מ-20 יעדים ויחס מעל 0.25) או יחס דגל-לחבילות מעל 0.7.
   הפלט כולל כעת `scan_alerts`.
5. **תא 16** - חוק הגברה מצד תגובות DNS: לכל כתובת מקור ששלחה
   לפחות 50 תשובות DNS מתוך UDP/53 בגודל ממוצע של 200 בייט ומעלה,
   מופק ממצא של reflector. הפלט מוסיף את המפתח `dns_amp`.

## מטריצת הזיהוי אחרי התיקונים

| סוג התקיפה | IsoForest | DBSCAN | שכבת החוקים | LSTM |
|---|:-:|:-:|:-:|:-:|
| TCP SYN scan      | ✅ | ✅ | ✅ סריקה אופקית | n/a |
| TCP Xmas scan     | - (אוכלוסייה קטנה) | - | ✅ סריקה אופקית | n/a |
| ARP spoofing      | ✅ | ✅ | ✅ ‏ARP מרובה-MAC | ➖ |
| DNS amplification | ✅ | ✅ | ✅ ‏amp / reflector | n/a |
| Spoofed SYN flood | ✅ | ✅ (עם שומר דילוג) | ✅ ‏syn_counter | n/a |

</div>
