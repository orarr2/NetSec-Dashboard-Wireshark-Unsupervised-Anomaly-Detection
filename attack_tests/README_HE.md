<div dir="rtl" align="right">

# בדיקות שפיות של Attack-PCAP

ה-notebook של הדשבורד (`app/Network_Security_Dashboard.ipynb`) בנוי
עבור הקלטות של גלישה ברשת ביתית. התיקייה הזאת נותנת לו חמישה
קבצי PCAP של תקיפות אמיתיות ו-CLI עצמאי שמחקה את תאים
8 / 12 / 16 / 22-26 כך שתוכלו לוודא שכל שכבת זיהוי נדלקת על
מחלקת המטרה שלה.

## הרצה

```
python3 attack_tests/run_pipeline.py \
    attack_tests/pcaps/<S1.pcap> attack_tests/pcaps/<S2.pcap>
```

‏`run_pipeline.py` הוא תת-קבוצה נאמנה של ה-notebook - חילוץ פיצ'רים
של tshark, ‏IsolationForest ב-`contamination = 0.10` הקבוע (סריקת
יציבות-seed נגרסה, ראו `docs/TRADEOFFS_EN.md` §7), ‏DBSCAN לפי מרפק
k-NN עם שומרי spoofed-flood, מערך החוקים
FTP / SMTP / SYN / FIN / NULL / Xmas / RST / ARP / DNS, חוק
ה-amp של תגובות DNS, ו-LSTM של גודל-פקטה-ממוצע פר-שנייה. אין Dash UI;
כל השאר זהה.

## ה-PCAPs המצורפים

| קובץ | מקור | פקטות | תקיפה |
|---|---|---:|---|
| `tcp_syn_scan.pcap` | markofu/pcaps EvilFingers NMAP | 2 020 | nmap `-sS` SYN scan |
| `xmas_scan.pcap`    | markofu/pcaps EvilFingers NMAP | 2 000 | nmap `-sX` סריקת stealth |
| `arpspoof.pcap`     | researcher111/ARP-pcap-files   | 16 285 | הרעלת cache של ARP, 9 דקות |
| `synflood.pcap`     | pvrmza/DDoS-packet-captures    | 37 841 | הצפת TCP SYN מזויפת (37,623 src-IPs) |
| `dns_amp.pcap`      | pvrmza/DDoS-packet-captures    | 12 000 | הגברת DNS-ANY |

## מה הריצות מוודאות

### `tcp_syn_scan.pcap` → ARP-spoof  (`run_synscan_arpspoof.log`)

- ‏IsolationForest מסמן את `192.168.1.10` (1,002 SYN / 1,007 פקטות).
- חוק הסריקה האופקית מדליק `*** SCAN ***` על אותו IP עם `SYN ratio=1.00`.
- חוק ARP-spoofing מסמן את `192.168.1.1` שנתבע על ידי שתי MACs
  (`08:00:27:2d:f8:5a` ו-`08:00:27:5e:01:7c`) - MITM מהספר.
- ‏DBSCAN מפצל נקי את S2 ל-5 אשכולות, silhouette 0.63.

### `xmas_scan.pcap` → `dns_amp.pcap`  (`run_xmas_dnsamp.log`)

- סריקת Xmas (‏FIN | PSH | URG = 0x29 על `192.168.1.10`, 1,000 פקטות)
  עכשיו מדליקה את אותו חוק `*** SCAN ***`. בעבר זה היה סמוי.
- הקלטת הגברת DNS: ‏IsolationForest מסמן את ארבעת הרפלקטורים שהוא
  צריך לסמן (8.8.8.8, ‏8.8.4.4, ‏212.8.51.69, ‏1.1.1.1), וגם חוק ה-amp
  של צד התגובה נדלק על 8 IPs של רפלקטורים ששלחו ממוצע ~1,100 בייט
  (למשל `212.8.51.69 responses=250 mean_size=1090.1`,
  כולם `*** AMP REFLECTOR ***`).

### `synflood.pcap` → `arpspoof.pcap`  (`run_synflood_arpspoof.log`)

- 37,623 IPs מקור מזויפים ייחודיים. בעבר: ‏DBSCAN קרס עם 9.8GB RSS
  ולא הסתיים. עכשיו: קריסת eps ל-0 מזוהה (`eps collapsed to 0;
  using mean k-dist=0.050`) ו-DBSCAN מדלג עם `DBSCAN skipped:
  37,623 IPs > cap 5,000 (spoofed-flood pattern)`.
  ‏IsolationForest עדיין מסמן 218 IPs. הדשבורד לא קורס מ-OOM.

## מה השינויים ב-notebook מכסים

חמישה תיקונים הושזרו חזרה אל ה-notebook מהריצות האלה:

1. **תא 8** - מונה flags חדש של TCP ל-FIN-only, ‏NULL (ללא flags),
   ו-Xmas (‏FIN | PSH | URG) פר-IP מקור. נוסף כעמודות `fin_count`,
   `null_count`, `xmas_count` באגרגציה הפר-IP.
2. **תא 8** - אגרגציית `dns_amp_per_src` חדשה: פר-IP מקור, הספירה /
   סך הבייטים / הגודל הממוצע של *תגובות* DNS שיוצאות מ-UDP/53.
3. **תא 12** - מטריצת הפיצ'רים של IsolationForest הורחבה עם שלוש
   סופרות סריקות-חמקניות; קריסה של eps-מהמרפק ל-0 מזוהה ומוחלפת
   ב-k-distance ממוצע; ‏DBSCAN מדולג כש-`|IPs| > 5,000` כך
   שהצפות מזויפות לא יפוצצו זיכרון.
4. **תא 16** - חוק סריקה אופקית הורחב מ-SYN-only כך שגם מדליק על
   FIN-only, ‏NULL, ‏Xmas עם אותם ספים של > 50-pkt +
   ((>20-dst AND ratio>0.25) OR ratio>0.7). הפלט כעת כולל `scan_alerts`.
5. **תא 16** - חוק הגברה מצד תגובות DNS: לכל IP מקור ששלח ≥ 50
   תשובות DNS מתוך UDP/53 עם גודל תגובה ממוצע ≥ 200 בייט,
   מופק ממצא reflector. הפלט מוסיף `dns_amp`.

## מטריצת זיהוי אחרי התיקונים

| מחלקת תקיפה | IsoForest | DBSCAN | שכבת חוקים | LSTM |
|---|:-:|:-:|:-:|:-:|
| TCP SYN scan      | ✅ | ✅ | ✅ סריקה אופקית | n/a |
| TCP Xmas scan     | - (אוכלוסייה קטנה) | - | ✅ סריקה אופקית | n/a |
| ARP spoofing      | ✅ | ✅ | ✅ ARP multi-MAC | ➖ |
| DNS amplification | ✅ | ✅ | ✅ amp / reflector | n/a |
| Spoofed SYN flood | ✅ | ✅ (עם שומר דילוג) | ✅ syn_counter | n/a |

</div>
