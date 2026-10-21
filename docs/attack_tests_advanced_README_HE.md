<div dir="rtl" align="right">

# סימולציות של מנועים מתקדמים מהקלטות אמיתיות

התיקייה המקבילה `attack_tests/` מכסה את ה-**מגלים** בצינור
(‏IsolationForest, ‏DBSCAN, וחוקי scan / flood / amp / ARP).
תיקיית-המשנה הזו מכסה את חמשת **מנועי הזיהוי** בתוספת שכבת ה-fusion,
כולם ב-`app/advanced_engines.py`: ‏ARP/DHCP, מנהור DNS, ‏DGA,
‏beaconing ו-TLS. הספים שלהם נקבעו במקור על בסיס היגיון; הסוויטה
הזו מוכיחה שהם נדלקים על הקלטות אמיתיות שמציגות את ההתנהגות
הצפויה, ושומרים על שקט על `benign_home.pcapng` (שומר ה-false
positives).

כל הקלטה היא אמיתית, מתוך dataset ידוע ואמין, ואומתה ב-tshark לפני
שהאותות הצפויים נרשמו ל-`sources.json`. אין כאן שום דבר סינתטי.

## מה נמצא היכן

| הקלטה | מיקום | אותות שהיא מדליקה |
|---|---|---|
| `arp-storm.pcap` | מחויבת בריפו (`pcaps/`, 47 KB, ‏Wireshark wiki, ‏public domain) | `arp_mac_many_ips` |
| `dns-tunnel-iodine.pcap` | מחויבת בריפו (`pcaps/`, 77 KB, ‏elastic/examples, ‏Apache-2.0) | `dns_tunneling` |
| `The-Ultimate-PCAP.pcapng` | נמשכת לפי דרישה (`_cache/`, 15 MB, ‏Johannes Weber) | `rogue_dhcp`, `arp_mac_many_ips`, `arp_ip_multi_mac`, `nxdomain_storm` |
| `ctu-botnet-91-conficker.pcap` | נמשכת לפי דרישה (`_cache/`, 26 MB, ‏Stratosphere/CTU) | `nxdomain_storm`, `beaconing`, `rogue_dhcp` |
| `hancitor-cobaltstrike.pcap` | נמשכת לפי דרישה (`_cache/`, 10 MB מתוך קובץ zip של 9 MB עם סיסמה, ‏malware-traffic-analysis.net) | `sni_ip_mismatch`, `tls_no_sni_external` |

## שימוש

```
# משיכת ההקלטות שלא מחויבות (מאמת sha256, מחלץ .gz / zip מוגן בסיסמה):
python attack_tests/advanced/fetch.py

# הצגת מה שכל הקלטה מפיקה בפועל (נוח לעיניים):
python attack_tests/advanced/verify_advanced.py

# אימות קפדני (מדלג על הקלטות שלא נמשכו עדיין):
python -m pytest tests/test_advanced_engines_real.py
```

Pytest מדלג כש-tshark לא נמצא ב-PATH (המנועים מריצים אותו דרך
shell) או כשהקלטה שאמורה להימשך לא נמצאת - כך ש-CI נשאר ירוק גם
בלי ההורדות של המחקר.

## שני פערי מנוע מתועדים שנמצאו באימות

ממצאים שנמדדו על ה-pcaps בפועל, לא משהו שצריך להסתיר:

- **‏`dga_domain` לא נדלק על Conficker.** תוויות ה-DGA של Conficker
  באורך 8 תווים ולעיתים נושאות תנועות (‏`vowel_ratio >= 0.25`
  נכשל בשומר של המנוע שדורש ערך מתחת ל-0.25). מנוע ה-`nxdomain_storm`
  כן נדלק על אותה הקלטה (155 תגובות NXDOMAIN למארח יחיד הן אותו
  סימפטום DGA שנראה מצד התגובה), ולכן זיהום של Conficker עדיין
  מופעל - פשוט דרך מנוע אחר.
- **‏`beaconing` לא נדלק על הקלטת Hancitor / Cobalt Strike.** ה-C2
  של Hancitor בדוגמה הזו הוא HTTP מעל פורט 80, לא TCP-SYN מחזורי,
  והוא נופל מחוץ למסנן ה-TCP-start של מנוע ה-beaconing.
  `sni_ip_mismatch` נדלק חמש פעמים על אותה הקלטה (‏SNIs בסגנון
  domain-fronting שמצביעים על כתובות של AWS), ולכן ה-C2 עדיין
  מזוהה.

שני פערים אמיתיים במנועים, שנחשפו על ידי סוויטת הבדיקות - לא כשלים
שצריך להסתיר. הם שייכים לסבב כיוונון עתידי של המנועים, לא לכאן.

## הוספת הקלטה חדשה

1. להוסיף רשומה ל-`sources.json` עם `family`, ‏`action`
   (`commit` או `fetch`), ‏`url`, ‏`sha256` ו-`expected_signals`.
2. `python attack_tests/advanced/fetch.py <family>` כדי להוריד.
3. `python attack_tests/advanced/verify_advanced.py` כדי לראות
   מה נדלק, ואז לעדכן את `expected_signals` כך שיתאים למציאות.
4. `pytest tests/test_advanced_engines_real.py` נועל את הממצאים.

</div>
