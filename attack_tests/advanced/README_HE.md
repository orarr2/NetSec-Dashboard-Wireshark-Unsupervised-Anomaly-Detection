<div dir="rtl">

# סימולציות של מנועים מתקדמים מהקלטות אמיתיות

> גרסה עברית של [`README.md`](README.md).

התיקייה המקבילה `attack_tests/` מכסה את ה-**מגלים** שבצינור
(‏IsolationForest, ‏DBSCAN, וחוקי scan / flood / amp / ARP). תיקיית-המשנה
הזאת מכסה את חמשת **מנועי הזיהוי** בתוספת שכבת ה-fusion ב-
`app/advanced_engines.py`: ‏ARP/DHCP, ‏DNS tunneling, ‏DGA, ‏beaconing, ‏TLS.
הספים שלהם נקבעו במקור משיקולי היגיון; הסוויטה הזאת מוכיחה שהם
נדלקים על הקלטות אמיתיות שמציגות את ההתנהגות המטרה, ושומרים על
שקט על `benign_home.pcapng` (שומר ה-false-positives).

כל הקלטה היא אמיתית, מתוך dataset ידוע ואמין, ואומתה ב-tshark לפני
שהאותות הצפויים נרשמו ל-`sources.json`. אין כאן שום דבר סינתטי.

## מה נמצא היכן

| הקלטה | מיקום | אותות שהיא מדליקה |
|---|---|---|
| `arp-storm.pcap` | מחויב (`pcaps/`, 47KB, ‏Wireshark wiki, ‏public domain) | `arp_mac_many_ips` |
| `dns-tunnel-iodine.pcap` | מחויב (`pcaps/`, 77KB, ‏elastic/examples, ‏Apache-2.0) | `dns_tunneling` |
| `The-Ultimate-PCAP.pcapng` | נמשך (`_cache/`, 15MB, ‏Johannes Weber) | `rogue_dhcp`, `arp_mac_many_ips`, `arp_ip_multi_mac`, `nxdomain_storm` |
| `ctu-botnet-91-conficker.pcap` | נמשך (`_cache/`, 26MB, ‏Stratosphere/CTU) | `nxdomain_storm`, `beaconing`, `rogue_dhcp` |
| `hancitor-cobaltstrike.pcap` | נמשך (`_cache/`, 10MB מתוך zip 9MB עם סיסמה, ‏malware-traffic-analysis.net) | `sni_ip_mismatch`, `tls_no_sni_external` |

## שימוש

```
# משיכת ההקלטות שלא מחויבות (מאמת sha256, מחלץ .gz / password-zip):
python attack_tests/advanced/fetch.py

# לראות מה כל הקלטה בפועל מפיקה (ידידותי לעיניים):
python attack_tests/advanced/verify_advanced.py

# לקבוע זאת כ-assertion (מדלג על הקלטות fetch-only אם לא משכתם אותן):
python -m pytest tests/test_advanced_engines_real.py
```

‏Pytest מדלג כש-tshark לא ב-PATH (המנועים מריצים לו shell) או כאשר
הקלטת fetch-only חסרה - כך ש-CI נשאר ירוק בלי ההורדות של המחקר.

## שני פערי מנוע מתועדים שנמצאו בעת האימות

ממצאים שנמדדו על ה-pcaps האמיתיים, לא משהו שצריך להסתיר:

- **‏`dga_domain` לא נדלק על Conficker.** תוויות ה-DGA של Conficker
  הן באורך 8 תווים ולעתים קרובות נושאות תנועות (‏`vowel_ratio >= 0.25`
  נכשל בשומר של המנוע, שדורש ‏`< 0.25`). מנוע ה-`nxdomain_storm` כן
  נדלק על אותה הקלטה (155 NXDOMAINs ל-host אחד זה אותו סימפטום DGA
  שנראה מצד התגובה), אז זיהוי של Conficker עדיין מופעל - פשוט דרך
  מנוע אחר.
- **‏`beaconing` לא נדלק על הקלטת Hancitor / Cobalt Strike.** ה-C2
  של Hancitor בדוגמה הזאת הוא HTTP מעל פורט 80, לא TCP-SYN מחזורי,
  ונופל מחוץ למסנן TCP-start של מנוע ה-beaconing. ‏`sni_ip_mismatch`
  נדלק 5 פעמים על אותה הקלטה (‏SNIs בסגנון domain-fronting שמצביעים
  על IPs של AWS), אז ה-C2 עדיין מזוהה.

שניהם פערים כנים במנועים, שנחשפו על ידי סוויטת הבדיקות - לא כשלים
שצריך להסתיר. הם שייכים לסבב כיוון עתידי של המנועים, לא לכאן.

## הוספת הקלטה חדשה

1. הוספת רשומה ל-`sources.json` עם `family`, ‏`action` (`commit` או
   `fetch`), ‏`url`, ‏`sha256`, ו-`expected_signals`.
2. `python attack_tests/advanced/fetch.py <family>` כדי להוריד.
3. `python attack_tests/advanced/verify_advanced.py` כדי לראות מה
   נדלק, ואז מגדירים את `expected_signals` כך שיתאים למציאות.
4. `pytest tests/test_advanced_engines_real.py` נועל את זה.

</div>
