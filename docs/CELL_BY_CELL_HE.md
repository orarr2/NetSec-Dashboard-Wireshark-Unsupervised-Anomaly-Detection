# מדריך תא-תא — לוח בקרה לניתוח אבטחת רשת

המחברת מכילה 50 תאים (25 קוד, 25 markdown). המסמך הזה מסביר מה כל תא קוד עושה.

## ארכיטקטורה כללית

המחברת בנויה כך שעד תא 47 (לא כולל), רצות רק **הגדרות פונקציות וייבוא ספריות**. אין שום ניתוח נתונים שמתבצע אוטומטית כשמריצים את התאים. ניתוח אמיתי מתחיל רק כשהמשתמש לוחץ "Load PCAP" או מקליט בלייב מהדשבורד (תא 47).

```
תאים 0-3:   Markdown — כותרת, מבוא, הסבר על שכבות TCP/IP
תא 4:       ייבוא — התקנה אוטומטית של ספריות, איתור tshark
תא 5:       Markdown — מסביר על נתיבי PCAP
תא 6:       משתני PCAP ריקים + פונקציית בורר קבצים PySide6
תא 7:       Markdown — מסביר את מנוע הניתוח
תא 8:       _analyze_pcap_tshark / _analyze_pcap_scapy — טוענים מהירים
תא 9:       Markdown
תא 10:      איפוס מצב + load_session_from_pcap
תא 11:      Markdown
תא 12:      run_ml_on_session — IsolationForest + DBSCAN
תא 13:      Markdown
תא 14:      compute_z_scores
תא 15:      Markdown
תא 16:      run_security_scans
תא 17:      Markdown
תא 18:      compute_session_compare
תא 19:      Markdown
תא 20:      generate_insights_lines + process_session + compute_pair_state
תא 21:      Markdown
תא 22:      מחלקת LSTMModel
תא 23:      Markdown
תא 24:      run_lstm_on_session — לולאת אימון עם early stopping
תא 25:      Markdown
תא 26:      evaluate_lstm
תא 27:      Markdown
תאים 28-36: Markdown + תאים ריקים (חלקים שעברו לתאים אחרים)
תא 37:      מנוע סיווג — OUI lookup + classify_local_device בשלושה שלבים
תא 38:      Markdown
תא 39:      בונה מצאי המכשירים + מדדי כיסוי
תא 40:      Markdown
תא 41:      LiveCaptureWorker — תהליך tshark משנה ברקע
תא 42:      Markdown
תא 43:      ניתוח גלישה (קטגוריה + שעה) + מפת מכשירים (PCA)
תא 44:      Markdown
תא 45:      make_figures + _build_proximity_map_figure — 34 גרפי Plotly
תא 46:      Markdown
תא 47:      אפליקציית Dash — עיצוב Aurora + מסך פתיחה CRT + 7 חלקי ניווט
```

---

## תא 4 — ייבוא וסביבה

**מטרה:** לוודא שכל ספרייה נדרשת מותקנת; לאתר את `tshark` על הדיסק.

עובר במלולאה על dict בשם `PKGS` שממפה שמות pip → שמות import. לכל זוג מנסה `import`; אם נכשל, מריץ `pip install --quiet`. לאחר מכן מאתר את `tshark` ע"י חיפוש:

1. `shutil.which('tshark')`
2. נתיבי התקנה נפוצים: `/usr/bin/tshark`, `/usr/local/bin/tshark`, `/Applications/Wireshark.app/Contents/MacOS/tshark`, `C:\Program Files\Wireshark\tshark.exe`, `C:\Program Files (x86)\Wireshark\tshark.exe`

הנתיב שנמצא נשמר ב-`TSHARK_PATH`; אם לא נמצא דבר, `TSHARK_PATH = None` והמחברת נופלת חזרה ל-`scapy`.

**תופעות לוואי:** `scapy.conf.verb = 0` (משתיק scapy), `warnings.filterwarnings('ignore')` (מסתיר deprecation noise).

---

## תא 6 — משתני PCAP ריקים + בורר קבצים

**מטרה:** לאתחל משתני placeholder ולהגדיר את בורר הקבצים מבוסס PySide6 שכפתור Upload שבדשבורד קורא אליו.

משתנים: `PCAP1 = None`, `PCAP2 = None`, `CSV1 = None`, `CSV2 = None`, `MY_DEVICE_IP = "192.168.1.50"` (placeholder — המשתמש משנה את זה).

`pick_pcap_files()` כותב סקריפט PySide6 קטן ל-tempfile ומריץ אותו דרך `subprocess.run`. הסקריפט מציג בורר קבצים מקומי ומדפיס את הנתיבים שנבחרו ל-stdout. הפונקציה קוראת את ה-stdout ומחזירה רשימת נתיבים. העקיפות הזו נמנעת מטעינת PySide6 לתוך תהליך המחברת עצמו (מה שיכול לקרוס את Jupyter בחלק מההתקנות).

---

## תא 8 — מנוע קליטה

**מטרה:** התא החשוב ביותר. מנתח PCAP ל-dict מובנה שכל יתר הצינור צורך.

### `_find_tshark()`
מחזיר את הנתיב ששמור בתא 4, או `None`.

### `_analyze_pcap_tshark(path, label)`
בונה פקודת tshark עם 25 שדות:

```
frame.time_epoch, frame.len,
eth.src, eth.dst, ip.src, ip.dst,
_ws.col.Protocol,
tcp.srcport, tcp.dstport, tcp.flags,
udp.srcport, udp.dstport,
dns.qry.name, dns.flags.rcode, dns.flags.response,
arp.src.proto_ipv4, arp.src.hw_mac,
wlan.fc.type, wlan.fc.subtype, wlan.sa, wlan.da,
wlan.fc.retry, wlan.duration,
wlan_radio.signal_dbm, radiotap.dbm_antsignal
```

הפלט נלכד כ-DataFrame של pandas דרך `pd.read_csv(StringIO(out), sep='\t')`. לאחר מכן מעבר אחד דרך ה-DataFrame בונה:

| מבנה | תוכן |
|---|---|
| `ips_src` | Counter של ספירת חבילות לפי IP מקור |
| `bytes_src / bytes_dst` | נפח bytes לפי IP |
| `protocols` | Counter של שם פרוטוקול שכבה אחרונה |
| `macs` | Counter של ספירת חבילות לפי MAC |
| `dns_real` | תדירויות שמות שאילתות DNS (Counter) |
| `dns_timeline` | רשימת `(ts, src_ip, query)` לכל חבילת DNS |
| `df_pkts` | DataFrame של `(ts, src, dst, size, proto)` לכל חבילת IP |
| `arp_ip_to_macs` | dict של IP → set של MACs שנראו |
| `syn_counter / rst_counter` | מונים של SYN/RST לפי מקור |
| `ports_per_ip / dns_per_ip / mdns_per_ip` | אוספי אותות לפי IP עבור המסווג |
| `wlan_features` | דגימות RSSI לכל MAC, probe req, assoc, ספירות retry |

`wlan_features` הוא הבסיס לניתוח קרבה במצב RSSI. אם אף שדה `wlan.*` לא מאוכלס (טיפוסי ללכידות Wi-Fi ב-Windows שמציגות Ethernet כבר deframed), זה נשאר dict ריק ו-`wlan_available = False`.

### `_analyze_pcap_scapy(path, label)`
Fallback למקרה ש-tshark לא זמין. משתמש ב-`scapy.rdpcap` ועובר על החבילות. איטי יותר אבל בלי תלות חיצונית. מחזיר את אותה סכמת dict עם `wlan_features = {}` ו-`wlan_available = False` (scapy לא יכול להגיע לשכבת הרדיו בלי מתאם תומך monitor mode).

### `load_session_from_pcap(path, label)`
Dispatcher: קורא ל-`_analyze_pcap_tshark` אם `TSHARK_PATH` מוגדר, אחרת `_analyze_pcap_scapy`.

---

## תא 10 — משבצות session ריקות

מאתחל `S1 = None`, `S2 = None`. הדשבורד משנה את אלה כשהמשתמש טוען PCAP.

---

## תא 12 — ML לא מפוקח

`run_ml_on_session(S)` בונה מטריצת 7 תכונות מ-`ip_agg` (`mean_len`, `std_len`, `count`, `burst_score`, `unique_dsts`, `syn_count`, `rst_count`), מריץ עליה `StandardScaler`, ואז:

**IsolationForest** עם sensitivity sweep של 20 נקודות contamination מ-0.02 עד 0.30. לכל ערך, מתאים את המודל ורושם את הציון הממוצע של הקבוצה המסומנת. בוחר את ה-contamination שהקבוצה המסומנת שלו בעלת **הציון הממוצע הנמוך ביותר** (הקיצונית ביותר — הנקודות שבודדו הכי מהר ע"י העצים). שומר את הערך הנבחר ב-`ip_agg.attrs['chosen_contamination']`.

**DBSCAN** עם `eps` מ-k-distance elbow: `NearestNeighbors(n_neighbors=2)`, סידור המרחקים בסדר יורד, איתור הנגזרת השנייה המקסימלית — זה ה-elbow. שימוש ב-`min_samples=2` כי במרחב 7-מימדי עם 50-150 נקודות, הצפיפות נמוכה מטבעה.

**סטטיסטיקת Hopkins H** מחושבת לצד. H ≈ 0.5 = הנתונים אקראיים; H > 0.65 = יש מבנה אשכולות אמיתי.

כותב עמודות `iso_flag`, `iso_score`, `dbscan_label` ל-`ip_agg`.

---

## תא 14 — Z-Scores מול עמיתים מקומיים

`compute_z_scores(S, my_ip)` מסנן את `ip_agg` רק לכתובות IP פרטיות (דרך `is_private`), מחשב ממוצע וסטיית תקן לכל תכונה, ואז `(value − mean) / std` לשורה שמתאימה ל-`my_ip`. מחזיר Series.

הסינון לעמיתים מקומיים קריטי: בלעדיו, ה-baseline כולל IPs של CDN/cloud שמדברים עם המכשיר שלך, מה שמנפח את `mean_len` וגורם ל-Z-score של המכשיר שלך להיבלע לכל מטריקה רגילה.

---

## תא 16 — סריקות אבטחה מבוססות חוקים

`run_security_scans(S)` מריץ 5 סריקות מול `df_pkts` ורשימת החבילות הגולמית:

1. **Credentials של FTP/SMTP** — מחפש ב-payloads של חבילות שורות `USER`, `PASS`, `MAIL FROM`, `RCPT TO` על הפורטים הרלוונטיים.
2. **TCP SYN flood/scan** — מסמן IPs עם `syn_count > 100`.
3. **ARP spoofing** — מסמן IPs שמופיעים עם יותר מ-MAC אחד ב-`arp_ip_to_macs`.
4. **DNS NXDOMAIN spike** — מסמן sessions עם יותר מ-50 תגובות NXDOMAIN.
5. **DNS tunnelling** — מסמן שאילתות ארוכות מ-60 תווים או על פורטי DNS לא סטנדרטיים.

מחזיר dict של שם סריקה → רשימת פריטים מסומנים.

---

## תא 18 — השוואת sessions

`compute_session_compare(S1, S2)` עושה אריתמטיקת קבוצות: `new = ips2 − ips1`, `gone = ips1 − ips2`, `both = ips1 ∩ ips2`. בונה DataFrame השוואה עם נפחי bytes לכל IP לשני ה-sessions ותגיות סטטוס.

---

## תא 20 — Intelligence Insights + דבק הצינור

`generate_insights_lines(s1, s2, local_ip_agg_df, compare_df_arg, my_ip)` מייצר 8 ממצאים אוטומטיים מנתוני runtime:

1. הצומת המקומי הדומיננטי (נפח bytes הגבוה ביותר)
2. המקור החיצוני הגדול ביותר (יעד CDN/cloud)
3. טביעת אצבע של סביבת DNS (8 שירותים מובילים דרך `classify_external_ip`)
4. בריאות ARP (האם יש IP עם יותר מ-MAC אחד?)
5. ספירת שאילתות DNS ארוכות
6. תחלופת IP (ספירות חדש/נעלם)
7. סטטוס credentials של FTP/SMTP
8. המלצת VLAN ל-IoT (מבוסס על קטגוריות המכשירים המסווגים)

`process_session(session, my_ip)` מריץ את הצינור הסשני המלא: ML + Z-scores + סריקות אבטחה + סיווג + insights.

`compute_pair_state(s1, s2, my_ip)` מריץ את הצינור הזוגי: השוואה + תובנות חוצות-sessions.

---

## תא 22 — ארכיטקטורת LSTM

`class LSTMModel(nn.Module)` — LSTM קטן עם:
- מימד קלט 1 (רק גודל חבילה)
- מימד hidden 32
- שכבה אחת
- פלט לינארי ל-1 (חיזוי גודל חבילה הבאה)

---

## תא 24 — אימון LSTM

`SEQ_LEN = 10`, `BATCH = 64`, `EPOCHS = 30`, `PATIENCE = 2`.

`run_lstm_on_session(S, label)` בונה רצפים מקובצי-זמן (bins של שנייה אחת, ממוצע גודל חבילה), מחלק 80/20 כרונולוגית (ללא ערבוב — זה היה גורם ל-leak של עתיד לעבר), מאמן עם MSE loss + Adam, עוקב אחר val loss בכל epoch, עוצר מוקדם אם val loss לא משתפר במשך `PATIENCE` epochs רצופים. משחזר משקלים הטובים ביותר בסוף.

סף אנומליה = `mean(val_err) + 2 * std(val_err)` — משתמש בשגיאות validation לא שגיאות training (כדי שישקף הכללה, לא שינון).

---

## תא 26 — הערכת LSTM

`evaluate_lstm(...)` מריץ את המודל המאומן על כל הרצף, מחשב שגיאה לכל חיזוי, מחזיר את מערך השגיאות והסף עבור גרף ההיסטוגרמה.

---

## תא 37 — מנוע סיווג

התא הכי מורכב מחוץ לדשבורד. טוען שלושה קבצי JSON דרך `_find_config(name)` (מחפש ב-cwd, parent, `/mnt/data`, `/home/claude`):

1. `device_rules.json` → `DEVICE_RULES` (261 חוקים, 12 קטגוריות hierarchy)
2. `cloud_ranges.json` → `CLOUD_RANGES` (27 static + 247 CIDR + 334 rDNS)
3. `dns_fingerprints.json` → `DNS_FINGERPRINTS` (217 טביעות אצבע)

בונה `OUI_DB` מאחד מתוך (לפי סדר עדיפות):
1. קובץ `manuf` של Wireshark (התקנות Linux/macOS/Windows)
2. פלט `tshark -G manuf`
3. חבילת Python `manuf`
4. fallback מובנה של 30 vendors

### `oui_lookup(mac)`
מסיר נקודתיים/מקפים, לוקח את 6 התווים hex הראשונים, מחזיר מחרוזת vendor מ-`OUI_DB`.

### `is_random_mac(mac)`
בודק את ביט ה-U/L של האוקטט הראשון. מוגדר = locally administered (MAC פרטיות אקראי), לא מוגדר = ייחודי גלובלית (vendor אמיתי).

### `_match_dns_fingerprint(dns_queries)`
עובר על 217 טביעות האצבע. לכל אחת, סופר כמה מ-`signature_domains` שלה מופיעים כ-substring (או regex match) של כל שאילתת DNS. אם הספירה מגיעה ל-`match_threshold`, רושם את הטביעה הזו כהתאמה. מחזיר את הטביעה המתאימה ביותר ואת הציון שלה (או `None, 0`).

### `_behavioral_classify(port_set, dns_queries, vendor_from_oui, mac_random)`
ה-fallback האחרון. שרשרת בדיקות דפוסי פורטים:
- 554 → מצלמת IP (RTSP)
- 9100/631/515 → מדפסת
- 5060/5061/2000 → טלפון VoIP (SIP)
- 8008/8009/8443 + vendor Google → Chromecast
- 62078 → iPhone
- 1900 → מכשיר UPnP
- 1883/8883 → MQTT IoT hub
- Web-only עם MAC אקראי → "טלפון או laptop"
- Web-only עם vendor ידוע → "מחשב vendor"
- vendor ידוע ללא פורטים ברורים → "generic vendor endpoint"
- שום דבר → "Network endpoint (no signals available)"

תמיד מחזיר tuple `(classification_dict, confidence_str)`.

### `classify_local_device(mac, mdns_names, ports, dns_queries)`
ה-dispatcher של שלושת השלבים. מחזיר dict עם `category`, `subcategory`, `vendor`, `model`, `rule_id`, `vendor_from_oui`, `mac`, `confidence`, `mac_privacy_random`.

### סיווג כתובות IP חיצוניות
`classify_external_ip(ip, do_rdns=True)`:
1. חיפוש ב-`STATIC_IPS` dict (התאמה מדויקת)
2. עובר על `NETWORKS` (אובייקטי `ip_network` מנותחים מ-`cidr_ranges`) לחברות
3. אם `do_rdns`, עושה חיפוש reverse DNS עם timeout של 0.6s (cached לכל session) ו-regex match מול `_RDNS_REGEXES`
4. אחרת מחזיר `{provider: 'Unknown', service: '', type: 'Unclassified', ...}`

---

## תא 39 — מצאי מכשירים ומדדי כיסוי

`_is_private(ip)` — בודק טווחי RFC 1918 דרך `ipaddress.ip_address(ip).is_private`.

`build_device_inventory(session, my_ip)` — עובר על `session['ip_agg']`, מסווג כל IP פרטי דרך `classify_local_device(...)`, מצמיד את התוצאה לכל שורה. בונה DataFrame עם עמודות: IP, MAC, vendor, category, subcategory, model, confidence, total_bytes, packet_count.

מדדי כיסוי שמחושבים: כמה מכשירים קיבלו סיווג Tier-1 לעומת Tier-2 לעומת Tier-3; לכמה יש vendor ידוע; כמה משתמשים ב-MAC אקראי.

---

## תא 41 — Worker לכידה חיה

`LiveCaptureWorker` הוא צובר בטוח-thread:

```python
class LiveCaptureWorker:
    def __init__(self):
        self.MIN_SECONDS = 30
        self.lock = threading.Lock()
        self.data = {}
        self.stop_event = threading.Event()
        self.thread = None

    def start(self, interface):
        self.reset()
        self.stop_event.clear()
        cmd = [TSHARK_PATH, '-i', interface, '-l', '-T', 'fields', ...]
        self.thread = threading.Thread(target=self._capture_loop, args=(cmd,))
        self.thread.start()

    def _capture_loop(self, cmd):
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, ...)
        while not self.stop_event.is_set():
            line = proc.stdout.readline()
            with self.lock:
                # עדכון מונים אטומי
                ...

    def snapshot(self):
        with self.lock:
            return copy.deepcopy(self.data)

    def stop_and_save(self):
        self.stop_event.set()
        # כותב את הפריימים שנלכדו ל-PCAP בקובץ זמני
        ...
```

`LIVE_SESSIONS = {'S1': LiveCaptureWorker(), 'S2': LiveCaptureWorker()}` — worker אחד לכל משבצת session.

`list_capture_interfaces()` מריץ `tshark -D` ומפרק את הפלט ל-`[(name, description), ...]` עבור ה-dropdown של הדשבורד.

---

## תא 43 — ניתוח גלישה + מפת מכשירים

`CATEGORY_RULES` היא רשימת דפוסי regex שממפים שאילתות DNS לקטגוריות (Streaming, Work, Google/Cloud, Cloud Infra, Social, Security/Update, News/Media, CDN/Infra).

`categorize_dns_query(q)` מחזיר את הקטגוריה הראשונה שמתאימה, או "Other".

`build_browse_by_category(s)` — לכל מכשיר עם שם mDNS, מחשב את האחוז של שאילתות ה-DNS שלו לכל קטגוריה. מחזיר DataFrame ל-stacked bar.

`build_browse_by_hour(s)` — לכל מכשיר, מחלק את timeline ה-DNS שלו לפי שעת היום. מחזיר DataFrame ל-heatmap.

`_build_device_map_figure(session, label)` — מריץ PCA על מטריצת תכונות המכשיר המסווג (one-hot category + תכונות מספריות) ומייצר scatter 2D צבוע לפי קטגוריה.

---

## תא 45 — בניית כל הגרפים

```python
import plotly.io as _pio
_pio.templates.default = "none"
```

השורות הראשונות קובעות את ברירת המחדל של Plotly template ל-"none". זה עוקף את מנגנון `apply_default_cascade` של Plotly לחלוטין, ומונע קריסת template-corruption שיכולה לקרות אחרי הרבה rebuilds.

`make_figures(s1, s2, compare_df, z_scores, my_ip)` בונה 26 גרפי בסיס באמצעות `plotly.express` ו-`plotly.graph_objects`. נושאים:

- talkers, burst, proto, dns, devices, timeline, lstm
- profile (radar), zbar (signed bar)
- browse_cat, browse_hour, browse_cat_s1, browse_hour_s1
- syn, confusion, sensitivity
- cmp_traffic, cmp_new_gone, cmp_delta

ואז קריאות לכל session ל-`_build_device_map_figure()` ול-`_build_proximity_map_figure()` מוסיפות עוד 4 (`device_map`, `device_map_s2`, `proximity`, `proximity_s2`).

`_apply_aurora_layout(figs)` מחיל את עיצוב Aurora על כל גרף: רקעים שקופים, זוג גופנים Inter Tight + Newsreader, צבעי צירים עמומים, hover labels בסגנון glass-panel.

`_estimate_distance_m(rssi, tx=20, n=2.5, pl_d0=40)` מיישם את מודל הנחתת מסלול לוגריתמי פנימי.

`_build_proximity_map_figure(session, title_label)` בוחר בין מצב RSSI (אם ב-`wlan_features` יש דגימות RSSI כלשהן) לבין מצב התנהגותי (אחרת). המסלול ההתנהגותי מריץ MDS על `1 − Pearson_correlation` של bins פעילות של 30 שניות.

`rebuild_figures()` הוא ה-orchestrator שהדשבורד קורא אליו כשנטען PCAP חדש.

---

## תא 47 — דשבורד (עיצוב Aurora + מסך פתיחה CRT)

התא הגדול ביותר במחברת. מגדיר:

- פלטת צבעים: `INK`, `INK_DIM`, `INK_MUTE`, `VIOLET`, `CYAN`, `MAGENTA`, וכו'
- CSS ב-`AURORA_INDEX_STRING` (טיפוגרפיה, animations, utility classes של glass-panel)
- `_NETSEC_LETTERS` — קואורדינטות פיקסל-גריד עבור N, E, T, S, C
- `_build_netsec_crt_logo()` — מחזיר Base64 SVG data URL עבור הלוגו פיקסל-ארט הוורוד
- `_build_intro_splash()` — מרכיב את מסך הפתיחה של מסוף CRT (prompt CLI ירוק, לוגו NETSEC ורוד, עץ תיקיות מזויף, סמן מהבהב, שכבת scanline)
- `build_intro_view()` — תצוגת הברוכים-הבאים/הסבר שמכילה את מסך הפתיחה
- `build_choice_view()` — בורר העלאה/הקלטה
- `build_main_view()` — דשבורד הניתוח עם sidebar + topbar + chart panel
- `_build_second_pcap_modal()` — modal "Load Second PCAP"
- Topbar עם 6 KPI חיים + כפתור Load Second PCAP
- Sidebar עם `NAV_ITEMS` (28 entries ב-7 חלקים)
- Dash callbacks: `splash_to_choice`, `choice_to_main`, `click_nav`, `render_chart`, `brand_to_home`, `restart_app`, `open_second_pcap_modal`, ועוד שרשרת callback של live-capture

הדשבורד משתמש ב-`dcc.Store` למצב client-side כי Dash callbacks לא יכולים לשתף משתני Python globals בין דפדפנים.

האפליקציה משוגרת דרך `app.run(host='127.0.0.1', port=8050, jupyter_mode='external')`.

---

## תאים 48-49 — ריקים

שמורים להרחבות עתידיות.
