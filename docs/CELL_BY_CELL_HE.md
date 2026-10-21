<div dir="rtl" align="right">

# מדריך תא-אחר-תא - דשבורד Network Security

> גרסה עברית של [`CELL_BY_CELL_EN.md`](CELL_BY_CELL_EN.md).

ה-notebook מכיל 50 תאים (25 קוד, 25 markdown). המסמך הזה עובר על
כל תא קוד בסדר הופעתו ב-`app/Network_Security_Dashboard.ipynb`.
הנרטיב תואם לקוד שנשלח היום; כשערכים חשובים (ספירות פיצ'רים, ספים,
‏hyperparameters) אלה הערכים שהקוד בפועל משתמש בהם.

## ארכיטקטורה כללית

סדר ייבוא: ה-notebook קודם מגדיר הכל (קבועים, helpers, מגלים, בוני
צ'ארטים, callbacks) ורק משיק את אפליקציית Dash בתא הקוד האמיתי
האחרון (48). תאים 28/29/31/33/35 הם stubs של `pass` שנשארים במקום
כך שמספרי התאים יישארו יציבים עם כותרות ה-markdown הישנות; תא 49
הוא בלוק אינטגרציית client-side שמייבא את ה-helpers של צד ה-VM
כשהם נוכחים.

```
תא 0..3     Markdown   כותרת, מבוא, הסברי שכבות TCP/IP
תא 4         קוד        ייבואים, התקנת pip אוטומטית, באנר, גילוי tshark
תא 5         Markdown   הנחיית נתיבי קבצים
תא 6         קוד        קבועי העלאה, MY_DEVICE_IP, פענוח העלאה + אימות נתיב
תא 7         Markdown   מבוא למנוע ניתוח PCAP
תא 8         קוד        analyze_pcap  (loader מהיר של tshark + fallback של scapy)
תא 9         Markdown   מבוא למצב session
תא 10        קוד        S1 / S2 / SESSION_PCAPS + load_session_from_pcap
תא 11        Markdown   מבוא לאיכות נתונים
תא 12        קוד        run_ml_on_session  (IsolationForest + DBSCAN)
תא 13        Markdown   מבוא ל-feature engineering
תא 14        קוד        compute_z_scores  (התקן מול peers מקומיים)
תא 15        Markdown   בחירת מודל ML
תא 16        קוד        run_security_scans  (מנוע חוקים דטרמיניסטי)
תא 17        Markdown   אימון ML / hyperparameters
תא 18        קוד        compute_session_compare  (set diff של S1 מול S2)
תא 19        Markdown   הערכת ML
תא 20        קוד        generate_insights_lines + process_session + compute_pair_state
תא 21        Markdown   מבוא לארכיטקטורת LSTM
תא 22        קוד        מחלקת LSTMModel
תא 23        Markdown   מבוא לאימון LSTM
תא 24        קוד        train_lstm_for_session  (SEQ_LEN=10, MAX_EPOCHS=15)
תא 25        Markdown   מבוא להערכת LSTM
תא 26        קוד        evaluate_lstm
תא 27        Markdown   מבוא לפרופילינג התקן
תאים 28-35   בעיקר `pass`  (סקשנים ישנים הועברו לתאים אחרים;
                             כותרות markdown שרדו למספור פרקים)
תא 36        Markdown   מבוא למנוע סיווג
תא 37        קוד        מנוע סיווג (קונפיגורציות JSON, DB של OUI, מסווג 3 שכבות)
תא 38        Markdown   מבוא למצאי
תא 39        קוד        מצאי + ציון איום + כיסוי
תא 40        Markdown   מבוא ל-capture חי
תא 41        קוד        LiveCaptureWorker (קורא ring של tshark + snapshot + merge)
תא 42        Markdown   מבוא לניתוח גלישה
תא 43        קוד        קטגוריית גלישה / שעה, confusion matrix, צ'ארט sensitivity sweep
תא 44        Markdown   מבוא לויזואליזציה
תא 45        קוד        make_figures + _build_device_map_figure + _build_proximity_map_figure
תא 46        Markdown   מבוא להשקת דשבורד
תא 47        קוד        מנועי Advanced Threat Detection (beaconing, DNS tunneling, DGA, ARP/DHCP, TLS, fusion)
תא 48        קוד        אפליקציית Dash - ‏Aurora theme, layout, ‏38 callbacks server + 12 clientside, ‏app.run()
תא 49        קוד        VM client integration shim (ייבוא server.dashboard_client)
```

זוג ה-single-source-of-truth הוא `app/Network_Security_Dashboard.ipynb`
(סמכותי) ו-`app/dashboard_module.py` (ייצוא byte-exact). ה-exporter
הוא `tools/export_dashboard_module.py` ו-CI מריץ אותו עם `--check`
בכל push כך שהשניים לא יוכלו לסטות בשקט.

---

## תא 4 - ייבואים וסביבה

**מטרה:** לוודא שכל ספרייה נדרשת מותקנת; לאתר את `tshark` ואת
קובץ `manuf` של Wireshark בדיסק.

עובר על רשימת `PKGS` שמממפת שמות pip לשמות ייבוא. לכל אחד, מנסה
`import`; אם זה נכשל, מריץ `pip install --quiet`. מייבא את מערך
זמן הריצה: ‏numpy, ‏pandas, ‏torch, ‏scikit-learn, ‏plotly, ‏dash,
‏dash_bootstrap_components, ‏scapy, ‏`manuf` (best-effort).

מדפיס באנר גרסה שמציין כל חבילה pinned. אז מאתר `tshark`:

1. `shutil.which("tshark")`
2. נתיבי התקנה נפוצים: ‏`/usr/bin/tshark`, ‏`/usr/local/bin/tshark`,
   `/Applications/Wireshark.app/Contents/MacOS/tshark`,
   `C:\Program Files\Wireshark\tshark.exe`,
   `C:\Program Files (x86)\Wireshark\tshark.exe`

התוצאה שמורה ב-cache כ-`_TSHARK_PATH_FOR_LOADER`. קובץ `manuf`
של Wireshark מתגלה באותה דרך לתוך `MANUF_PATH`. ‏tshark חסר אינו
קטלני - ה-fallback של scapy בתא 8 תופס.

**תופעות לוואי:** ‏`scapy.conf.verb = 0`, ‏`warnings.filterwarnings("ignore")`.

---

## תא 6 - קבועי העלאה + מאמתים

**מטרה:** הקבועים וה-helpers שקריאות הקלט לקובץ של הדשבורד
משתמשות בהם.

קבועים: ‏`PCAP1 = None`, ‏`PCAP2 = None`, ‏`CSV1 = None`, ‏`CSV2 = None`,
`MY_DEVICE_IP = os.environ.get("NETSEC_MY_DEVICE_IP", "")` (ריק כברירת
מחדל; ריק אומר שתצוגת הפרופיל בוחרת אוטומטית את ההתקן המקומי העמוס
ביותר). ‏`MAX_UPLOAD_BYTES = 100 * 1024 * 1024` ו-
`MAX_UPLOAD_HUMAN = "100 MB"` חוסמים את נתיב ה-drag-and-drop;
לקלט נתיב ההדבקה אין תקרת גודל.

פונקציות:

- `decode_uploaded_pcap(contents, filename)` מפצל את ה-data URL,
  מפענח base64, אוכף `MAX_UPLOAD_BYTES`, מנקה את שם הקובץ ל-
  `[alnum._-]`, מכריח את ה-suffix ל-`.pcap` / `.pcapng`, וכותב
  לנתיב `tempfile.mkstemp(prefix="netsec_upload_")`. מחזיר
  `(path, error)`.
- `validate_pcap_path(text)` חותך גרשים, בודק `exists` /
  `isfile`, אוכף את ה-whitelist של סיומות `{.pcap, .pcapng, .cap}`,
  ודוחה קבצים אפס-בייט.

אף אחד מהמאמתים לא בודק magic-byte של הקובץ - קובץ שלא-PCAP בשם
שגוי מגיע ל-tshark ונכשל עמוק יותר עם `RuntimeError` של "tshark
החזיר 0 שורות".

---

## תא 8 - מנוע קליטת PCAP

**מטרה:** פענוח PCAP ל-dict מובנה של session שכל שלב downstream
צורך.

### Helpers
- `_safe_epoch(dt)` / `_safe_fromtimestamp(ts)` נמנעים מהקריסה
  של Windows על epoch שלילי על captures ש-timestamps שלהם לפני
  1970.
- `_find_tshark()` מחזיר את נתיב ה-loader השמור ב-cache.
- `_extract_wifi_ssid_bssid(path)` מריץ `tshark -Y wlan.fc.type==0 ...`
  למשוך זוגות Beacon / Probe-Response של SSID+BSSID; בשימוש על ידי
  מפת Wigle בצד ה-VM. מדולג כשל-capture אין frames של WLAN.

### `_analyze_pcap_tshark(path, label)`
בונה פקודת tshark עם **‏25 שדות**, ‏`sep="|"`, ללא שורת כותרת:

```
frame.time_epoch, frame.len,
eth.src, eth.dst, ip.src, ip.dst, ipv6.src, ipv6.dst,
_ws.col.Protocol,
tcp.srcport, tcp.dstport, tcp.flags,
udp.srcport, udp.dstport,
dns.qry.name, dns.flags.rcode, dns.flags.response,
arp.src.proto_ipv4, arp.src.hw_mac,
wlan.fc.type, wlan.fc.subtype, wlan.sa, wlan.fc.retry,
radiotap.dbm_antsignal, wlan_radio.signal_dbm
```

פלט tshark המלא נתפס בזיכרון
(`subprocess.check_output(...)`), מפוענח דרך
`pd.read_csv(io.StringIO(out), sep="|")`, ואז pass יחיד בונה:

| מבנה | תוכן |
|---|---|
| `ips_src` / `ips_dst` | ספירות פקטות פר-IP מקור / יעד (v4 או v6, מאוחדים) |
| `bytes_src` / `bytes_dst` | נפחי בייטים פר-IP |
| `protocols` | מונה פרוטוקולים (שם שכבה אחרונה) |
| `macs` | ספירת פקטות פר-MAC |
| `dns_real`, `dns_timeline`, `dns_per_ip`, `mdns_per_ip`, `dns_nxdomain`, `dns_nonstandard`, `dns_long_queries`, `nxdomain_per_dst` | אגרגטי DNS |
| `dns_amp_per_src` | מועמדי reflector לחוק ה-amp |
| `arp_ip_to_macs` | dict של `ip -> set(macs)` לזיהוי ARP-spoof |
| `syn_counter`, `rst_counter`, `fin_counter`, `null_counter`, `xmas_counter` | מוני flags של TCP פר-מקור (מסוכים עם `0x3F` כך ש-ECE/CWR מתעלמים) |
| `ports_per_ip` | איחוד פר-IP של פורטי tcp/udp src+dst (לסיווג) |
| `ip_agg` | frame פיצ'רים פר-IP (ראו תא 12) |
| `timeline_df`, `pkt_sizes` | לצ'ארטי ה-timeline וה-burst |
| `wlan_features` | דגימות RSSI פר-MAC, ספירת probe request, ספירת association, ספירת retry |
| `wifi_bssid` | BSSIDs שנראו (בשימוש על ידי מפת geo של Wigle ב-VM) |
| `t0`, `t1` | timestamp מוקדם ביותר / מאוחר ביותר של פקטה |

`wlan_features` מאוכלס רק כאשר ה-capture באמת מכיל שדות
`wlan.*` (802.11 monitor mode). ‏captures של Wi-Fi של Windows
לרוב מציגים Ethernet מפורק, אז זה נשאר ריק ו-`wlan_available`
יורד ל-`False`.

### `_analyze_pcap_scapy(path, label)`
‏Fallback לכאשר tshark לא זמין. משתמש ב-`scapy.rdpcap` ומבצע
איטרציה על פקטות, מפיק את אותה סכמת dict עם
`wlan_features = {}` ו-`wlan_available = False` (scapy ללא
monitor-mode לא רואה את שכבת הרדיו).

### `analyze_pcap(path, label)` (dispatcher)
קורא ל-`_analyze_pcap_tshark` קודם; בכל חריגה נופל ל-
`_analyze_pcap_scapy` (עם אזהרה מודפסת ל-stdout).

---

## תא 10 - חריצי session

מאתחל את מצב ה-session ברמת המודול שהדשבורד משנה כשהמשתמש
טוען captures:

```
S1 = None
S2 = None
ip_agg = None                              # frame פר-IP של ה-session האחרון
z_scores = None                            # Z-scores של ה-session האחרון
local_ip_agg = None
extern_ip_agg = None
compare_df = None                          # frame delta של S1 מול S2
new_n = 0
gone_n = 0
SESSION_PCAPS = {"S1": None, "S2": None}   # נתיב PCAP מקור לכל חריץ
INSIGHTS_LINES = []
```

`load_session_from_pcap(path, label)` הוא wrapper דק סביב
`analyze_pcap` שגם רושם את נתיב המקור ב-`SESSION_PCAPS`.
ממצאי אבטחה מאוחסנים ב-`S["_security_findings"]` בזמן ניתוח,
לא ב-dict ברמת מודול, אז כל צרכן קורא אותם מאותו dict של session
שעמודות ה-ML חיות בו.

---

## תא 12 - ML לא-מפוקח

`run_ml_on_session(S)` בונה את מטריצת **‏10 הפיצ'רים** מ-
`S["ip_agg"]`, מנרמל אותה ב-`StandardScaler`, ומריץ:

**‏IsolationForest** ב-`contamination = 0.10` הקבוע,
`n_estimators = 200`, `random_state = 42`. סריקה של 20 נקודות
נגרסה אחרי מדידה שלא הראתה שיפור על פני 0.10 הקבוע
(F1 ממוצע 0.247 מול 0.250 על פני 5 seeds מול ground truth
המתויג של `attack_tests`, בעלות fit פי-15). ראו
`docs/TRADEOFFS_EN.md` §7 לטיעון המלא. כותב
`iso_score` (decision_function), `iso_flag`, `anomaly` (`==-1`) ו-
`iso_stability` עמודות ל-`ip_agg`.

**‏DBSCAN** עם `eps` ממרפק k-distance (`k=2`
`NearestNeighbors`, מיון מרחקים יורד, לקיחת argmin של diff-of-diff
כמרפק), בתוספת שני שומרים:

- **קריסת eps**: כשהמרפק קורא `eps <= 0` (הצפות מקור מזויף שבהן
  כל נקודה יושבת על אותו וקטור פיצ'רים),
  `eps = max(mean(k_dist), 0.05)`.
- **‏cap נפח**: כאשר `len(ip_agg) > 5000`
  (`DBSCAN_MAX_IPS = 5000`), ‏DBSCAN מדולג לחלוטין - כל שורה
  מתויגת `cluster = -1` - כדי להימנע מהתפוצצות שכונה O(n²) על
  captures עם עשרות אלפי IPs מקור.

`min_samples = 2`. ‏Silhouette מחושב על הנקודות non-noise בלבד
כאשר יש ≥ 2 אשכולות, אחרת נשמר כ-`None`. `dbscan_meaningful`
רושם האם נמצא לפחות אשכול אמיתי אחד.

ערכים מאוחסנים ב-`ip_agg.attrs` עבור תצוגת Model Diagnostics:
`_chosen_contamination`, `_eps_auto`, `_min_samples`, `_silhouette`,
`_n_clusters`, `_n_noise`.

10 עמודות הפיצ'רים הן:

```
mean_len, std_len, count, burst_score, unique_dsts,
syn_count, rst_count, fin_count, null_count, xmas_count
```

---

## תא 14 - Z-scores מול peers מקומיים

`compute_z_scores(S, my_ip)` מסנן את `ip_agg` ל-IPs פרטיים בלבד דרך
`_is_private` ברמת המודול (תא 39), מחשב `mean` ו-`std`
פר-פיצ'ר על קבוצת ה-peers, ואז מחזיר
`(value - mean) / std` עבור השורה שתואמת ל-`my_ip` כ-`pd.Series`.

מסנן ה-local-peer קריטי: בלעדיו, הבייסליין היה כולל יעדי CDN/ענן
שערכי הפיצ'רים שלהם היו מנפחים את הממוצע ומגמידים את ה-Z-score של
ההתקן שלכם לכל מטריקה רגילה.

---

## תא 16 - מנוע חוקים דטרמיניסטי

`run_security_scans(S)` הוא **סוס העבודה** של הזיהוי. על captures
של תקיפות מתויגים החוקים תופסים 100% מהתוקפים המתויגים; תפקיד שכבת
ה-ML הוא למצוא את מה שהחוקים פספסו. מריץ את הסריקות הבאות ומחזיר
dict עם המפתחות המדויקים שמוצגים:

- `scan_alerts` - זיהוי סריקות אופקיות פר-flag (SYN / FIN / NULL /
  Xmas). מקור מתאים כאשר `count > 50` וגם
  ((`unique_dsts > 20` וגם יחס ה-flag > 0.25) או שיחס
  flag-to-packets חורג מ-0.7). שער היחס על ענף היעדים הרבים שומר
  מ-client רגיל שמגיע ל-20+ hosts ביחס SYN נמוך מלהידלק.
- `dns_amp` - רפלקטורים (נבנה מ-`dns_amp_per_src`): שולחי תגובת
  DNS עם `count >= 50` וגם `mean_size >= 200` בייטים.
- `flood` - הצפת SYN אגרגטיבית: ‏`total_syn >= 1000` וגם
  `n_syn_srcs >= 100` וגם `syn_rate >= 100/s`. גם מדווח על
  ‏`spoofed_source_pattern` boolean (`total_syn / n_srcs <= 3`).
- `arp_spoofing` - ‏IPs שממופים ליותר מ-MAC אחד ב-
  `arp_ip_to_macs`.
- `ftp` / `smtp` - היוריסטיקות אישורי plaintext שסורקות את רשימת
  הפקטות ל-`USER|PASS|RETR|STOR` (פורטים 21 / 25 / 587). אלה
  דורשות שפקטות יהיו זמינות ב-`S["pkts"]`, שמאוכלס רק בנתיב של
  scapy היום - ה-loader המהיר של tshark שומר `pkts=[]`.
- `syn_top`, `rst_top`, `fin_top`, `null_top`, `xmas_top` - שולחים
  מובילים פר-flag (לטבלאות אבטחה).
- `dns_long` - שאילתות DNS ארוכות מ-60 תווים.

שמות המפתחות המובחנים חשובים: הרכבת המועמדים של שופט LLM
(`llm_judge/judge_core.assemble_candidates`) קוראת רק
`scan_alerts`, `amp_alerts`, `flood_alerts`, `arp_spoofing_ips` מה-
dict ש-`attack_tests/run_pipeline.py` מפיק, שהיא יישום נפרד של
אותם חוקים ששומר על זהות מבנית.

---

## תא 18 - השוואת session

`compute_session_compare(S1, S2)` מריץ אריתמטיקת קבוצות על ה-IPs
שנוכחים בכל session:

```
new  = ips2 - ips1
gone = ips1 - ips2
both = ips1 & ips2
```

מחזיר DataFrame עם עמודות `ip`, `bytes_s1`, `bytes_s2`,
`change`, `status ∈ {both, new, gone}`. תצוגות ההשוואה
(`cmp_traffic`, `cmp_new_gone`, `cmp_delta`) כולן קוראות מה-frame
הזה, אז הן מרנדרות מצב ריק עד ש-session שני נטען.

---

## תא 20 - תובנות + דבק צינור

`generate_insights_lines(s1, s2, local_ip_agg_df, compare_df_arg, my_ip)`
מפיק 8 one-liners שנוצרו אוטומטית שסקשן התובנות מראה:

1. דובר מקומי דומיננטי (נפח בייטים הגבוה ביותר)
2. יעד חיצוני גדול ביותר
3. ‏fingerprint של סביבת DNS (8 שירותים מובילים דרך
   `classify_external_ip`)
4. בריאות ARP (כל IP עם >1 MAC?)
5. ספירת שאילתות DNS ארוכות
6. ‏churn של IP (ספירות חדשים / שנעלמו)
7. חשיפת אישורי FTP / SMTP
8. המלצת VLAN ל-IoT (מבוסס על קטגוריות התקנים מסווגים)

`process_session(session, my_ip)` הוא ה-driver פר-session:
‏ML + Z-scores + חוקים + סיווג + תובנות.

`compute_pair_state(s1, s2, my_ip)` הוא ה-driver ברמת הזוג:
השוואה + תובנות חוצות-sessions.

---

## תא 22 - ארכיטקטורת LSTM

```python
class LSTMModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.lstm = nn.LSTM(input_size=1, hidden_size=64, batch_first=True)
        self.head = nn.Linear(64, 1)
```

רגרסור קטן של הערך הבא על המצב החבוי האחרון.

---

## תא 24 - אימון LSTM

קבועים: ‏`SEQ_LEN = 10`, `MAX_BINS = 20000`. ‏Hyperparameters של זמן
ריצה בתוך `train_lstm_for_session`: ‏`MAX_EPOCHS = 15`, `PATIENCE = 2`,
`batch_size = 512`, `Adam(lr=1e-3)`, MSE loss.

אות: **גודל פקטה ממוצע פר-מקבץ של שנייה**, מולא באפסים לשניות סרק
(שניות שעון-קיר - לא seconds-with-traffic - אז פערים ארוכים
מראים כ-bursts בשני הצדדים). אם יותר מ-`MAX_BINS` מקבצים נוכחים,
הסדרה decimated ב-stride ל-`MAX_BINS`.

שער אימון: צריך לפחות 20 מקבצים שמישים (`SEQ_LEN=10` + רצפת
10-sequence). ‏captures קצרים יותר מדלגים על LSTM בשקט - החוקים
הדטרמיניסטיים מכסים אותם.

פיצול: כרונולוגי 80/20 (ערבוב אקראי היה מדליף עתיד לעבר).
‏Checkpoint של best-val נשמר ל-
`tempfile.gettempdir()/lstm_best_<label>.pt` ונטען מחדש בסוף.

---

## תא 26 - הערכת LSTM

`evaluate_lstm(...)` מריץ את המודל המאומן על כל הרצף ומחשב שגיאת
חיזוי פר-רצף. **הסף** של האנומליה הוא
`val_errors.mean() + 2 * val_errors.std()` - נמדד על פרוסת
ה-validation המופרשת, לא על סט האימון, אז הסף משקף הכללה. שומר
`lstm_errors` (כל הרצפים) ו-`lstm_threshold` ב-dict ה-session.

---

## תאים 28, 29, 31, 33, 35 - Stubs

כל אחד מכיל `pass` יחיד. הם קיימים כי מספור הסקשן ב-markdown היה
קשור היסטורית לאינדקסי תאי קוד, ותוכן הסקשנים האלה אוחד מאוחר יותר
לתאים 12 / 16 / 18 / 20. הסרתם הייתה ממספרת מחדש כל תא וכל התייחסות
לאינדקס תא על פני ה-codebase. הם compile לכלום.

---

## תא 37 - מנוע סיווג

טוען שלושה קבצי JSON דרך `_find_config(name)`, שמחפש
`NETSEC_APP_DIR`, תיקיית ה-notebook, הורה שלה, ו-`~/`:

1. `device_rules.json` → `DEVICE_RULES` (261 חוקים ממוינים לפי
   `priority` יורד; 12 קטגוריות היררכיה)
2. `cloud_ranges.json` → 27 IPs סטטיים + 247 טווחי CIDR + 332
   תבניות regex של rDNS
3. `dns_fingerprints.json` → 217 ‏fingerprints

`_load_oui_db()` בונה `OUI_DB` מאחד מאלה, בסדר:

1. קובץ `manuf` של Wireshark (נתיבי התקנה של Linux / macOS / Windows
   שהתגלו בתא 4)
2. פלט `tshark -G manuf`
3. חבילת Python ‏`manuf`
4. ‏fallback משובץ של 30 vendors

Helpers פומביים:

- `oui_lookup(mac)` חותך separators, לוקח את 6 תווי ה-hex הראשונים,
  מחזיר את מחרוזת ה-vendor.
- `is_random_mac(mac)` בודק את ה-bit של U/L של ה-octet הראשון
  (`first & 0b10`); set = ‏MAC פרטיות מנוהל מקומית.
- `_match_dns_fingerprint(dns_queries)` עובר על 217 ה-fingerprints,
  מתאים substring של כל דומיין חתימה מול סט השאילתות (ומתאים
  regex אם החתימה מכילה metacharacters של regex). ה-fingerprint
  המדורג הגבוה ביותר שמעל `match_threshold` שלו מנצח.
- `_behavioral_classify(port_set, dns_queries, vendor, mac_random)`
  הוא ה-fallback הסופי. היוריסטיקות פורטים: 554→מצלמת IP;
  {9100,631,515}→מדפסת; {5060,5061,2000}→טלפון VoIP;
  {8008,8009,8443}+vendor של Google→‏Chromecast; 62078→‏iPhone;
  1900→‏UPnP; {1883,8883}→‏MQTT; ‏web-only עם MAC אקראי→"טלפון
  או מחשב נייד"; ‏web-only עם vendor ידוע→"מחשב vendor"; ‏vendor
  ידוע ללא פורטים ברורים→"generic vendor endpoint"; כלום→
  "Network endpoint".

`classify_local_device(mac, mdns_names, ports, dns_queries)` הוא
ה-dispatcher של 3 השכבות. שכבה 1 חוקים של `device_rules.json`
(סוגי תנאים: `vendor_match`, `mdns_regex`, `ports_any`,
`dns_regex`; ‏confidence מה-`priority` של החוק - ≥800 גבוה, ≥500
בינוני, ≥200 נמוך, אחרת very-low). שכבה 2 ‏fingerprints של DNS.
שכבה 3 ה-fallback ההתנהגותי. מחזיר dict עם
`category, subcategory, vendor, model, rule_id, vendor_from_oui,
confidence, mac_privacy_random`.

סיווג IP חיצוני חי באותו תא:
`classify_external_ip(ip, do_rdns=None)`. סדר:

1. התאמה מדויקת ב-27 ה-IPs הסטטיים
2. סריקה לינארית של 247 אובייקטי `ip_network` של CIDR לחברות
3. חיפוש reverse-DNS (**‏opt-in דרך `NETSEC_ENABLE_RDNS=1`**, כבוי
   כברירת מחדל כי זה מייצר שאילתות PTR על הרשת המנוטרת;
   0.6 שניות לחיפוש, עד 20 workers, חסום על ידי בייטים ל-200 IPs)
   מותאם מול 332 regexes של rDNS
4. מחזיר `{provider: "Unknown", service: "", type: "Unclassified", ...}`

---

## תא 39 - מצאי, ציון איום, כיסוי

`_is_private(ip)` משתמש ב-`ipaddress.ip_address(ip).is_private`
(‏RFC 1918 + link-local + loopback).

`_pick_dominant_mac(mac_counter)` בוחר את ה-MAC הנפוץ ביותר שנראה
עבור IP (התקן ששינה MAC באמצע ה-capture מניב את ה-MAC של הרוב).

`_derive_device_name(ip, mdns_names, model)` מפיק שם ידידותי -
‏hostname של mDNS כשנוכח (עם suffix של `.local` נחתך נכון כ-suffix,
לא כסט תווים - ראו רגרסיה ב-
`tests/test_device_name_derivation.py`), אחרת `<model>-<last_octet>`.

`compute_threat_score(ip, session)` הוא ציון אדיטיבי מבוסס-חוקים
בלבד חסום ב-100, עם שכבות CRITICAL ≥75 / HIGH ≥50 / MEDIUM ≥25 /
LOW אחרת. אותות תורמים:

| אות | נקודות |
|---|---|
| ‏SYN ≥ 1000 / ≥ 200 / ≥ 50 | 30 / 15..30 / עד 10 |
| ‏unique_dsts ≥ 200 / ≥ 100 / ≥ 50 | 20 / עד 15 / 5 |
| ‏RST ≥ 100 | עד 10 |
| פורטים נבדלים ≥ 100 / ≥ 30 | 10 / 5 |
| חוסר עקביות ARP IP-to-MAC | +25 |
| שאילתות DNS ארוכות (>60 תווים, פר-IP) | עד 15 |
| ‏NXDOMAIN ל-IP זה ≥ 50 | עד 10 |
| ≥ 3 אותות עצמאיים | +10 |

`build_local_inventory(session)` עובר על `ips_src`, שומר רק IPs
פרטיים, מסווג כל אחד, ומחזיר DataFrame עם `ip`, `mac`,
`category`, `subcategory`, `vendor`, `model`, `confidence`,
`mac_privacy_random`, `threat_score`, `threat_tier`, `threat_reasons`,
`packets`, `bytes`, `ports`, `rule_id`, `vendor_oui`, `device_name`.

`build_external_inventory(session, do_rdns=None, max_rdns=200)` משקף
את הנתיב הפרטי עבור IPs חיצוניים. `compute_coverage(local_inv,
external_inv)` מחזיר ספירות סיווג פר-שכבה עבור gauges הכיסוי.

המצאים חיים ב-globals של המודול (`LOCAL_INV_S1`, `LOCAL_INV_S2`,
`EXTERNAL_INV_S1`, `EXTERNAL_INV_S2`, `COVERAGE_S1`, `COVERAGE_S2`),
מרועננים על ידי `rebuild_inventories()` בתא 45.

---

## תא 41 - ‏Capture חי

`LiveCaptureWorker` מריץ `tshark -i <iface> -w chunk -l -T fields
-E separator=|` עם 18 שדות תחת lock, קורא כל שורה למונים פר-IP.
התנגשות interface מוגנת על פני workers. מכונת מצבים:
‏`idle → recording ⇄ paused → saved`, עם
`threading.Timer` שאוכף אורך session מינימום/מקסימום
(`MIN_SECONDS = 120`, `MAX_SECONDS = 3600`). ‏`stderr` מועבר ל-
`DEVNULL` בכוונה - ‏pipe היה נתפס ב-deadlock על שורת ספירת פקטות
של tshark.

`stop_and_save()` ממזג את ה-chunks המוקלטים עם `mergecap`; אם
`mergecap` חסר הוא שומר רק את ה-chunk הראשון ומדווח על אובדן
הנתונים ב-`error_msg`.

`LIVE_SESSIONS = {"S1": LiveCaptureWorker(), "S2": LiveCaptureWorker()}`
- ‏worker אחד לכל חריץ session.

`list_capture_interfaces()` מריץ `tshark -D` ומפענח
`[(name, description), ...]` ל-dropdown של ה-interface; התוצאה
שמורה ב-`_INTERFACE_LIST_CACHE`. שגיאות בכוונה לא נשמרות ב-cache
כך ש-tshark שבור יורה שוב את subprocess הבדיקה רק כשהפאנל
מרנדר מחדש.

**נתיב ה-analyze** להקלטה חיה מתעלם מה-`snapshot()` בזיכרון
וקולט מחדש את ה-PCAP הממוזג דרך הנתיב הסטנדרטי של
`_ingest_pcap_from_path`, כך ש-session חי מקבל את אותם פלטים של
`threats` / מנועים מתקדמים כמו PCAP שנטען.

---

## תא 43 - ניתוח גלישה, בלבול, רגישות

`CATEGORY_RULES` היא רשימה של tuples ‏`(name, regex)` שממפים שאילתות
DNS לקטגוריות גלישה (‏Streaming, ‏Work / Productivity,
‏Google / Cloud, ‏Cloud Infra, ‏Social, ‏Security / Update,
‏News / Media, ‏CDN / Infra). ‏`classify_domain(q)` מחזיר את הקטגוריה
המתאימה הראשונה או `"Other"`.

`make_browsing_category_fig(s, label, device_names_map)` ו-
`make_browsing_hour_fig(s, label, device_names_map)` מרנדרים את
‏bar הקטגוריה הנערם ואת heatmap הפר-שעה לכל התקן בשם.

`make_confusion_matrix_fig(s1, s2)` מרנדר מטריצת הסכמה 2×2 של
IsolationForest × DBSCAN פר-session, כך שקורא יכול לראות באיזו
תדירות שני מודלי ה-ML מצביעים על אותו IP.

`make_sensitivity_sweep_fig(ip_agg_or_features)` מתאים 20 מודלי
IsolationForest על פני `linspace(0.02, 0.30, 20)` (`n_estimators=100`
- זול יותר במכוון מה-`200` של פרודקשן) ומשרטט את ה-tradeoff של
ה-flagged-count, מצייר קו "Chosen" אנכי ב-
`_chosen_contamination` (0.10 היום). זה **ויזואליזציה בלבד**;
מודל הפרודקשן תמיד משתמש ב-0.10 הקבוע מתא 12.

`build_browse_figures(S1, S2)` מתזמר את צ'ארטי הגלישה פר-session
ומאחסן אותם ב-globals של המודול (`FIG_BROWSE_CAT_S1`,
`FIG_BROWSE_CAT_S2`, `FIG_BROWSE_HOUR_S1`, `FIG_BROWSE_HOUR_S2`,
`FIG_CONFUSION`, `FIG_SENSITIVITY`).

---

## תא 45 - מפעל הצ'ארטים

`make_figures(s1, s2, cdf, z_scores_df, my_ip)` הוא מפעל ~30 הצ'ארטים
שמאכלס את `FIGS`. נושאים: ‏top talkers, ‏burst timeline מול
scan, פרוטוקולים, ‏DNS, התקנים, ‏timeline, היסטוגרמת שגיאות LSTM
וקו סף, radar של פרופיל פר-התקן, ‏bar של Z-score חתום,
פעילות DNS פר-שעה, התפלגויות flags של TCP, השוואת S1↔S2
(‏delta של תעבורה, חדשים / שנעלמו, ‏delta של בייטים), ותאומי
S1 / S2 פר-צ'ארט.

כל צ'ארט עובר דרך `_apply_aurora_layout(fig)` שמגדיר את ה-theme
של Aurora: רקעים שקופים, זוג פונטים Inter Tight + Newsreader,
צבעי צירים מעומעמים, תוויות hover של glass-panel.

`_build_device_map_figure(session_dict, title_label, inv=None)` מריץ
‏PCA על מטריצת פיצ'רי ה-ML, צובע כל נקודה לפי הקטגוריה האמיתית של
ההתקן מהמצאי (קודם צבע כל נקודה שגוי כ-"External" - רגרסיה תוקנה
ננעלה ב-`rebuild_figures`). מצאים חסרים/ריקים נופלים ל-"External".

`_estimate_distance_m(rssi, tx=20, n=2.5, pl_d0=40)` הוא מודל
אובדן נתיב לוגריתמי של מרחק פנים ש-RSSI-mode של מפת הקרבה משתמש
בו.

`_build_proximity_map_figure(session_dict, title_label)` בוחר בין:

- **מצב RSSI** כאשר `wlan_features` יש דגימות RSSI: ‏MDS על מטריצת
  המרחקים שנבנתה מ-`_estimate_distance_m`, מקובצת ב-
  2 מ' / 5 מ' / 15 מ'.
- **מצב התנהגותי** אחרת: ‏MDS על `1 - Pearson_correlation` של
  מקבצי פעילות של 30 שניות עבור top-30 talkers, עם בונוס אותו-
  `/24`-subnet של `+0.25` ו-buckets 0.6 / 0.3 / 0.0.

`rebuild_figures()` מתזמר rebuild מלא של FIGS אחרי שינוי session:
‏`rebuild_inventories()` קודם, אז `make_figures(...)`,
`build_browse_figures(...)`, טבלאות היררכיה / ספקים חיצוניים /
סוג שירות / כיסוי פר-session, ולבסוף מפות ההתקן / קרבה.
הוא נקרא מ-~12 UI callbacks (`click_nav`, `click_tab`,
ניווט, החלפת session, קישור מותג, סיום live-analyze, …).

---

## תא 47 - מנועי Advanced Threat Detection

קבועי סף:

```
ADV_BEACON_MIN_EVENTS  = 16
ADV_BEACON_SCORE_FLAG  = 0.80
ADV_DNS_UNIQUE_MIN     = 20
ADV_DNS_UNIQUE_RATIO   = 0.90
ADV_DNS_ENTROPY_FLAG   = 3.8
ADV_DNS_LABEL_LEN_FLAG = 40
ADV_NX_STORM_MIN       = 30
ADV_DGA_MIN_LABEL_LEN  = 7
ADV_DGA_LOGPROB_FLAG   = None   # -> אדפטיבי: mean(logprobs) - std
ADV_FUSION_WINDOW_MIN  = 15
```

`_adv_load_pk(path)` הוא parse **שני** של tshark עם 28 שדות
(`_ADV_TSHARK_FIELDS`) - מוסיף `dns.qry.type`, `arp.opcode`,
`arp.dst.proto_ipv4`, `tls.handshake.extensions_server_name`,
`tls.handshake.ja3`, `tls.handshake.ja4`, `tls.record.version`,
`tls.handshake.ciphersuite`, `dhcp.option.dhcp_server_id`. זה
pass נפרד מה-loader של תא 8 כי הנתיב המהיר כוון לפיצ'רים הבסיסיים
והוספת תשעה שדות נוספים לכל פקטה ב-capture גדול איטית נמדדת.

חמשת המנועים מפיקים צורת שורה משותפת `_adv_sig` (`device`,
`peer`, `signal`, `tactic`, `technique`, `score`, `severity`, `count`,
`first_ts`, `last_ts`, `detail`):

| מנוע | לוגיקת זיהוי | טכניקת MITRE |
|---|---|---|
| `_adv_detect_arp_dhcp` | IP → >1 MAC; MAC → ≥4 IPs; הצפת gratuitous ARP; >1 ‏dhcp server id | T1557 / T1557.002 |
| `_adv_detect_dns_tunnel` | פר-registrable domain: ייחודי ≥ 20 וגם יחס ≥ 0.90 וגם (אנטרופיה מקסימלית ≥ 3.8 או ‏qlen ממוצע ≥ 40); סופות NXDOMAIN ≥ 30 פר-`ip_dst` | T1071.004 / T1568.002 |
| `_adv_detect_dga` | מודל char-bigram (‏Laplace, `^…$`) מאומן על דומיינים *שנפתרו* ב-capture זה; כש-<30 בסיסים נבדלים, מגדיל עם 50 הדומיינים הנפוצים המקודדים. מסמן תוויות שההסתברות הלוגריתמית שלהן < `mean - std` וגם אנטרופיה ≥ 3.6 וגם ‏vowel_ratio < 0.25 | T1568.002 |
| `_adv_detect_beaconing` | זוגות (src, dst), רק TCP-SYN או UDP, ≥16 אירועים, פרטי→ציבורי בלבד, ‏NTP/123 מוחרג, חציון מרווח ≥ 1 שניות. סדירות היא ממוצע שלושה תת-ציונים: ‏IQR-skew, פיזור MAD/חציון, ‏MAD של גודל פקטה. מסמן ב-≥ 0.80, "גבוה" ב-≥ 0.90 | T1071 |
| `_adv_detect_tls` | JA3 נדיר (התקן יחיד, בדיוק הופעה אחת, ל-peer חיצוני → 0.5/נמוך); ‏TLS ל-IP חיצוני בלי SNI (0.45/נמוך); ‏SNI-provider ≠ ספק-dst-IP דרך `_AdvCloudDB` (0.6/בינוני, ‏domain fronting) | T1071.001 / T1090 |

`_adv_fuse(all_signals)` הוא scorer של fusion / kill-chain: פר-התקן,
`base = max(signal_score)`, `best = max טכניקות נבדלות בתוך
חלון גולש של 15 דקות`, `boost = 1 + 0.5·(best − 1)`,
**‏`risk = min(1.0, base × boost)`**.

`run_advanced_threats(pcap_path)` מחזיר
`{available, n_packets, per_engine{5 keys}, all_signals, device_risk}`.
הוא **לעולם לא מעלה חריגה** - בכל כישלון מחזיר
`{"available": False, "reason": ...}`.

הערה: האותות המתקדמים מועברים לשופט LLM - ‏`judge_cli` מעביר אותם
ל-`assemble_candidates` דרך `threats_to_advanced_signals`.

---

## תא 48 - דשבורד (‏Aurora theme + ניווט + callbacks)

התא הגדול ביותר (~5,400 שורות). מגדיר את אפליקציית Dash המלאה:

**‏Theme.** קבועי פלטה (`INK`, `INK_DIM`, `INK_MUTE`, `VIOLET`,
`CYAN`, `MAGENTA`, `WARM_PALETTE`, `PIE_PALETTE` …). `AURORA_INDEX_STRING`
הוא `index_string` מותאם אישית שמעביר את ה-CSS של Aurora (Google-Fonts
`Newsreader` + `JetBrains Mono` + `Inter Tight`, מחלקות utility של
glass-panel, אנימציות).

**תצוגות.** שלוש תצוגות ברמה עליונה, מחליפות על ידי `render_main`
מה-store של `app-mode`: ‏`intro` / `choice` / `dashboard`.

- `build_intro_view()` - ‏splash של NETSEC של pixel-art ורוד על
  טרמינל CRT ירוק, הנרטיב של "welcome", תיבת הסימון של האישור
  (`intro-ack`) שמגדרת את כפתור ה-Continue (`intro-continue-btn`).
- `build_choice_view()` - ‏drag-and-drop ‏`dcc.Upload` +
  `#pcap-path-input` + `#pcap-path-btn` + `#record-live-btn`,
  כרטיס ה-staging (`#staged-analyze-btn` / `#staged-clear-btn`),
  פאנל חינוך עם תוכן המעמיק וקישור "Back to welcome". כל נתיב
  ש-staged כאן מנותח רק אחרי שהמשתמש לוחץ ▶ Analyze על כרטיס
  ה-staging - נתיב שהוקלד שגוי לא יכול להפעיל ריצה ארוכה.
- `build_dashboard_view()` - סרגל הצד + topbar + רצועת הטאבים +
  רצועת בוחר הצ'ארטים + אזור הצ'ארט + כפתור Restart צף.

**טאבים וניווט.** שני טאבים ברמה עליונה (`analyze` 📊 ו-`security`
🛡️) כל אחד מארח תת-קבוצה של **52 ‏`NAV_ITEMS`** המקובצים ל-**9
סקשנים** (live, analysis, device, browsing, security, compare,
inventory, external, coverage). ‏Session sub-tabs (גלולות S1 / S2)
נעולות עד ש-session שני נטען. `SESSION_TWIN` ממפה כל פריט
לעמיתו ב-S1↔S2. `NEEDS_S2_IDS` מגדר כל פריט scope-S2 כך שלחיצה על
אחד כש-S2 ריק מראה באנר "טענו capture שני" במקום לטעות.

**‏Store של מצב.** 13 ‏`dcc.Store`s (`app-mode`, `active-chart`,
`active-session`, `active-tab`, `trigger-rebuild`, `staged-pcap`,
`staged-second-pcap`, `s2-loaded-tick`, `live-rec-tick`,
`live-stats-store`, `scroll-helper`, `last-chart-per-tab`,
`replacing-s1`) + ‏`dcc.Interval` אחד (`live-recording-tick`, 3,000ms,
מוגדר על ידי `toggle_live_tick`).

**‏Callbacks.** 38 server-side + 12 clientside. הדגשים:

- `handle_first_action` / `handle_second_first_action` - ‏stage
  של PCAP מכל נתיב קלט.
- `handle_analyze_staged` / `handle_second_analyze_staged` -
  הלחיצה על ▶ Analyze שמריצה בפועל את הצינור.
- `handle_live_analyze` - ה-▶ Analyze על הקלטה חיה שמורה.
- `click_nav`, `click_tab`, `click_session_tab` - ניווט בין
  52 הצ'ארטים / 2 טאבים / גלולות S1|S2.
- `update_sidebar`, `render_chart`, `update_chart_picker_strip`,
  `render_tab_strip` - מרנדרים את ה-UI הנגזר.
- `send_session_to_n8n` - **‏scp** של ה-PCAP המקורי ל-
  `NETSEC_REMOTE_HOST` מעל Tailscale (ברירת מחדל ריקה; הכתובית
  קוראת "set NETSEC_REMOTE_HOST" עד שמוגדר, כך ש-fork טרי
  לא יכול בשקט לכוון ל-VM של מישהו אחר). חוסם את ה-callback עד
  7 שניות בזמן בדיקה של `:8765/health` ו-`:5678` לפני ההעתקה.
- ‏Clientside: ‏scroll-to-top, ‏spinner של כפתור analyze,
  עדכוני DOM של live-stat על ה-tick של 3 שניות (במכוון בלי
  render מחדש כך שאזור הצ'ארט לא יהבהב).

**פורטים.** ‏`_find_free_port(8050, 8100)` בוחר את הפורט הפנוי
הראשון ב-`[8050, 8099]`; נופל לפורט שהוקצה על ידי OS. האפליקציה
משוקת עם `app.run(debug=False, port=PORT, use_reloader=False,
jupyter_mode="external")`.

הכפתור לשליחת session לשופט LLM ב-GitHub Actions
(`_render_ai_judge_link`) מצביע ל-`<repo>/upload/main/incoming`
שנגזר מ-`git remote get-url origin`, כך ש-fork אוטומטית מכוון
לריפו שלו.

---

## תא 49 - VM client integration shim

בלוק ייבוא אופציונלי. כאשר `server/dashboard_client.py` ב-path,
הוא חושף את `load_session_from_api` ו-`upload_session_via_api`
ב-namespace של המודול כך ששליטה עתידית של דשבורד תוכל למשוך
‏dict של session מ-endpoint `/v1/sessions/{id}` של ה-VM או לדחוף
‏PCAP ל-`/v1/pcap`. היום ה-UI עדיין מנתב העלאות דרך כפתור ה-scp
בתא 48; חיווט נתיב ה-HTTP ל-callback נמצא ברשימת המעקב.

</div>
