<div dir="rtl">

# שכבת Triage של LLM-as-Judge - מפרט ועיצוב

> גרסה עברית של [`LLM_JUDGE_SPEC.md`](LLM_JUDGE_SPEC.md).

**סטטוס:** **הוטמע ונשלח.** המסמך הזה נשמר כרשומת העיצוב - החלטות
העיצוב שנחתו, ה-tradeoffs שנעשו, ו-(בטבלת הסטיות ב-
`llm_judge/README.md`) הקבוצה הקטנה של בחירות שבהן הקוד שנשלח
במכוון שונה מהתכנית המקורית. הטמעה סמכותית חיה ב-`llm_judge/`
ומופעלת end-to-end על ידי `tests/test_llm_judge_*.py`; ‏workflow
‏`analyze-pcap.yml` של Actions לשעבר נגרס (worker ה-VM הוא הנתיב
האוטונומי).
**קהל:** כל מי שמרחיב את שכבת השופט או רוצה את ההיגיון מאחורי
הקוד הנוכחי.
**‏Scope:** שכבת triage בין מנועי הזיהוי הקיימים לאנליסט. מדרגת
מועמדים, מפיקה חשיבה בשפה טבעית, ומכויילת מול ground truth
המתויג ב-`attack_tests/`.

הערות נתיב לקוראים: בכל מקום שהמסמך הזה אומר `app/llm_judge.py`,
`app/llm_judge_config.py`, `app/llm_clients/`, `attack_tests/calibrate_judge.py`,
`attack_tests/calibration/`, `docs/schemas/`, `docs/PROMPT_CHANGELOG.md`,
`data/judge_cache.sqlite` או `data/analyst_verdicts.jsonl`, הקוד
שנשלח חי תחת `llm_judge/` (עם שמות הקבצים האנלוגיים -
`judge_core.py`, `judge_config.py`, `llm_clients.py`, `calibration.py`,
`calibration/`, `schemas/`, `PROMPT_CHANGELOG.md`, `cache/judge_cache.sqlite`).
השינוי שם במכוון: השופט הוא שכבה עצמאית, לא חלק מ-`app/`, וחי
לצד הבדיקות שלו, ‏cache ושער CI משלו.

---

## 1. תקציר מנהלים

הדשבורד כבר מריץ שלושה מודלי ML לא-מפוקחים (‏IsolationForest,
‏DBSCAN, ‏LSTM), שתי שכבות של חוקים דטרמיניסטיים, וחמישה מנועי איום
מתקדמים בתוספת scorer של fusion מעליהם. כל אחד מפיק אות משלו.
שום דבר לא ממזג אותם לפסיקה פר-מועמד אחת, ושום דבר לא מפיק הצדקה
בשפה טבעית. האנליסט משלם את העלות הקוגניטיבית המלאה של כל false
positive.

המפרט הזה מוסיף רכיב אחד: **‏LLM-as-Judge** שמקבל מועמד אחד בכל
פעם (IP אחד, או flow אחד), רואה כל אות רלוונטי ב-JSON blob דחוס,
ומחזיר verdict JSON קפדני עם קטגוריה, confidence, רשימת ראיות,
ועקבות reasoning של פסקה אחת. הפלט שלו מדרג מחדש את התור שהאנליסט
רואה ומפיק את הסיכום שהאנליסט היה כותב בכל מקרה.

השופט מכויל דרך **‏Cohen's kappa** מול
`attack_tests/ground_truth.json` - התוויות כבר ממצות עבור חמישה
‏PCAPs של תקיפות אמיתיות, אז אין צורך בסט כיול חיצוני. ‏Kappa הופך
למספר היחיד ששומר מול סחיפת prompt.

**לא-יעד:** השופט לא פועל. `recommended_action: "block"` זו הצעה
לאנליסט, לעולם לא מחווטת ל-blocklist.

---

## 2. ‏Context - מה כבר קיים

כל דבר למטה כבר בריפו ואין לגעת בו על ידי העבודה הזאת מלבד בנקודות
האינטגרציה שבסעיף §11.

### 2.1 מנועי זיהוי

| שכבה | מיקום (תא notebook / קובץ) | פלט |
|---|---|---|
| חילוץ פיצ'רים פר-IP | תא 8 / `run_pipeline.analyze_pcap` | DataFrame של `ip_agg` עם 10 פיצ'רים |
| IsolationForest | תא 12 / `run_ml_on_session` | עמודות `iso_score`, `iso_stability`, `anomaly` |
| DBSCAN | תא 12 / `run_ml_on_session` | עמודת `cluster` (`-1` = noise) |
| LSTM זמני | תאים 22-26 | שגיאה פר-bin, סף `val_mean + 2σ` |
| חוקים דטרמיניסטיים | תא 16 / `run_security_scans` | `scan_alerts`, `flood_alerts`, `amp_alerts`, `arp_spoofing_ips`, `arp_spoofing_macs` |
| מנועי איום מתקדמים | תא 47 של `Network_Security_Dashboard.ipynb` | חמישה מנועים - beaconing, DNS tunneling, DGA, ARP/DHCP, TLS - ו-scorer של fusion פר-התקן מעליהם בחלון של 15 דקות (לא מנוע שישי) |
| סיווג התקנים | מנוע 3 שכבות (hostname/OUI/port → DNS fingerprints → heuristics) | 12 קטגוריות |

### 2.2 וקטור פיצ'רים (פר-IP)

עשרה פיצ'רים מוזנים ל-IsolationForest / DBSCAN:

```
mean_len, std_len, count, burst_score, unique_dsts,
syn_count, rst_count, fin_count, null_count, xmas_count
```

מנורמלים ב-`StandardScaler` לפני ששניהם רצים.

### 2.3 Ground truth

`attack_tests/ground_truth.json` מתייג חמישה PCAPs:

| PCAP | תקיפה | שדות אמת |
|---|---|---|
| `tcp_syn_scan.pcap` | ‏nmap `-sS` | `attacker_ips`, ‏`scan_alert_types: ["SYN"]` צפוי, ‏ML חייב לסמן את התוקף |
| `xmas_scan.pcap` | ‏nmap `-sX` | `attacker_ips`, ‏`scan_alert_types: ["XMAS"]` צפוי |
| `arpspoof.pcap` | הרעלת ARP MITM | `spoofed_ips`, `spoofing_macs` |
| `synflood.pcap` | הצפת SYN מזויפת (37,623 src) | `aggregate_flood: true`, `min_syn_sources: 30000`, `dbscan_skipped: true` |
| `dns_amp.pcap` | החזרת DNS ANY | `reflector_ips` (8 IPs), `amp_rule: true` |

`attack_tests/evaluate.py` כבר מחשב precision / recall / F1
פר-שכבה מול סטי האמת האלה וקובע בדיקות ציפייה. זה ה-scaffolding
שצינור הכיול ירחיב.

### 2.4 בדיקות רגרסיה

`tests/test_detection_regression.py` מריץ כל PCAP דרך אותם נתיבי
קוד כמו הדשבורד וקובע שבדיקות ה-ground-truth עוברות.
`tests/test_notebook_integrity.py` גם קובע שכל תא notebook
‏compiles ושה-`app/dashboard_module.py` בסנכרון עם ה-notebook
(מתחולל מחדש על ידי `tools/export_dashboard_module.py --check`).

**כל שינוי ב-notebook חייב להיות אחרי שחזור של
`app/dashboard_module.py`** - אחרת ‏CI נשבר.

---

## 3. הצהרת בעיה

שלוש נקודות כאב ממוחשות:

1. **אין verdict יחיד פר-מועמד.** ‏IsolationForest אומר "ציון
   outlier = −0.31, יציבות = 0.8"; ‏DBSCAN אומר "אשכול = −1";
   חוק ה-SYN אומר "scan_alert מסוג SYN"; המנועים המתקדמים כל אחד
   מוסיף תג משלו. האנליסט הוא ה-fuser.
2. **אין reasoning בשפה טבעית.** כרטיס Model Diagnostics חושף את
   ה-hyperparameters; ‏`docs/MODELS.md` מסביר מה כל מודל עושה;
   האנליסט עדיין כותב את פסקת "למה IP זה חשוד" ביד.
3. **אין אות כיול.** איכות זיהוי נמדדת פר-שכבה (precision / recall /
   F1 מול ground truth), אבל אין מד מספר יחיד שרגרסיה כשלוגיקת
   ה-fusion סוחפת. הוספת חוק או כיוון של סף אין לה אות עלות-סחיפה
   ברור.

---

## 4. פתרון מוצע

להכניס רכיב אחד לצינור: **‏LLM-as-Judge** שמקבל מועמד אחד בכל פעם,
רואה כל אות רלוונטי ב-JSON blob דחוס, ומחזיר verdict JSON קפדני.

### 4.1 מהו "מועמד"

כל ישות שסומנה על ידי **לפחות אחד** מ:

- אנומליית majority-vote של IsolationForest (`iso_stability >= 0.5`)
- noise של DBSCAN (`cluster == -1`) - בכפוף ל-cap של 5000-IP
- אנומליה זמנית של LSTM (שגיאת bin > `val_mean + 2σ`) מיוחסת
  חזרה ל-IPs הפעילים ב-bin זה
- כל חוק דטרמיניסטי (`scan_alerts`, `flood_alerts`, `amp_alerts`,
  `arp_spoofing_ips`, `arp_spoofing_macs`)
- כל ממצא של מנוע איום מתקדם

זהות המועמד היא אחת מ:

- **פר-IP:** שורה של `ip_agg`
- **פר-flow:** ‏tuple של `(src, dst, proto)`, בשימוש רק עבור ממצאי
  מנוע מתקדם שלא ממפים נקי ל-IP יחיד (למשל זוגות beaconing)

ברירת המחדל של היישות היא פר-IP. מועמדי פר-flow נכנסים לתור רק
כש-מנוע מתקדם מפיק ממצא ברמת flow.

### 4.2 מה השופט רואה

**‏JSON דחוס** blob, מתוקצב ב-2-4 KB פר-מועמד:

```json
{
  "candidate_id": "192.168.1.10",
  "kind": "ip",
  "session_context": {
    "duration_s": 71.2,
    "total_packets": 2020,
    "total_ips": 5
  },
  "features": {
    "mean_len": 60.0, "std_len": 0.0, "count": 1007,
    "burst_score": 1007.0, "unique_dsts": 1000,
    "syn_count": 1002, "rst_count": 0,
    "fin_count": 0, "null_count": 0, "xmas_count": 0
  },
  "ml_signals": {
    "iso_score": -0.31, "iso_stability": 1.0, "anomaly": true,
    "cluster": -1, "silhouette": null,
    "lstm_bin_flag_count": 0
  },
  "rule_signals": {
    "scan_alerts": [{"type": "SYN", "count": 1002, "unique_dsts": 1000, "ratio": 1.0}],
    "flood_alerts": [],
    "amp_alerts": [],
    "arp_multi_mac": false
  },
  "advanced_signals": {
    "beaconing": null,
    "dns_tunneling": null,
    "dga": null,
    "tls_anomaly": null,
    "fusion_score": null
  },
  "device_context": {
    "category": "unknown",
    "hostname": null,
    "oui_vendor": null
  },
  "enrichments": {
    "is_private": true,
    "reverse_dns": null,
    "asn": null,
    "baseline_seen_before": false
  }
}
```

כל שדה אופציונלי מלבד `candidate_id`, `kind`, `features`, ו-
`ml_signals`. ‏Nulls / רשימות ריקות אומרים "לא ישים".

### 4.3 מה השופט מחזיר

JSON קפדני - התגובה נדחית ועוברת retry אם היא נכשלת באימות סכמה:

```json
{
  "verdict": "benign | suspicious | malicious",
  "category": "beaconing_c2 | dns_tunnel | dns_amp | port_scan | arp_mitm | syn_flood | benign_anomaly",
  "confidence": 0.0,
  "evidence_features": ["syn_count", "unique_dsts", "scan_alert.SYN"],
  "reasoning": "פסקה אחת, <= 400 תווים, מסבירה את ה-verdict.",
  "recommended_action": "monitor | investigate | block"
}
```

מגבלות:

- `confidence` ב-`[0.0, 1.0]`.
- `evidence_features` מתייחס לשמות שדות מ-blob הקלט (או נתיבים
  נקודתיים לתוכו). נאכף רק רך - משמש לרנדור UI
  highlights, לא לזרימת שליטה.
- `reasoning` היא מחרוזת יחידה, בלי newlines, חסומה קשה על ידי
  prompt.
- אימות סכמה כושל: ‏**retry פעם אחת**, אז זורק את המועמד מתור
  השופט ורושם את הכישלון. לעולם אל תרעיל את ה-scoreboard עם
  תגובה חצי-מפוענחת.

### 4.4 קטגוריות - מיפוי ל-ground truth

| קטגוריית שופט | תקיפת ground-truth |
|---|---|
| `port_scan` | `tcp_syn_scan`, `tcp_xmas_scan` |
| `arp_mitm` | `arp_spoofing` |
| `syn_flood` | `spoofed_syn_flood` |
| `dns_amp` | `dns_amplification` |
| `beaconing_c2` | (לא ב-ground truth הנוכחי - עתידי) |
| `dns_tunnel` | (לא ב-ground truth הנוכחי - עתידי) |
| `benign_anomaly` | כל IP שסומן על ידי detector אבל מתויג benign |

המיפוי הזה הוא מה שהופך את Cohen's kappa למוגדר היטב מול ה-ground
truth הנוכחי. הקטגוריות `beaconing_c2` ו-`dns_tunnel` מוצהרות
עכשיו כך שה-prompt עמיד לעתיד.

---

## 5. התנהגות זמן ריצה - זרימת end-to-end

הזרימה, בזמן טעינה של PCAP אחד:

```
                +----------------------------+
                |  קובץ PCAP (S1 או S2)      |
                +-------------+--------------+
                              |
                              v
             +----------------+---------------+
             |  חילוץ פיצ'רים של tshark      |    (תא 8, ללא שינוי)
             |  -> ip_agg, dns_amp_per_src,   |
             |     מפות arp, מוני flags TCP  |
             +----------------+---------------+
                              |
                              v
             +----------------+---------------+
             |  מנועי ML + חוקים + מתקדמים   |    (תאים 12/16 + תא
             |  -> ml_signals, rule_signals,  |     מנועים מתקדמים, ללא שינוי)
             |     advanced_signals           |
             +----------------+---------------+
                              |
                              v
             +----------------+---------------+
             |  מרכיב מועמדים                |    חדש
             |  - איחוד של ישויות שסומנו     |
             |  - JSON blob אחד פר-מועמד    |
             |  - dedup לפי fingerprint      |
             +----------------+---------------+
                              |
                              v
             +----------------+---------------+
             |  חיפוש Cache (SQLite)         |    חדש
             |  - key: (fingerprint, prompt_v)|
             |  - hit -> שימוש חוזר ב-verdict|
             |  - miss -> קריאה ל-LLM        |
             +----------------+---------------+
                              |
                              v
             +----------------+---------------+
             |  קריאת LLM (מצב JSON קפדני)  |    חדש
             |  - אימות schema של תגובה     |
             |  - retry פעם אחת על לא תקין  |
             |  - drop + log על כישלון שני  |
             +----------------+---------------+
                              |
                              v
             +----------------+---------------+
             |  Scorer של Ensemble           |    חדש
             |  priority =                    |
             |    w1*anomaly_score +          |
             |    w2*judge_confidence +       |
             |    w3*category_weight +        |
             |    w4*threat_intel (opt.)      |
             +----------------+---------------+
                              |
                              v
             +----------------+---------------+
             |  Dashboard: תור מדורג מחדש    |    UI חדש (Dash card)
             |  + inline reasoning trace     |
             |  + widget verdict של אנליסט   |
             +----------------+---------------+
                              |
                              v
             +----------------+---------------+
             |  data/analyst_verdicts.jsonl   |    audit log חדש
             |  (agree / disagree / override) |
             +--------------------------------+
```

תכונות מרכזיות:

- **קריאת ה-LLM היא הצעד היחיד שתלוי ב-I/O.** כל השאר הוא Python
  דטרמיניסטי על DataFrames שכבר חושבו.
- **‏Cache אגרסיבי.** ‏fingerprint של מועמד = hash של JSON blob
  הקלט. שני blobs זהים פוגעים באותו verdict. ‏Fingerprint גם כולל
  את גרסת ה-prompt כך שעריכות prompt מבטלות את ה-cache.
- **כישלון מתבודד למועמד.** תגובת LLM רעה יחידה זורקת את אותו
  מועמד מתור השופט עם רשומת log. דירוג האנומליה הלא-מועשר עדיין
  מאכלס את הדשבורד.
- **השופט מאחורי feature flag.** `LLM_JUDGE_ENABLED = True/False`
  בראש הקונפיגורציה. כשכבוי, הדשבורד מתנהג בדיוק כמו היום.
  השוואות A/B במרחק commit אחד.

---

## 6. חוזה - מודל נתונים בפירוט

### 6.1 סכמת context של מועמד (קלט ל-LLM)

`docs/schemas/candidate_context.schema.json` - ‏JSON Schema draft-2020-12,
אומת עם `judge_core.validate_verdict` (הידני - התלות ב-
`jsonschema` שהתכנית הוסיפה לעולם לא נחתה כי הבדיקות פשוטות יותר
כקוד מפורש ותלות אחת פחות ל-pin). ראו §4.2 לצורה.
`required`: `candidate_id`, `kind`, `features`, `ml_signals`.

### 6.2 סכמת verdict של שופט (פלט מ-LLM)

`docs/schemas/judge_verdict.schema.json`. ראו §4.3.

ערכי Enum ממצים - אין שדות טקסט חופשי מלבד `reasoning`. זו נקודת
האכיפה לתכונת "JSON קפדני".

### 6.3 מפתח Cache

```
fingerprint = sha256(
    canonical_json(candidate_context) + prompt_version_string
).hexdigest()
```

`canonical_json` = מפתחות ממוינים, בלי whitespace. ‏`prompt_version_string`
היא מחרוזת סמנטית שעולה בכל שינוי prompt (§7.2).

### 6.4 Log של verdict אנליסט

`data/analyst_verdicts.jsonl` - אובייקט JSON אחד לשורה:

```json
{
  "ts": "2026-07-09T14:22:11Z",
  "candidate_id": "192.168.1.10",
  "pcap": "tcp_syn_scan.pcap",
  "prompt_version": "v1.0.0",
  "judge_verdict": {...},
  "analyst_verdict": "agree | disagree | override",
  "analyst_category": "port_scan | ...",
  "analyst_note": "טקסט חופשי"
}
```

נצרך על ידי צינור הכיול בריצה הבאה.

---

## 7. אלטרנטיבות ארכיטקטורה

שלוש צורות ברות-קיימא לזמן ריצה. השוואה ב-§7.4, המלצה ב-§7.5.

### 7.1 אלטרנטיבה A - תא notebook סינכרוני in-notebook

**צורה:** תא notebook חדש (נגיד `# ==== notebook cell 46 ====`)
שרץ אחרי תאי ה-ML / החוקים / המתקדמים הקיימים. הוא:

1. מרכיב מועמדים מה-DataFrames שכבר ב-namespace הגלובלי של
   ה-notebook.
2. קורא ל-client של ה-LLM (סינכרונית, בקשה אחת פר-מועמד).
3. כותב verdicts חזרה לעמודת `ip_agg["judge_verdict"]` חדשה
   ולרשימת `judge_summary` ברמה עליונה.
4. ‏callbacks של Dash downstream קוראים את השדות האלה ומרנדרים
   אותם.

**יתרונות:**

- אפס מורכבות deployment - ה-notebook כבר רץ end-to-end כשהמשתמש
  לוחץ "Restart & Run All."
- ‏debuggable ישירות מ-Jupyter.
- אין תהליכים חדשים, ‏sockets, או קבצים-בטיסה.
- עקבי עם המודל notebook-as-app הנוכחי (קובץ אחד, ריצה אחת).

**חסרונות:**

- חוסם. אם ה-API של ה-LLM איטי או רשימת מועמדים גדולה, טעינת
  הדשבורד חוסמת על כל תור השופט. ‏PCAP של 30 מועמדים עם API של
  2 שניות פר-קריאה לוקח דקה לטעון.
- תאי notebook קשים ל-unit-test. כיסוי רגרסיה חי ב-`run_pipeline.py`
  שחולץ - שהיה צריך לכפול את אותה לוגיקה.
- מפתח ה-API של ה-LLM חי בסביבת הביצוע של ה-notebook, לצד מכונות
  ה-`pip install` של המשתמש.
- `app/dashboard_module.py` מכפיל במורכבות ללא תועלת - תא השופט
  הוא קוד מת לבדיקות שלא מגדירות את מפתח ה-API.

### 7.2 אלטרנטיבה B - CLI מהצד + SQLite cache

**צורה:** מודול Python עצמאי `app/llm_judge.py` (ניתן לייבוא
מ-notebook, מ-`run_pipeline.py`, ומ-CLI חדש). הוא חושף:

```python
def judge_candidates(candidates: list[dict],
                    prompt_version: str = PROMPT_VERSION,
                    cache_db: str = "data/judge_cache.sqlite") -> list[dict]
```

תא ה-notebook מתכווץ לשתי שורות:

```python
from llm_judge import judge_candidates
S["judge_verdicts"] = judge_candidates(assemble_candidates(S))
```

‏CLI חדש `attack_tests/calibrate_judge.py` משתמש מחדש באותה
פונקציה כדי להריץ את השופט על חמשת ה-PCAPs של ground-truth
ולחשב kappa.

ה-SQLite cache היא טבלה יחידה:

```sql
CREATE TABLE judge_cache (
    fingerprint TEXT PRIMARY KEY,
    prompt_version TEXT NOT NULL,
    verdict_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    llm_model TEXT NOT NULL,
    latency_ms INTEGER
);
```

**יתרונות:**

- ניתן לבדיקה בבידוד - ‏`test_llm_judge_unit.py` עושה mock ל-client
  של ה-LLM וקובע מול blobs של fixture; ‏`test_judge_kappa_regression.py`
  רץ מול ה-LLM האמיתי (או מוקלט) וקובע kappa >= סף.
- ‏Cache עמיד על פני restarts של notebook. ריצה שנייה של אותו
  PCAP פוגעת ב-cache 100%.
- ‏CLI של הכיול הוא תוצאת לוואי טבעית - אותו ייבוא, נקודת כניסה
  שונה.
- הפרדה נקייה של דאגות: ‏notebook = תזמור + UI; מודול = לוגיקת
  שופט.
- מתאים לתבנית הקיימת של הריפו: ‏`run_pipeline.py` בדיוק בצורה הזאת
  עבור שכבת ה-ML.

**חסרונות:**

- עדיין חוסם בתוך ריצת notebook יחידה (אלא אם המודול מקביל
  פנימית עם pool של threads - סביר, קל).
- ה-notebook חייב לייבא את המודול - ייבוא אחד חדש בראש ה-notebook
  לשמור בסנכרון כש-`dashboard_module.py` מתחולל מחדש.
- מוסיף `jsonschema` ו-SDK של LLM שנבחר ל-`requirements.txt`.

### 7.3 אלטרנטיבה C - שירות רקע מתמשך

**צורה:** שירות FastAPI (או Flask) ארוך-טווח, שמוצג לצד אפליקציית
Dash, שבבעלותו:

- ה-client של ה-LLM.
- ה-SQLite cache.
- ‏endpoint POST ‏`/judge` שמקבל blob של מועמד ומחזיר verdict.
- ‏endpoint GET ‏`/kappa` שמחזיר kappa חי נוכחי לפילת Model
  Diagnostics.
- אופציונלי: ‏worker thread שמחמם מראש verdicts למועמדים
  שמוזרמים מה-notebook דרך תור.

ה-notebook קורא לשירות על `http://localhost:PORT/judge`.

**יתרונות:**

- ‏UX הטוב ביותר תחת עומס - אפליקציית Dash יכולה לרנדר את התור
  כש-verdicts מגיעים במקום לחסום על כל ה-batch.
- ‏endpoint של kappa חי טריוויאלי. כרטיס Model Diagnostics עושה
  לו poll.
- השירות יכול לאכוף תקציב קשה פר-batch מרכזית (rate limit,
  cap של טוקנים).
- הגבול הנקי ביותר להרחבות עתידיות (רב-tenant, ‏backends של LLM
  מרוחקים, תגובות streaming).

**חסרונות:**

- שני תהליכים להשיק, לבדוק בריאות ולנהל. הסיפור הנוכחי "התקינו
  Wireshark, הריצו notebook אחד" הופך ל"התקינו Wireshark, הריצו
  notebook אחד, ושירות אחד."
- מורכבות deployment כמעין-Docker דולפת לפרויקט מחקר שהיום רץ
  נקי עם `pip install -r requirements.txt` + Jupyter.
- השירות הוא מצב כישלון חדש: אם הוא קורס באמצע-batch, לחצי
  המועמדים יש verdicts ולחצי אין. אלטרנטיבה B מתאוששת שקוף מה-cache
  בריצה הבאה; אלטרנטיבה C צריכה לטפל במצב החלקי של אמצע-batch
  בעצמה.
- מוגזם לשימוש הנוכחי של אנליסט יחיד, מכונה יחידה.

### 7.4 השוואה

| ממד | A: in-notebook | B: sidecar module | C: שירות רקע |
|---|---|---|---|
| מורכבות deployment | הנמוכה ביותר | נמוכה | גבוהה |
| ‏Testability | גרועה (קשורה ל-notebook) | טובה (ידידותית ל-`pytest`) | טובה, אבל צריכה process fixtures |
| עמידות cache | רק in-memory | עמידה (SQLite) | עמידה (SQLite) |
| התנהגות חוסמת | חוסמת טעינת Dash | חוסמת טעינת Dash (thread-pooled) | לא חוסמת (async) |
| ‏Latency ל-verdict ראשון | ~1× LLM RTT | ~1× LLM RTT | ~1× LLM RTT (streaming אפשרי) |
| מתאים לצורת הריפו הנוכחית | מאולץ | טבעי (משקף `run_pipeline.py`) | תבנית חדשה |
| בידוד תקלות | קריסת notebook = אובדן מלא | בידוד פר-מועמד | בידוד פר-בקשה |
| פילת kappa חיה | לא ישירה | מחושבת מחדש על רענון Dash | endpoint טריוויאלי |
| עלות היפוך | שכתוב תא | מחיקת מודול + החזרת תא | הסרת שירות + החזרת תא |
| חיווט CI | לוגיקה כפולה | ייבוא אחד בבדיקה | צריך שירות שיעלה ב-CI |
| תלויות נוספות | jsonschema, LLM SDK | jsonschema, LLM SDK | jsonschema, LLM SDK, FastAPI/Flask |

### 7.5 המלצה

**אלטרנטיבה B - מודול sidecar + SQLite cache.**

היגיון:

1. התבנית הקיימת של הריפו היא בדיוק זו: ‏`run_pipeline.py` כבר
   מרים תאי notebook למודול שניתן לייבוא עבור בדיקות ו-CLIs.
   אלטרנטיבה B מרחיבה את התבנית הזאת; אלטרנטיבה A שוברת אותה;
   אלטרנטיבה C ממציאה אחת חדשה.
2. כיול Cohen's kappa צריך batch runner על חמשת ה-PCAPs של
   ground-truth (`calibrate_judge.py`). אלטרנטיבה B מקבלת את זה
   חינם על ידי חשיפת `judge_candidates()` כפונקציה. אלטרנטיבה A
   מכריחה את ה-calibrator להגיע ל-globals של ה-notebook או
   להכפיל את הלוגיקה. אלטרנטיבה C מכריחה את ה-calibrator לסובב
   את השירות.
3. מודל הקונקרנטיות הנוכחי של הדשבורד הוא single-threaded פר-callback
   של Dash. פער הביצועים בין B (batch של thread-pool) ל-C
   (streaming async) אמיתי אבל לא כואב ב-scale היעד (5-50
   מועמדים פר-PCAP טיפוסי).
4. היפוך. אלטרנטיבה B היא קובץ אחד (`app/llm_judge.py`) בתוספת
   ייבוא אחד ב-notebook. כיבוי `LLM_JUDGE_ENABLED` מחזיר את
   ההתנהגות הנראית ב-commit יחיד. אלטרנטיבה C משאירה binary של
   שירות וחיווט healthcheck מאחור.

**נדחה לאלטרנטיבה C רק אם:** מצב הקלטה חי (streaming של `tshark`)
מורחב להפעיל קריאות שופט בזמן אמת, או שהכלי גדל מאנליסט יחיד
לפריסה SOC משותפת. אף אחד לא ב-scope היום.

---

## 8. צינור כיול

### 8.1 מיפוי ‏Ground-truth

לכל PCAP ב-`attack_tests/ground_truth.json`, בנו סט אמת:

```
truth[pcap] = {
    ip: category
    for ip in (attacker_ips ∪ spoofed_ips ∪ reflector_ips)
}
```

כאשר `category` נגזר מהשדה `attack` דרך הטבלה ב-§4.4.
כל IPs אחרים שנראו ב-PCAP ששורדים את מסנן המועמדים מתויגים
`benign_anomaly` בסט האמת - אלה ה-false positives שהכיול חייב
להעניש.

### 8.2 חישוב Kappa

Cohen's kappa על מטריצת שתי עמודות, שורה אחת פר-מועמד:

```
              | truth = category
              +------------------
predicted     |
= category    |
```

הקטגוריות הן ה-enum של 7 דרכים מ-§4.3. ‏Kappa רב-מחלקתי (משוקלל =
`"linear"` או לא-משוקלל) דרך
`sklearn.metrics.cohen_kappa_score(y_true, y_pred, labels=CATEGORIES)`.

דווחו שניהם:

- **‏Verdict kappa** (3 דרכים: `benign / suspicious / malicious`) -
  המד הגס.
- **‏Category kappa** (7 דרכים) - המד הקפדני.

שער CI משתמש ב-**‏category kappa**, סף `0.60` ב-
`judge_config.KAPPA_THRESHOLD` הנוכחי (rollout §14 נפתח ב-0.60;
המדידה שנשלחה של v0.3.0 היא 0.7911 על `openai/gpt-oss-120b`,
הרבה מעל יעד הטיוטה של 0.65 שהתכנית הקודמת הגדירה כיעד שאיפה).

### 8.3 קובץ - `attack_tests/calibrate_judge.py`

צורה:

```python
def calibrate(prompt_version: str, results_path: str) -> dict:
    """הרץ את השופט על כל PCAP של ground-truth, חשב kappa, שפוך JSON."""
    y_true, y_pred = [], []
    per_pcap = {}
    for pcap, gt in GROUND_TRUTH.items():
        S = analyze_pcap(pcaps_dir / pcap, "S1")
        run_ml_on_session(S)
        findings = run_security_scans(S)
        candidates = assemble_candidates(S, findings)
        verdicts = judge_candidates(candidates, prompt_version=prompt_version)
        y_t, y_p = align_to_truth(candidates, verdicts, gt)
        per_pcap[pcap] = {
            "verdict_kappa": kappa_3way(y_t, y_p),
            "category_kappa": kappa_7way(y_t, y_p),
            "precision_by_cat": ...,
            "recall_by_cat": ...,
            "f1_by_cat": ...,
        }
        y_true.extend(y_t); y_pred.extend(y_p)
    overall = {
        "verdict_kappa": kappa_3way(y_true, y_pred),
        "category_kappa": kappa_7way(y_true, y_pred),
        "confusion_matrix": confusion(y_true, y_pred, CATEGORIES),
    }
    dump({"prompt_version": prompt_version, "overall": overall,
          "per_pcap": per_pcap}, results_path)
    return overall
```

התוצאות נכתבות ל-`attack_tests/calibration/results/<prompt_version>.json`.

### 8.4 שער CI - `tests/test_judge_kappa_regression.py`

```python
def test_judge_category_kappa_meets_threshold():
    latest = load_latest_calibration_result()
    assert latest["overall"]["category_kappa"] >= KAPPA_THRESHOLD, \
        f"category kappa {latest['overall']['category_kappa']:.3f} "
        f"< threshold {KAPPA_THRESHOLD}"
```

`KAPPA_THRESHOLD = 0.65` בהתחלה. העלו ל-`0.70` אחרי שהגרסה v1
מתייצבת.

הבדיקה קוראת את קובץ הכיול שכבר הופק - היא **אינה** קוראת ל-LLM.
זה שומר על CI זול ודטרמיניסטי. ייצור התוצאות הוא צעד ידני
שקשור ללולאת האיטרציה של prompt (§10). זו החלטת עיצוב מכוונת:
קריאת LLM ב-CI יקרה ולא דטרמיניסטית; השומר הוא ששינוי prompt
בלי קובץ כיול תואם הוא פער שחוסם merge שהביקורת תתפוס.

**שער אלטרנטיבי:** הריצו מחדש כיול ב-CI מול **‏fixture של תגובת
LLM שהוקלטה** (פר-גרסת prompt). אותו סף, דטרמיניסטי, חינם. בחרו
את זה אם הצעד הידני מרגיש קל מדי לדלג עליו.

### 8.5 לולאת משוב

כל פעם שה-prompt משתנה:

1. העלו את `PROMPT_VERSION`.
2. הריצו `python attack_tests/calibrate_judge.py`.
3. השוו kappa לגרסה הקודמת.
4. **‏Commit רק אם kappa לא נסוג.**

`data/analyst_verdicts.jsonl` מתווסף לאמת בריצת הכיול הבאה -
‏overrides של אנליסט הופכים לנתיב הצמיחה של סט ה-ground-truth.

---

## 9. ציון ensemble

ציון עדיפות בשימוש לדירוג התור שהאנליסט רואה:

```
priority(c) = w_anom * normalized_iso_score(c)
            + w_judge_conf * judge.confidence
            + w_cat * category_weight[judge.category]
            + w_ti * threat_intel_score(c)   # אופציונלי, 0 אם אין
```

משקלים (טיוטה ראשונית):

| משקל | ערך | הצדקה |
|---|---:|---|
| `w_anom` | 0.20 | שמור על ה-detector הבסיסי כרצפה |
| `w_judge_conf` | 0.40 | השופט הוא האות הראשי |
| `w_cat` | 0.30 | משקל קטגוריה מעניש benign_anomaly, מתגמל קטגוריות malicious |
| `w_ti` | 0.10 | שמור לאינטגרציית threat-intel מאוחרת |

משקלי קטגוריה (טיוטה ראשונית):

```
category_weight = {
    "syn_flood":     1.0,
    "dns_amp":       1.0,
    "arp_mitm":      1.0,
    "port_scan":     0.8,
    "beaconing_c2":  0.9,
    "dns_tunnel":    0.9,
    "benign_anomaly": 0.0,
}
```

כל המשקלים הם hyperparameters מכוונים פעם אחת מול סט הכיול
(חיפוש grid חד-פעמי על חמשת ה-PCAPs, מקסום precision@top-N).
הם חיים ב-`app/llm_judge_config.py` ומוצגים בכרטיס Model
Diagnostics.

---

## 10. עיצוב Prompt

### 10.1 ‏prompt מערכת (טיוטה, אנגלית, משובצת ב-`app/llm_judge.py`)

```
You are a network-security triage analyst. You receive a JSON blob
describing one candidate IP or flow that at least one unsupervised
detector or deterministic rule has flagged. Your job:

1. Return a strict JSON object matching the schema below. No prose
   outside the JSON. No markdown fences.
2. Assign a verdict (benign | suspicious | malicious) and a category
   from the fixed enum.
3. Ground every claim in the input blob - cite feature names in
   `evidence_features`.
4. If the signals are contradictory or thin, prefer "suspicious" over
   "malicious". If they are strong and unambiguous, use "malicious".
5. Never invent facts not in the blob. If a field is null, it is unknown,
   not zero.
6. `recommended_action` is a suggestion for a human, never an action
   this system will execute.

Schema:
{schema_here}

Category cheat sheet:
- port_scan: high unique_dsts + one dominant TCP flag counter + high
  ratio of that flag to total packets. Attackers touch many destinations.
- syn_flood: session-level SYN rate high AND many spoofed sources (see
  session_context and rule_signals.flood_alerts).
- arp_mitm: rule_signals.arp_multi_mac == true OR an IP appears in
  arp_spoofing_ips.
- dns_amp: rule_signals.amp_alerts non-empty AND UDP/53 responses
  dominate.
- beaconing_c2: advanced_signals.beaconing non-null and periodic.
- dns_tunnel: advanced_signals.dns_tunneling non-null OR unusually long
  DNS query strings.
- benign_anomaly: any statistical outlier without a matching attack
  pattern in the signals. Prefer this over "malicious" when in doubt.
```

גרסת prompt: כרגע `v0.5.0` (ראו `llm_judge/PROMPT_CHANGELOG.md`
להיסטוריית הגרסאות ו-kappa פר-גרסה). מועלה על ידי
`docs/PROMPT_CHANGELOG.md`.

### 10.2 ‏prompt של משתמש

רק ה-JSON blob של המועמד (§4.2), מילה-במילה, בהודעה יחידה.

### 10.3 קונפיגורציית LLM

- `response_format = json_object` (או שוות-ערך של ספק של JSON
  קפדני).
- Temperature: ‏`0.0` לשחזור במהלך כיול; ‏`0.2` בפרודקשן לווריאציה
  קלה על `reasoning`.
- Max output tokens: 400.
- Timeout: 15 שניות פר-בקשה. ב-timeout, להתייחס ככישלון סכמה
  (retry פעם אחת, אז drop).

### 10.4 בחירת ספק

לא ספציפי כאן. המודול `app/llm_judge.py` חושף protocol
`LLMClient` עם שיטה אחת `judge(context: dict) -> dict`.
יישומים קונקרטיים לכל ספק חיים ב-
`app/llm_clients/`. הספק הפעיל נבחר על ידי
`LLM_JUDGE_PROVIDER` בקונפיגורציה. זה שומר על החלפה לספק אחר
(או מודל on-prem דרך Ollama) מכני.

---

## 11. נקודות אינטגרציה

קבצים שנגעו על ידי ההטמעה, ואיך:

| קובץ | סוג שינוי | מה |
|---|---|---|
| `app/llm_judge.py` | **חדש** | `judge_candidates()`, `assemble_candidates()`, protocol `LLMClient` |
| `app/llm_judge_config.py` | **חדש** | ‏Feature flag, משקלים, ספים, גרסת prompt |
| `app/llm_clients/__init__.py` | **חדש** | רישום ספק |
| `app/llm_clients/<provider>.py` | **חדש** | ‏`LLMClient` קונקרטי פר-ספק |
| `app/Network_Security_Dashboard.ipynb` | שנה | תא חדש אחד שקורא ל-`judge_candidates()`; כרטיס UI לתור + reasoning; פילת Model Diagnostics |
| `app/dashboard_module.py` | מתחולל מחדש | דרך `tools/export_dashboard_module.py` - אל תערכו ידנית |
| `attack_tests/calibrate_judge.py` | **חדש** | CLI: הריץ שופט על PCAPs של ground-truth, שפוך תוצאות kappa |
| `attack_tests/calibration/results/` | **תיקייה חדשה** | JSON כיול פר-גרסת prompt |
| `docs/schemas/candidate_context.schema.json` | **חדש** | סכמת קלט |
| `docs/schemas/judge_verdict.schema.json` | **חדש** | סכמת פלט |
| `docs/PROMPT_CHANGELOG.md` | **חדש** | היסטוריית גרסת prompt + delta של kappa פר-גרסה |
| `data/judge_cache.sqlite` | artifact זמן ריצה | לא מחויב; `.gitignore` |
| `data/analyst_verdicts.jsonl` | artifact זמן ריצה | לא מחויב; `.gitignore` |
| `tests/test_judge_kappa_regression.py` | **חדש** | שער CI |
| `tests/test_llm_judge_unit.py` | **חדש** | בדיקות unit עם LLM mocked |
| `requirements.txt` | שנה | ‏`+ jsonschema`, `+ <provider SDK>` |
| `.gitignore` | שנה | `data/judge_cache.sqlite`, `data/analyst_verdicts.jsonl` |

**שום דבר ב-`run_pipeline.py`, `evaluate.py`, `test_detection_regression.py`,
או בתאי notebook קיימים 8 / 12 / 16 / 22-26 לא משתנה.** השופט
אדיטיבי.

---

## 12. אינטגרציית דשבורד

שלושה שינויי UI, כולם ב-notebook:

### 12.1 כרטיס תור מדורג מחדש

כרטיס Dash חדש, "Triaged Anomalies", נכנס לסקשן האבטחה.
עמודות:

| # | IP | Verdict | Cat | Conf | Evidence | Reasoning |
|--:|---|---|---|--:|---|---|
| 1 | 192.168.1.10 | malicious | port_scan | 0.98 | syn_count, unique_dsts, scan_alert.SYN | "יחס SYN 1.00 על פני 1000 יעדים נבדלים ב-71 שניות ..." |

השורות ממוינות לפי priority של ensemble (§9). ‏hover של שורה
חושף את ה-JSON blob של הקלט המלא. לחיצה על שורה פותחת widget
verdict של אנליסט (agree / disagree / override + note).

### 12.2 פילת Model Diagnostics

כרטיס Model Diagnostics הקיים מקבל פילה חדשה:

```
Judge kappa (live): 0.72
```

מחושב לפי דרישה מ-log של verdict אנליסט ל-N הימים האחרונים
(ברירת מחדל N=7). אם אין verdicts שהוקלטו עדיין, הראו `n/a`.

### 12.3 ‏Feature flag

בראש ה-notebook:

```python
LLM_JUDGE_ENABLED = True
```

כש-`False`, הכרטיס החדש מוסתר והתור חוזר להזמנה הנוכחית של
IsolationForest-only. גם הפילה של Model Diagnostics נעלמת.
זה הכלי A/B.

---

## 13. פריסת קבצים - עץ חדש מלא

```
app/
├── llm_judge.py                          חדש
├── llm_judge_config.py                   חדש
└── llm_clients/                          חדש
    ├── __init__.py
    └── <provider>.py

attack_tests/
├── calibrate_judge.py                    חדש
└── calibration/                          חדש
    └── results/
        └── v0.1.0.json                   (מופק על ידי calibrate)

data/                                     חדש (gitignored)
├── judge_cache.sqlite
└── analyst_verdicts.jsonl

docs/
├── LLM_JUDGE_SPEC.md                     קובץ זה
├── PROMPT_CHANGELOG.md                   חדש
└── schemas/                              חדש
    ├── candidate_context.schema.json
    └── judge_verdict.schema.json

tests/
├── test_judge_kappa_regression.py        חדש
└── test_llm_judge_unit.py                חדש
```

---

## 14. תכנית rollout

שלבים מסודרים. כל אחד הוא commit / PR עצמאי.

1. **תיקון באגים ידועים של edge-case ב-DBSCAN / `eps_auto`**
   (תנאי יציבות בייסליין - השופט יורש כל קלט שהבייסליין מפיק).
   זה scope הגנתי; דלגו רק אם ה-CI הנוכחי ירוק מול חמשת ה-PCAPs
   של ground-truth ואין issues פתוחים באזור הזה.
2. **נחתת סכמות + שלד קונפיגורציה.** `docs/schemas/*`,
   `app/llm_judge_config.py`, `data/` ב-`.gitignore`. אין שינוי
   התנהגות.
3. **נחיתת `app/llm_judge.py` מאחורי feature flag, flag כבוי
   כברירת מחדל.** כולל `assemble_candidates()`, protocol
   `LLMClient`, ספק קונקרטי אחד, ‏cache, ‏retry/drop.
4. **נחיתת `attack_tests/calibrate_judge.py`** ו-commit של תוצאת
   הכיול הראשונה ב-`attack_tests/calibration/results/v0.1.0.json`.
   דווחו kappa בתיאור ה-PR.
5. **נחיתת `tests/test_judge_kappa_regression.py`.** סף ב-0.60
   בהתחלה (מתחת לערך הנמדד של v0.1.0, מה שלא יהיה), לתת מרווח
   לכמה איטרציות ראשונות של prompt בלי לחסום מידית merges.
   העלו ל-0.65 אחרי שתי איטרציות מוצלחות של prompt.
6. **נחיתת תא דשבורד + כרטיס UI + widget של verdict log.** ‏Flag
   נשאר כבוי ב-`main`; מפתחים הופכים אותו מקומית.
7. **הפכו את ה-flag** ברגע ש-kappa קטגוריה >= 0.65 על סט הכיול
   ובדיקות unit עוברות.

לולאת איטרציה מצעד 3 ואילך:

```
עריכת prompt -> העלאת PROMPT_VERSION
            -> הרצת calibrate_judge
            -> השוואת kappa מול הקודם
            -> commit אם kappa לא נסוג
            -> עדכון docs/PROMPT_CHANGELOG.md
```

---

## 15. מטריקות

נרשמות בכל ריצת כיול ובכל session חי.

| מטריקה | היכן | יעד |
|---|---|---|
| ‏Category kappa (כיול) | `attack_tests/calibration/results/<v>.json` | >= 0.70 |
| ‏Category kappa (חי מתגלגל 7 ימים) | פילת Model Diagnostics | >= 0.60 |
| ‏Precision @ top-50 מול anomaly-only | הערכה offline | +25 pp |
| שיעור FP-burn (מועמדים שהאנליסט דוחה לשעה) | log של verdict אנליסט | −50% |
| ‏LLM latency ‏p50 / p95 | DB של cache | נעקב, בלי SLA קשיח |
| עלות LLM פר-מועמד (טוקנים × מחיר) | DB של cache | נעקב, cap קשיח של `MAX_TOKENS_PER_BATCH` |
| שיעור הסכמת אנליסט | log של verdict חי | 60-85% (גבולות - ראו למטה) |
| מטריצת confusion פר-קטגוריה (מתגלגלת) | כיול + חי | ‏off-diagonal < 15% פר-תא |

**גבולות הסכמת אנליסט:** מתחת ל-60% מסמן סחיפת prompt → כיילו מחדש.
מעל 85% מסמן rubber-stamping → דגמו 5% מה-verdicts שבועית ל-audit.

---

## 16. גבולות scope

- השופט הוא triage. הוא לא פועל. `recommended_action: "block"` זו
  הצעה, לעולם לא מחווטת ל-blocklist או ל-firewall.
- מצב הקלטה חי (streaming של `tshark`) מחוץ ל-scope ל-v1.
  השופט רץ רק בזמן טעינת PCAP. אלטרנטיבה C (§7.3) היא הדלת
  בחזרה פנימה.
- קטגוריות beaconing ו-dns-tunnel מוצהרות ב-enum אבל עדיין לא
  ב-ground truth. הכיול שלהן נמדד רק מול PCAPs סינתטיים או שיוספו
  בעתיד; ‏kappa מחושב רק על הקטגוריות עם כיסוי אמת עד אז.
- השופט הוא single-tenant. בלי auth רב-משתמשי על ה-widget.
  ‏verdicts של אנליסט מתווספים לקובץ מקומי; פריסת SOC עתידית
  צריכה store מתאים.

---

## 17. סיכונים ומיטיגציות

| סיכון | מיטיגציה |
|---|---|
| סחיפת prompt בשקט מרגיסה kappa | שער CI על ‏category kappa; `docs/PROMPT_CHANGELOG.md` רושם kappa פר-גרסה |
| ‏outage של API של LLM חוסם טעינת דשבורד | ‏Feature flag + cache - cache חם לחלוטין מגיש בלי ה-API |
| LLM מפיק JSON לא תקין | אימות schema + retry אחד + drop + log |
| עלות מתפוצצת על PCAP גדול | ‏cap קשיח `MAX_CANDIDATES_PER_BATCH`; רישום מועמדים שנזרקו |
| אנליסט חותם כגומי על verdicts | audit של דגימה אקראית שבועית של 5%; מטריקה של שיעור חוסר-הסכמה |
| סט ‏Ground-truth קטן (חמישה PCAPs) | log של verdict אנליסט מרחיב את סט האמת עם הזמן; הצהרנו עליו במפורש כמגבלה ידועה עד שיוספו PCAPs של beaconing / tunnel |
| הרעלת cache על ידי תגובה לא תקינה שנכתבת | רק verdicts שאומתו-schema נכתבים ל-cache |
| אי-דטרמיניזם בעקבות reasoning שובר בדיקות | הבדיקות קובעות רק על שדות מובנים (verdict, category, confidence), לעולם לא על מחרוזת ה-reasoning |

---

## 18. שאלות פתוחות

נשארו למיישם:

1. **בחירת ספק.** המפרט אגנוסטי לספק. איזה מודל? ‏on-prem Ollama?
   ‏SaaS API? ‏protocol ‏`LLMClient` מקבל אחד או אחר - אבל ספק
   ברירת המחדל שמחויב ל-`requirements.txt` צריך החלטה.
2. **מקורות העשרה.** ‏`enrichments.reverse_dns` ו-
   `enrichments.asn` מוצהרים. האם הם מאוכלסים מ-MaxMind DB
   מקומי, חיפוש חי, או משאירים null ב-v1?
3. **שפת prompt.** אנגלית כברירת מחדל; גרסת prompt עברית אפשרית
   אבל מוסיפה ציר אחד של סחיפה. ממליצים אנגלית בלבד ל-v1.
4. **משקול Kappa.** לא-משוקלל מול לינארי משוקלל. ‏kappa לינארי
   סלחני יותר לקטגוריות near-miss (`syn_flood` נחזה כ-`port_scan`
   פחות גרוע מ-`benign`). ממליצים לינארי.
5. **מודל עלות CI.** כיול ידני + fixture שהוקלט (§8.4
   שער אלטרנטיבי) מול קריאת LLM אמיתית ב-CI לילי בלבד. ממליצים
   ידני + fixture עד שעלות היא לא-נושא מוכח.

---

## 19. הגדרת הצלחה

v1 גמור כשכל הדברים הבאים מתקיימים:

- `LLM_JUDGE_ENABLED = True` ב-`main`.
- ‏Category kappa על סט הכיול >= 0.65.
- `tests/test_judge_kappa_regression.py` שומר `main`.
- כרטיס התור המדורג-מחדש של הדשבורד נראה בטעינות S1 ו-S2.
- כרטיס Model Diagnostics מציג פילת kappa חיה.
- ל-`docs/PROMPT_CHANGELOG.md` יש לפחות רשומה אחת.
- ‏Category kappa על סט הכיול לא נסוג על פני 3 ה-commits האחרונים.

v1 במפורש **לא** נדרש:

- לכסות `beaconing_c2` או `dns_tunnel` על נתונים מתויגים.
- לתמוך במצב הקלטה חי.
- לחסום אוטומטית שום דבר.

</div>
