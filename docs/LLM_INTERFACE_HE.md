<div dir="rtl" align="right">

# שופט LLM - מה שואלים, מה המודל רואה, מה הוא מחזיר

החוזה המדויק בין צינור NetSec לשופטי ה-LLM. כל שופט בפאנל מקבל
את אותם שלושה דברים פר-מועמד: ‏prompt מערכת (קבוע), ‏blob מועמד
(JSON פר-מועמד), וסכמת JSON שהוא חייב להתאים לה. בלי context מוסתר,
בלי retrieval, בלי כלים. קריאת HTTP אחת = מועמד אחד = verdict אחד.

**מקור האמת:** [llm_judge/judge_core.py](../llm_judge/judge_core.py)
(‏SYSTEM_PROMPT, ‏VERDICT_SCHEMA, ‏`_verdict_from_client`,
`judge_candidates_panel`). המסמך הזה הוא מראה; אם הוא זז, הקוד
מנצח.

---

## 1. איך נראית ריצת פאנל

ל-PCAP אחד:

1. הצינור רץ (`analyze_pcap` -> `run_ml_on_session` ->
   `run_security_scans`).
2. `assemble_candidates` בוחר את ה-IPs / sessions שאיזה detector סימן
   ואורז כל אחד ל-JSON blob (סכמה למטה).
3. לכל מועמד, ‏`judge_candidates_panel` מוציא בקשת HTTP אחת
   פר-שופט, במקביל, דרך `_verdict_from_client`.
4. אם השופטים לא מסכימים על תווית ה-verdict או על הקטגוריה, כל
   שופט מקבל קריאת HTTP שנייה - תור ה-debate - עם ניתוחי השופטים
   האחרים באנונימיות.
5. ‏resolver דטרמיניסטי בוחר את ה-verdict האפקטיבי מכל העמדות
   שאחרי ה-debate (החמורות ביותר מנצחות על פיצולים; תיקו נפתר
   על confidence).
6. ‏מעקה החוקים מכריח "suspicious" (עם קטגוריית החוק) על כל
   מועמד שעל חוקו שנדלק הפאנל אמר "benign".

זמן השעון נשלט על ידי השופט האיטי ביותר, לא על ידי מספר השופטים.
מודלי Groq עונים ב-~0.5-1 שניות; שופט Ollama של CPU-only לוקח
~50 שניות.

---

## 2. ‏prompt המערכת (קבוע - כל שופט, כל מועמד)

כל בקשה נפתחת עם הבלוק הזה, מילה-במילה. הוא לעולם לא משתנה בזמן
ריצה; הסכמה משולבת כך ששרת מצב-קפדני יכול לאכוף אותה.

```
You are a network-security triage analyst. You receive a JSON blob
describing one candidate (an IP, a flow, or the whole session) that at
least one unsupervised detector or deterministic rule has flagged. Your
job:

1. Return a strict JSON object matching the schema below. No prose
   outside the JSON. No markdown fences.
2. Assign a verdict (benign | suspicious | malicious) and a category
   from the fixed enum.
3. Ground every claim in the input blob - cite feature names in
   evidence_features.
4. If the signals are contradictory or thin, prefer "suspicious" over
   "malicious". If they are strong and unambiguous, use "malicious".
5. Never invent facts not in the blob. If a field is null, it is unknown,
   not zero.
6. recommended_action is a suggestion for a human, never an action
   this system will execute.
7. confidence is a number between 0.0 and 1.0. reasoning is a single
   paragraph, no newlines, at most 400 characters.
8. The deterministic rules are HIGH-PRECISION. If any rule has fired -
   rule_signals.scan_alerts / amp_alerts / flood_alerts is non-empty, or
   arp_multi_mac is true - classify into the matching attack category and
   do NOT return "benign". Only override a fired rule if you can name
   concrete evidence in the blob that it misfired.
```

ואז סכמת ה-verdict מצורפת (ראו סעיף 4), גיליון הרמאויות של
הקטגוריות, ושתי דוגמאות מפורטות (סריקת SYN אנכית שממופה ל-
`malicious/port_scan`, ו-ML-only outlier שממופה ל-
`benign/benign_anomaly`).

גודל prompt כולל: ‏~1500 תווים. שמרו אותו קצר - כל מועמד משלם את
עלות הטוקנים שוב.

---

## 3. ‏blob המועמד (פר-מועמד - כל ה-context שהמודל רואה)

כל שדה שיש ל-LLM גישה אליו. כל השאר על ה-capture - פקטות גולמיות,
מוני פר-flow, מטא-דאטה של PCAP - נשאר בצינור ולעולם לא מגיע למודל.

```json
{
  "candidate_id": "192.168.1.10",
  "kind": "ip",

  "session_context": {
    "duration_s": 0.1,
    "total_packets": 2000,
    "total_ips": 2,
    "iso_timestamp": "2026-08-01T09:41:00",
    "hour_of_day": 9,
    "day_of_week": "Sat"
  },

  "features": {
    "mean_len": 54.0,
    "std_len": 0.0,
    "count": 1000.0,
    "burst_score": 1000.0,
    "unique_dsts": 1.0,
    "syn_count": 0.0,
    "rst_count": 0.0,
    "fin_count": 0.0,
    "null_count": 0.0,
    "xmas_count": 1000.0
  },

  "ml_signals": {
    "iso_score": 0.0,
    "iso_stability": 0.0,
    "anomaly": false,
    "cluster": -1,
    "silhouette": null,
    "lstm_bin_flag_count": null
  },

  "rule_signals": {
    "scan_alerts": [
      {"type": "XMAS", "count": 1000, "unique_dsts": 1, "ratio": 1.0}
    ],
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
    "hostname": "orarr-macbook.local",
    "oui_vendor": "Apple, Inc."
  },

  "websites": {
    "top_http_hosts": null,
    "top_tls_sni": [
      {"host": "cloudflare.com", "count": 87},
      {"host": "googleapis.com", "count": 34}
    ],
    "top_dns_queries": [
      {"host": "evil-c2.duckdns.org", "count": 128},
      {"host": "pool.ntp.org", "count": 12}
    ]
  },

  "traffic": {
    "top_dst_ports": [
      {"port_proto": "443/tcp", "count": 900},
      {"port_proto": "53/udp", "count": 30},
      {"port_proto": "80/tcp", "count": 20}
    ],
    "bytes_in": 3000000,
    "bytes_out": 1000000,
    "upload_ratio": 0.25
  },

  "enrichments": {
    "is_private": true,
    "reverse_dns": null,
    "asn": null,
    "baseline_seen_before": null
  },

  "trigger_reasons": ["scan_rule"]
}
```

### סמנטיקה של קבוצות שדה

- **‏`candidate_id` + `kind`** - זהות. ‏`kind` הוא `ip` למועמדים
  פר-host או `session` לחוקים אגרגטיביים (למשל spoofed SYN flood).
- **‏`session_context`** - סכומי capture ברמה כדי שהשופט ידע את
  הסקאלה ("1000 פקטות מה-IP הזה מתוך 2000 בסה"כ = הוא דומיננטי"),
  בתוספת `iso_timestamp`, ‏`hour_of_day` (0-23), ו-`day_of_week`
  (Mon..Sun) כך שפעילות מחוץ לשעות העבודה נושאת משקל. כל שלושת
  שדות הזמן הם null כאשר הקורא בנה S בלי timestamp אמיתי (למשל
  unit tests).
- **‏`features`** - 10 העמודות הסטטיסטיות שעליהן מודלי ה-ML מתאמנים.
  כל הספירות והיחסים הם עבור IP המועמד בלבד.
- **‏`ml_signals`** - ציון IsolationForest + יציבות, מזהה cluster
  של DBSCAN (-1 = noise), ‏silhouette (כשקיים cluster אמיתי), וספירת
  bin flags של LSTM (מאוכלס רק עבור captures עם ≥ 20 מקבצי-זמן
  שמישים).
- **‏`rule_signals`** - החוקים הדטרמיניסטיים שנדלקו. אלה
  **בעלי דיוק גבוה** - אם איזשהו לא ריק, גיליון הרמאויות של הסכמה
  ו-ה-prompt מורים ל-LLM לנתב לקטגוריית התקיפה המתאימה ולעולם לא
  להחזיר "benign".
- **‏`advanced_signals`** - חמשת המנועים פר-IP (‏beaconing / DNS
  tunnel / DGA / TLS anomaly / fusion score). מאוכלס רק כשהמנוע
  נדלק על מועמד זה; ‏`null` אומר "לא נדלק", לא "נקי" - ה-prompt
  מלמד את המודל את ההבדל.
- **‏`device_context`** - `category` / `hostname` / `oui_vendor`.
  נתיב הדשבורד מאכלס את כל השלושה דרך `build_local_inventory` (מסווג
  התקנים + מצאי). נתיב ה-worker נופל ל-derivation קל שמשתמש רק ב-
  `S["ip_to_mac"]` (עבור `oui_vendor` דרך חבילת `manuf`) וב-
  `S["dns_per_ip"]` (עבור `hostname` דרך שמות mDNS של .local).
  בנתיב ה-worker ‏`_lightweight_device_context` עכשיו גוזר `category`
  מ-OUI / פורטים / שמות DNS כ-נפילה חזרה; מצאי שהופק בדשבורד שמחובר
  ב-`S["_local_inv"]` עדיין מקבל קדימות.
- **‏`websites`** - `top_http_hosts` / `top_tls_sni` / `top_dns_queries`,
  כל אחד רשימה מסודרת (עד 5, לפי count) של פריטי `{host, count}` או
  `null` כאשר הצינור לא צפה בתעבורה מהסוג הזה עבור IP זה.
  ‏mDNS (`.local`), `.arpa`, ושאילתות PTR מסוננות החוצה לפני
  דירוג כך שהרשימה משקפת גלישה חיצונית אמיתית. ‏hostnames שנראים
  אקראיים תומכים ב-`advanced_signals.dga` / `.beaconing`.
- **‏`traffic`** - `top_dst_ports` (עד 5 פריטי `{port_proto, count}`,
  ‏proto = "tcp" או "udp"), ‏`bytes_in` / `bytes_out` (סכומים
  כיווניים), ו-`upload_ratio` (`bytes_out / (bytes_in + bytes_out)`,
  מעוגל ל-3 ספרות). ‏`upload_ratio` גבוה עם `bytes_out` משמעותי ויעד
  ציבורי הוא צורה של exfiltration נתונים. נוכחות של `445/tcp`,
  `3389/tcp`, `22/tcp`, `5985/tcp` על host פנימי הוא אות של תנועה
  לרוחב.
- **‏`enrichments`** - `is_private` הוא השדה היחיד שתמיד מאוכלס.
  ‏`reverse_dns`, `asn`, `baseline_seen_before` שמורים למנועי העשרה
  עתידיים (‏Shodan מחובר אבל כבוי אלא אם
  `NETSEC_ENABLE_SHODAN=1`).
- **‏`trigger_reasons`** - למה המועמד הזה אפילו נבחר (אחד או יותר
  מ-`isolation_forest`, `dbscan_noise`, `scan_rule`, `amp_rule`,
  `arp_rule`, `flood_rule`, `lstm`). הפאנל משתמש בזה כדי להצדיק
  למה אנומליית ML-only לא נדרשת להיות זדונית.

---

## 4. סכמת ה-verdict (מה ה-LLM חייב להחזיר)

```json
{
  "type": "object",
  "properties": {
    "verdict":        {"type": "string", "enum": ["benign", "suspicious", "malicious"]},
    "category":       {"type": "string", "enum": ["beaconing_c2", "dns_tunnel", "dns_amp",
                                                  "port_scan", "arp_mitm", "syn_flood",
                                                  "benign_anomaly"]},
    "confidence":     {"type": "number"},
    "evidence_features": {"type": "array", "items": {"type": "string"}},
    "reasoning":      {"type": "string"},
    "recommended_action": {"type": "string", "enum": ["monitor", "investigate", "block"]}
  },
  "required": ["verdict", "category", "confidence", "evidence_features",
               "reasoning", "recommended_action"],
  "additionalProperties": false
}
```

תשובה אמיתית מ-`qwen2.5:3b` על המועמד למעלה:

```json
{
  "verdict": "suspicious",
  "category": "port_scan",
  "confidence": 0.95,
  "evidence_features": ["rule_signals.scan_alerts", "features.xmas_count"],
  "reasoning": "The high burst score suggests a more sophisticated attack.",
  "recommended_action": "investigate"
}
```

אימות צד-client (`validate_verdict`) ואז:

- מנרמל `reasoning` לשורה אחת וחותך ל-400 תווים,
- מכפה `confidence` ל-`round(float, 3)` ודוחה מחוץ ל-[0, 1],
- קוצץ `evidence_features` ל-12 פריטים,
- דוחה כל דבר מחוץ ל-enums או שדה נדרש חסר.

תגובה בעלת פגם עוברת ניסיון חוזר **פעם אחת** (שגיאת אימות JSON היא
בדרך כלל שיהוק חד-פעמי של מודל); ‏4xx קבוע מהשרת
(‏`json_validate_failed` של ‏`allam-2-7b`, מודל לא ידוע, מפתח גרוע)
מתויג עכשיו `permanent=True` ומדלג על לולאת ה-ניסיון חוזר לגמרי - תיקון
H3.

---

## 5. תור ה-debate (רק כשהשופטים לא מסכימים)

כששני verdicts תקינים או יותר מהסבב 1 שונים ב-`verdict` או
ב-`category`, הפאנל יורה קריאה שנייה לכל שופט תקין עם ניתוחי
השופטים האחרים באנונימיות כ-"Analyst 1", "Analyst 2", ...,
וסכמה אחרת (`DEBATE_SCHEMA`) שמוסיפה:

- `stance` (`maintain` | `revise`),
- `rebuttal` (פסקה אחת, ‏<=300 תווים, מתייחסת לנקודת ההתנגדות
  החזקה ביותר).

ה-prompt מזכיר לשופט שחוק דטרמיניסטי שנדלק עדיין בעל דיוק גבוה,
אז "benign" על מועמד שחוק נדלק עליו עדיין שגוי גם אם peer טען
לטובתו.

‏rebuttal אמיתי של debate מ-session 6 של xmas scan (כל שלושת
השופטים אמרו דברים שונים):

```
llama-3.1-8b-instant (maintain):
  "While Analyst 3's description of the scan as 'vertical' is accurate,
   it does not change the fact that the deterministic scan rule fired,
   indicating a malicious activity."

llama-3.3-70b-versatile (maintain):
  "Analysts 1 and 3 agree the scan rule fired, but 'suspicious'
   underestimates the threat; 1000 XMAS packets against one destination
   is a clear malicious indicator."

qwen2.5:3b (revise):
  "The high burst score suggests a more sophisticated attack."
```

ה-resolver הדטרמיניסטי אז בוחר את ה-verdict האפקטיבי מהעמדות
שלאחר ה-debate (תווית הרוב מנצחת; תיקו נפתר על confidence; פיצולים
משתמשים בחומרת fail-safe ומגדירים `needs_human_review=True`).

---

## 6. זמן שעון של פאנל ואיפה הזמן הולך

נמדד על VM הפרודקשן (‏Oracle ARM 4 vCPU / 24GB) עם
**פאנל ‏balanced_4 בן 4 שופטים** (הופעל 2026-08-01; ‏preset ברירת
המחדל כעת הוא `reliable_hybrid_4`: ‏groq:llama-3.1-8b-instant,
groq:openai/gpt-oss-120b, ollama:qwen2.5:3b, ollama:granite3.3:2b):

| שופט | Latency של סבב 1 | הערות |
|---|---|---|
| `groq:llama-3.1-8b-instant` | ‏~500ms | ‏Groq HTTP + הסקה, 100k טוקנים/יום חינם |
| `groq:llama-3.3-70b-versatile` | ‏~700ms | ‏Groq HTTP + הסקה, 100k טוקנים/יום חינם |
| `ollama:qwen2.5:3b` | ‏~53 שניות | הסקה מקומית CPU-only על ARM (צוואר הבקבוק) |
| `gemini:gemini-2.5-flash` | ‏~1-2 שניות | ‏Google AI Studio Bearer-auth, 15 RPM / 1M טוקנים/יום חינם |

זמן שעון של פאנל פר-מועמד = **max(כל השופטים)** כי הפאנל מריץ
אותם במקביל דרך `ThreadPoolExecutor`. אז ריצה של 4 שופטים מלאה
עדיין עולה ~53 שניות פר-מועמד, שנשלטת על ידי qwen (שלושת שופטי
הרשת מסיימים ו-idle בציפייה למודל המקומי). PCAP עם 5 מועמדים
לוקח ~4-5 דקות end-to-end.

אם שופט נכשל (‏4xx קבוע, ‏timeout, כל ה-retries מוצו), הפאנל ממשיך
לרוץ עם השורדים; ה-verdict האפקטיבי עדיין מופק והשופט הכושל נרשם
בדוח ההשתתפות. ממש: ‏1 או 2 מתוך 4 השופטים למטה, ‏`resolve_panel`
עדיין מחזיר verdict; רק אם כל 4 נכשלים המועמד נוחת ב-`dropped`.

**למה 4 ולא 5 או 6?** החזרות ירידות על גיוון - שני מודלי Groq
(שניהם ממשפחת Meta Llama) נותנים בייסליין חזק של "LLM מודרני
שעבר instruction-tuning"; ‏Gemini מוסיף corpus אימון באמת שונה
(‏Google DeepMind); ‏Qwen מוסיף בדיקה מקומית מחוץ-למשפחה (‏Alibaba)
שגם מכסה את המקרה של "מה אם כל ספקי הענן יורדים". הוספת מודל 5
על Groq תספור כפול את הטיית המשפחה; הוספת מודל מקומי 5 איטי
תדחוף את זמן השעון מעבר ל-2 דקות פר-מועמד. קונפיגורציית 4 השופטים
היא נקודת-אמצע מתועדת של diversity-cost ב-`docs/VM_ARCHITECTURE_SPEC_HE.md`
סעיף 10.

---

## 7. מה נוסף ב-I2 (2026-08-01) ומה נשאר פתוח

נמסר בגרסת prompt **‏v0.4.0** (נוכחי: **‏v0.5.0**):

- `session_context.hour_of_day` / `.day_of_week` / `.iso_timestamp`
- `device_context.oui_vendor` + `.hostname` (קל, נתיב worker;
  מצאי מלא עדיין דורש את `build_local_inventory` של הדשבורד)
- בלוק `websites` עם `top_http_hosts` / `top_tls_sni` / `top_dns_queries`
- בלוק `traffic` עם `top_dst_ports` / `bytes_in` / `bytes_out` /
  `upload_ratio`

שינויי צינור (`attack_tests/run_pipeline.py`):

- `FIELDS` קיבל `http.host` ו-`tls.handshake.extensions_server_name`
  (עמודת tshark נוספת אחת כל אחד; פקטות לא מושפעות מחזירות "").
- `analyze_pcap` עכשיו מחזיר `ip_to_mac`, `dns_per_ip`, `http_host_per_ip`,
  `tls_sni_per_ip`, `dst_ports_per_ip` כמפות Counter פר-IP ש-
  `assemble_candidates` צורכת.

נמסר ב-**‏v0.5.0** (היה פתוח):

- `device_context.category` בנתיב ה-worker - עכשיו נגזר על ידי
  `judge_core._lightweight_device_category` מ-OUI / פורטים / שמות DNS.
- גרסאות TLS + חבילות ciphers - עכשיו חשופות כבלוק `tls` דרך
  `judge_core._tls_for`.
- היסטוריית בייסליין (האם ה-IP הזה נראה קודם?) - עכשיו חשופה כבלוק
  `baseline_history` דרך `judge_core._history_for`.

כל העשרה היא additive; ה-prompt כבר מלמד את המודל ש-
`null` = לא ידוע, אז שדות חדשים לעולם לא רומזים בטעות "נצפה אפס".
‏העלאת `PROMPT_VERSION` (בוצעה: ‏`v0.3.0` -> `v0.4.0` -> `v0.5.0`) מבטלת כל
verdict ב-cache כך שהמודל שופט מחדש עם הקלט העשיר יותר בריצה הבאה.

---

## 8. איפה לשנות מה

| שינוי | קובץ |
|---|---|
| הוספה / עריכה של סעיפי prompt | `llm_judge/judge_core.py` (`SYSTEM_PROMPT`, `DEBATE_SYSTEM_PROMPT`) |
| הוספה / עריכה של סכמת output | `llm_judge/judge_core.py` (`VERDICT_SCHEMA`, `DEBATE_SCHEMA`) |
| הוספה / הסרה של שדות blob | `llm_judge/judge_core.py` (`assemble_candidates`) |
| התנהגות הגבלת קצב / ניסיון חוזר | `llm_judge/llm_clients.py` (`OpenAICompatClient._MAX_RETRIES`, `_MAX_WAIT_S`, `permanent`-tagging) |
| אילו שופטים רצים | `LLM_JUDGE_PANEL` ב-`deploy/.env` |
| ‏Debate on/off | `LLM_JUDGE_DEBATE` ב-`deploy/.env` |

שינוי prompt מעלה את `PROMPT_VERSION` ב-`llm_judge/judge_config.py`;
הגרסה הזאת היא חלק מה-טביעת אצבע של ה-cache, אז העלאתה מבטלת
כל verdict ב-cache אוטומטית.

</div>
