<div dir="rtl" align="right">

# LLM-as-Judge - Notebook עצמאי ל-Triage

הרחבה **אופציונלית, עצמאית לחלוטין** לדשבורד NetSec. הדשבורד הראשי
(`app/Network_Security_Dashboard.ipynb`) רץ בדיוק כמו קודם ולא יודע
על התיקייה הזאת; אם לעולם לא תפתחו את ה-notebook הזה, שום דבר כאן
לא ירוץ.

**קראו ראשון אם אתם חדשים כאן:**
[`docs/LLM_PANEL_ROLE.md`](../docs/LLM_PANEL_ROLE.md) מסביר **למה**
הפאנל קיים, אילו פערים ספציפיים הוא ממלא שחוקים דטרמיניסטיים ו-ML
לא יכולים, ואילו מעקות בטיחות מגבילים את מה שהוא עושה.

מה הוא עושה (עיצוב: [`docs/LLM_JUDGE_SPEC.md`](../docs/LLM_JUDGE_SPEC.md)):
צינור הזיהוי כבר מייצר ציונים פר-IP של ML (‏IsolationForest,
‏DBSCAN), התראות של חוקים דטרמיניסטיים (סריקות, הצפות, הגברת DNS,
‏ARP spoofing) - אבל כל אות מגיע בנפרד והאנליסט הוא זה שמאחד אותם.
ה-notebook הזה שולח כל מועמד שסומן, עם כל האותות שלו ב-JSON blob
אחד דחוס, למודל LLM שמחזיר **פסיקת JSON קפדנית** יחידה:
`benign | suspicious | malicious`, קטגוריית תקיפה, confidence,
הראיות שבהן השתמש, ו-reasoning trace של פסקה אחת. התור מדורג מחדש
לפי ציון ensemble ומוצג כטבלה.

השופט **לעולם לא פועל** - `recommended_action: "block"` זו הצעה
לבן אדם, לא מחוברת לכלום.

## ספקים - הביאו מודל משלכם

שלושה ספקים מובנים בתוספת מספר שרירותי של **פרופילי endpoint
מוגדרים בשם**. בחרו ריצת שופט יחיד עם `LLM_JUDGE_PROVIDER`, או פאנל
רב-ספקי עם `LLM_JUDGE_PANEL`:

| ספק | מה זה | הגדרה | עלות |
|---|---|---|---|
| `claude` (ברירת מחדל) | Anthropic API - איכות ה-JSON הטובה ביותר | `pip install -r llm_judge/requirements.txt` + הגדירו `ANTHROPIC_API_KEY` עם מפתח **משלכם** | המפתח שלכם, סנטים לכל PCAP |
| `ollama` | מודל מקומי דרך daemon של Ollama | התקינו מ-<https://ollama.com>, ‏`ollama pull qwen2.5:14b` (או כל מודל אחר) | חינם, offline |
| `openai_compat` | כל endpoint בסגנון OpenAI chat-completions: ‏LM Studio / llamafile / vLLM מקומי, או שירותים מאוחסנים שחושפים את פרוטוקול OpenAI | הגדירו `OPENAI_COMPAT_BASE_URL` + `OPENAI_COMPAT_MODEL` (+ `OPENAI_COMPAT_API_KEY` אם ה-endpoint צריך אחד) | חינם מקומית; מאוחסן לפי תנאיו |
| **פרופיל endpoint** | host שתואם ל-OpenAI עם שם, כך שפאנל יחיד יכול לערבב מספר ספקים (‏Groq + Gemini + …) בלי לערוך קוד | הגדירו שלושה משתני סביבה לכל פרופיל: ‏`LLM_JUDGE_EP_<NAME>_BASE_URL`, ‏`LLM_JUDGE_EP_<NAME>_MODEL`, ‏`LLM_JUDGE_EP_<NAME>_KEY_ENV=<env-var-holding-the-key>`. ‏`deploy/.env.example` נשלח עם חמישה פרופילים מוכנים לשימוש: ‏`GROQ`, ‏`GEMINI`, ‏`CEREBRAS`, ‏`OPENROUTER`, ‏`GITHUB`. התייחסו אליהם בפאנל כ-`groq:<model>`, ‏`gemini:<model>`, ... | לפי תנאי ה-free-tier של הספק |

**מפתח API לעולם לא נשמר בריפו הזה.** מפתחות נקראים מהסביבה בזמן
הקריאה; כל משתמש משלם (או לא) על שימוש משלו. מנגנון פרופילי
ה-endpoint במכוון לא לווה את `OPENAI_COMPAT_API_KEY` או את
`OPENAI_COMPAT_MODEL` הגלובליים: מפתח ומודל של פרופיל חייבים להיות
משלו, כך שמפתח שגוי לעולם לא ידלוף בין ספקים.

## התחלה מהירה

```bash
# 1. דרישות קדם של הפרויקט (פעם אחת): דרישות השורש + Wireshark מותקן
#    (‏tshark מזוהה אוטומטית בתיקיות ההתקנה הסטנדרטיות - אין צורך לערוך PATH)
pip install -r requirements.txt

# 2. בחרו ספק (ראו את הטבלה למעלה), למשל מקומי חינם:
set LLM_JUDGE_PROVIDER=ollama          # ‏Windows; ‏ export ... ב-Linux/macOS

# 3. פתחו את ה-notebook והריצו מלמעלה למטה
jupyter notebook llm_judge/LLM_Judge_Notebook.ipynb
```

## הסמכת מודל לפני שבוטחים בו - ה-benchmark

`benchmark_fixtures.json` מכיל **11 מועמדים מתויגים שחולצו מחמשת
קבצי ה-PCAP של תקיפות אמיתיות** על ידי צינור הפרודקשן. סקשן 0
של ה-notebook שופט את כולם עם כל מודל שתשמו ונותן לו ציון:

- **‏detection rate** - מועמדי תקיפה שנשפטו כלא-benign (עם ה-rule
  guardrail זה 1.0 לכל מודל שמחזיר JSON תקין);
- **‏category accuracy** - התאמה מדויקת של קטגוריית תקיפה: שם איכות
  המודל באמת מופיעה;
- **‏benign accuracy** - ‏ML-only outliers שנשארו נכון benign.

נמדד על מכונת CPU-only (11 fixtures, ‏guardrail פועל): ‏`llama3.2`
(3B) קיבל 100% בדיוק קטגוריה - אבל 7 מתוך 7 פסיקות התקיפה שלו היו
הצלות של ה-guardrail (המודל הגולמי אמר benign); ‏`gemma3:4b` קיבל
91% עם אפס הצלות (הפסיקות הגולמיות שלו כבר היו לא-benign). מודלים
מקומיים קטנים הם לכן שימושיים ל-triage ברמת detection; איכות
השיפוט הגולמית שלהם מופיעה רק על מועמדים שאף חוק לא מכסה, וזה
המקום שבו מודל חזק יותר עדיין מצדיק את מקומו.

## פאנל מומחים - רשת שופטים (opt-in)

במקום לבטוח במודל אחד, ‏`LLM_JUDGE_PANEL` מעביר כל מועמד דרך
**N שופטים עצמאיים** וגורם להם להתווכח לפני שמשהו מדווח:

```bash
# שני מודלי Groq על מפתח אחד (מופרדים בפסיק, אותו ספק):
set LLM_JUDGE_PANEL=llama-3.3-70b-versatile,llama-3.1-8b-instant
# או עירוב ספקים מפורש עם ערכים "provider:model":
set LLM_JUDGE_PANEL=openai_compat:llama-3.3-70b-versatile,ollama:llama3.2
```

זרימה פר-מועמד:

1. **סבב עצמאי** - כל שופט מחזיר פסיקה מסכימת-schema (ב-cache פר-מודל,
   אז ריצות חוזרות הן בחינם).
2. **סבב debate** - רק כשהשופטים לא מסכימים על ה-verdict או על
   הקטגוריה: כל שופט רואה את ניתוחי השופטים האחרים באופן אנונימי
   וחייב או **לעדכן** את עמדתו או **להגן** עליה ב-rebuttal שמצטט
   שדות מ-blob המועמד. מועמדים שעליהם יש הסכמה לא מפעילים קריאות
   נוספות.
3. **פתרון דטרמיניסטי** - הסכמה לוקחת את ה-verdict שלו ה-confidence
   הגבוה ביותר; מחלוקת ששרדה לוקחת את הצד ה-fail-safe (החמור יותר)
   ומסמנת `needs_human_review` (⚖). ה-rule guardrail עדיין שוכב מעל
   כל הפאנל.

כל ריצה גם מפיקה **דוח השתתפות** (ב-`verdicts.json` וב-markdown):
פר-מודל - מועמדים שהתקבלו, פסיקות תקינות, כשלים (עם דוגמאות),
debates, revisions, הסכמה עם ה-verdict הסופי, cache hits ו-latency
ממוצע. שופט שנכשל באתחול או עונה ג'יבריש מוחרג/נרשם והשופטים
הנותרים נושאים את ה-batch; הריצה נכשלת רק כשפחות משני שופטים
ניתנים לבנייה.

## שאלו את הארכיון: RAG על גבי פלט השופט

ה-`verdicts.json` של כל session (תוצאות פר-מועמד עשירות עם
projections של `evidence` + `context` של ה-capture המשומר) הוא
חומר המקור המושלם ל-QA מועשר-אחזור. מנוע `tools/netsec_rag.py` +
frontend של `tools/netsec_rag_web.py` ב-Dash מאנדקסים את ה-verdicts
של כל session ואת ה-summary ל-vector store מקומי (‏Ollama embeddings,
‏SQLite cosine store) וחושפים אותם ב-`https://<vm>/rag/`.

שאלו דברים כמו "אילו IPs על פני כל ה-sessions נשפטו כזדוניים",
"מה הפאנל אמר על 172.10.146.42", "אילו קטגוריות חוזרות הכי הרבה
ברשת שלי" - ה-RAG מאחזר את ה-verdicts בפועל מהארכיון ומקרקע את
תשובת המודל המקומי בהם. ראו `docs/ARCHITECTURE.md` איך זה משתלב
עם שאר המערך.

## הוספת שופט נוסף

הוספת מנוע נוסף = הוספת רשומה אחת ל-`LLM_JUDGE_PANEL` (אופציונלית
עם קידומת `provider:`). אין שינויי קוד. שני שופטים לא יכולים
לחלוק שם מודל - ‏verdicts מוחזקים ב-cache פר-מזהה מודל, אז כפילויות
היו מזייפות הסכמה.

ה-`LLM_JUDGE_COMMITTEE` הישן (צורה קבועה של שני מודלים, ללא debate)
נשמר כמצב legacy; כששניהם מוגדרים, הפאנל מנצח.

## ה-rule guardrail

שכבת החוקים הדטרמיניסטיים היא בעלת דיוק גבוה. נמדד שמודלים מקומיים
קטנים דורסים חוק שנדלק עם "benign" (תוך הזיה שלא נדלק שום חוק),
אז כברירת מחדל מועמד שחוקו נדלק לעולם לא יכול להסתיים כ-benign:
ה-verdict מועלה ל-`suspicious` עם הקטגוריה שהחוק מרמז עליה, ה-verdict
המקורי של המודל נשמר בתוצאה, וה-override מסומן (עמודת ⚑ ב-notebook).
כבו עם `LLM_JUDGE_RULE_GUARDRAIL=0`. ה-verdict הגולמי של המודל הוא
מה שנכנס ל-cache, אז החלפת מצב ה-guardrail לעולם לא דורשת איפוס cache.

## קבצים

| קובץ | תפקיד |
|---|---|
| `LLM_Judge_Notebook.ipynb` | נקודת כניסה אינטראקטיבית (‏Jupyter) |
| `judge_cli.py` | **‏CLI ללא ראש** - אותו צינור, בלי Jupyter, בשימוש על ידי ה-worker של ה-VM (גם שימושי מקומית) |
| `judge_config.py` | ספק/מודל, ‏guardrail, משקלים, ספים, גרסת prompt |
| `judge_core.py` | הרכבת מועמדים, system prompt, אימות verdict, ‏rule guardrail, ‏cache של SQLite, דירוג ensemble |
| `llm_clients.py` | `ClaudeClient` + `OllamaClient` + `OpenAICompatClient` |
| `benchmark.py` | הסמכת מודל: שופט את ה-fixtures המתויגים, מדרג דיוק/latency |
| `benchmark_fixtures.json` | 11 מועמדים מתויגים שחולצו מה-attack PCAPs (מחויב) |
| `calibration.py` | כיול Cohen's-kappa מול `attack_tests/ground_truth.json` |
| `send_report.py` | משלוח SMTP עצמאי (בשימוש על ידי `judge_cli --email`, על ידי notifier של worker ה-VM, וניתן לייבוא מכל מקום בפרויקט - ברירת מחדל ‏Gmail App Password, כל host של SMTP עובד) |
| `threat_intel.py` | ממזג מוניטין של Shodan לאות TI של מועמד + משקל דירוג (`W_TI`); נטען על ידי re-rank pass של worker ה-VM |
| `quota.py` | `QuotaStore` - מונה SQLite קטן לספירת בקשות/טוקנים יומית פר-ספק, מחובר לשדה `usage` ש-clients שתואמים ל-OpenAI מחזירים. אינפורמטיבי; שום דבר לא מדלג אוטומטית ספק שהגיע לגבול שלו |
| `requirements.txt` | תלויות אופציונליות של השופט בלבד (`anthropic`) על גבי `requirements.txt` של שורש הפרויקט |
| `schemas/*.schema.json` | חוזי JSON של input/output |
| `PROMPT_CHANGELOG.md` | היסטוריית גרסאות של prompt + kappa פר-גרסה |
| `calibration/results/` | דוחות כיול מחויבים (שער CI קורא את החדש ביותר) |
| `cache/`, `output/` | artifacts של זמן ריצה - ‏gitignored, בטוח למחיקה |

## הרצה בלי Jupyter - ה-CLI

```bash
python llm_judge/judge_cli.py path/to.pcap \
    --output verdicts.json \
    --markdown verdicts.md
```

אותו צינור זיהוי כמו ה-notebook, אותו guardrail, אותם משתני סביבה
של ספק. כותב:

- `verdicts.json` - batch מלא קריא-מכונה (סטטיסטיקות + תוצאות
  מדורגות + drops + capped). מאז דוח v2 כל תוצאה גם נושאת projection
  דחוס של `evidence` (זהות ההתקן, סיבות לטריגר, מספרי תעבורה מרכזיים,
  פורטים/אתרים מובילים, היסטוריית בייסליין) והקובץ נושא את ה-`context`
  של ה-capture (מתי הוקלט, פקטות, פרוטוקולים, קובץ מקור) - שניהם מזינים
  את מרנדרי הדוח ואת ההשוואה הזוגית S1-מול-S2.
- `verdicts.md` - הדוח האנושי: תקציר מנהלים עם שורות ראיה פר-ממצא,
  טבלת מועמדים מאוחדת, בלוקי Evidence-per-finding, ובמצב פאנל רשת
  Panel-votes שמציינת כל שופט ואת הצבעתו.

זו נקודת הכניסה של נתיב הסוכן האוטונומי שלמטה.

## סוכן אוטונומי

ה-workflow של GitHub Actions (`analyze-pcap.yml`) שבעבר הריץ את
השופט על PCAPs שנדחפו נגרס. הנתיב האוטונומי הוא כעת ה-worker של
ה-VM (`server/worker.py`), שתופס כל PCAP שהועלה ומריץ עליו את
אותו צינור CLI.

הבדיקות נמצאות עם שאר הסוויטה: ‏`tests/test_llm_judge_unit.py` ו-
`tests/test_llm_judge_providers.py` (‏LLM mocked + שרת תואם OpenAI
mock בתוך התהליך - בלי רשת), וגם
`tests/test_judge_kappa_regression.py` (קורא את תוצאת הכיול המחויבת;
מדלג עד שהראשונה קיימת).

## קונפיגורציה (משתני סביבה)

| משתנה | ברירת מחדל | משמעות |
|---|---|---|
| `LLM_JUDGE_PROVIDER` | `claude` | `claude` \| `ollama` \| `openai_compat` |
| `ANTHROPIC_API_KEY` | - | נדרש לספק Claude |
| `LLM_JUDGE_MODEL` | `claude-opus-4-8` | מזהה מודל Claude |
| `OLLAMA_MODEL` | `llama3.2` | שם מודל Ollama מקומי |
| `OLLAMA_HOST` | `http://localhost:11434` | כתובת daemon של Ollama |
| `OPENAI_COMPAT_BASE_URL` | `http://localhost:1234/v1` | ‏endpoint בסגנון OpenAI (ברירת מחדל: שרת LM Studio מקומי) |
| `OPENAI_COMPAT_MODEL` | - | שם מודל ב-endpoint הזה (נדרש לספק הזה) |
| `OPENAI_COMPAT_API_KEY` | - | מפתח Bearer, רק אם ה-endpoint צריך |
| `LLM_JUDGE_EP_<NAME>_BASE_URL` / `_MODEL` / `_KEY_ENV` | - | פרופיל endpoint עם שם (ראו סעיף Providers). מספר שרירותי של פרופילים; מתייחסים אליהם בפאנל כ-`<name>:<model>`. |
| `LLM_JUDGE_PANEL` | - | פאנל מומחים: שופטים מופרדים בפסיק (`model` או `provider:model`), ‏min 2 ייחודיים; ריק = כבוי. מנצח את `LLM_JUDGE_PROVIDER` עבור הריצה |
| `LLM_JUDGE_DEBATE` | `1` | `0` מדלג על סבב debate (הצבעת N-way פשוטה) |
| `LLM_JUDGE_PANEL_QUORUM` | `majority` | איך פאנל מפוצל מכריע. `majority`: רוב מוחלט (>50%) של שופטים תקפים בוחר את התווית; בלי רוב הצד החמור ביותר מנצח והמועמד מסומן `needs_human_review`. `fail-safe`: התווית החמורה ביותר תמיד מנצחת על כל פיצול (התנהגות לפני v0.5) |
| `LLM_JUDGE_GUARDRAIL_ESCAPE` | `1` | פתח יציאה צר ל-rule guardrail: ‏verdict ‏`benign` ב-confidence >= 0.85 שמצטט ראיות ב-whitelist (public resolver / anycast / known cloud provider) מועבר במקום להסתלם. כל bypass נרשם כ-`guardrail_bypassed`. `0` דורס כל benign-על-חוק-שנדלק |
| `LLM_JUDGE_BATCH_SIZE` | `1` | מועמדים ארוזים לקריאה אחת בסבב הראשוני של הפאנל. `1` = פר-מועמד. גודל לפי אריתמטיקה: בקשה עולה `1675 + n x 720` טוקנים (נמדד 2026-08 - ה-system prompt הוא ~1675 טוקנים משולם פעם אחת לקריאה, כל blob של מועמד ~720). מול תקרת הטוקנים לדקה החינמית של Groq של 6000 ל-`llama-3.1-8b-instant`, ‏`n=3` עולה 3835 ונכנס עם מקום; ‏`n=5` עולה 5275, כלומר 88% מהדקה כולה בבקשה אחת, אז כל קריאה מקבילה חונקת אותה לנפילה פר-מועמד שהיתה אמורה להחליף. ‏`n=3` גם מוציא 47% פחות טוקנים פר-capture מ-`n=1` |
| `LLM_JUDGE_COMMITTEE` | `0` | מצב ועדה של שני שופטים legacy. הוחלף על ידי `LLM_JUDGE_PANEL` |
| `LLM_JUDGE_COMMITTEE_MODEL_B` | `llama-3.1-8b-instant` | מודל שני לוועדת legacy |
| `LLM_JUDGE_RULE_GUARDRAIL` | `1` | `0` מכבה את ה-benign-override guardrail |
| `LLM_JUDGE_EFFORT` | `medium` | מאמץ reasoning של Claude (`low`/`medium`/`high`) |
| `LLM_JUDGE_TIMEOUT_S` | `300` | timeout פר-בקשה (מודלים מקומיים צריכים דקות ב-load הראשון) |
| `LLM_JUDGE_MAX_TOKENS` | `8192` | מקסימום טוקני פלט לכל verdict |
| `LLM_JUDGE_MAX_CANDIDATES` | `40` | תקרת batch; מועמדים שחוק הדליק תמיד שורדים |
| `LLM_JUDGE_KAPPA_THRESHOLD` | `0.60` | שער רגרסיה של CI על kappa קטגוריה (`tests/test_judge_kappa_regression.py`) |
| `LLM_JUDGE_QUOTA_DB` | `llm_judge/cache/llm_quota.sqlite` | היכן `QuotaStore` כותב מוני שימוש יומי פר-ספק |
| `LLM_JUDGE_ENABLED` | `1` | `0` הופך את השופט ל-no-op |
| `SMTP_USER` | - | תיבת דואר לשלוח ממנה את הדוח (מפעיל `--email`) |
| `SMTP_PASS` | - | ‏App password של אותה תיבת דואר |
| `SMTP_HOST` | `smtp.gmail.com` | שרת SMTP |
| `SMTP_PORT` | `587` | `587` STARTTLS, `465` TLS מרומז |
| `SMTP_FROM` | `SMTP_USER` | דריסת header של From: |

## שליחת הדוח באימייל

`send_report.py` שולח דוח מרונדר לכל כתובת, באמצעות `smtplib` של
stdlib ותיבת הדואר שלמשתני ה-SMTP למעלה מצביעים אליה - בלי שירות
צד-שלישי, בלי חשבון כאן:

```bash
# במהלך ריצה
python llm_judge/judge_cli.py capture.pcap --email you@example.com

# או עבור דוח שכבר קיים
python llm_judge/send_report.py verdicts.md you@example.com --json verdicts.json
```

ה-markdown מומר ל-HTML עבור הגוף ונשמר כחלופת plain-text, עם
`verdicts.json` כקובץ מצורף. כישלון משלוח מדווח ומחזיר קוד יציאה
לא-אפס מ-CLI העצמאי, אבל לעולם לא מבטל את `judge_cli.py` - ניתוח
שכבר רץ לא נזרק בגלל שתיבת דואר דחתה login. אותו module מניע את
התראות האימייל של worker ה-VM (`server/notify.py`).

## עלות ודטרמיניזם

- כל מועמד הוא קריאת LLM אחת של בערך 2-4 KB קלט ופלט JSON קטן.
  ‏Verdicts **ב-cache ב-SQLite** לפי fingerprint של (blob מועמד,
  גרסת prompt, מודל) - ריצה חוזרת של אותו PCAP היא בחינם וזהה
  byte-byte. ספקים מקומיים עולים כלום; על Claude PCAP טיפוסי
  (5-40 מועמדים) עולה סנטים על המפתח של המשתמש עצמו.
- אחרי שינוי מודל צריכה לבוא ריצת benchmark (סקשן 0 של ה-notebook)
  ו, לשימוש אמיתי, ריצת כיול - ‏kappa הוא פר-מודל.

## כיול - המספר שמשמר על ה-prompt

`attack_tests/ground_truth.json` מתייג חמישה קבצי PCAP של תקיפות אמיתיות.
סקשן הכיול של ה-notebook מריץ את השופט על כל החמישה ומחשב את
**‏Cohen's kappa** בין קטגוריות השופט לבין התוויות:

- מועמדים פר-IP מקבלים ציון מול רשימות היישויות המתויגות
  (‏IPs שסומנו ולא נמצאים ברשימה נחשבים `benign_anomaly` - ה-false
  positives שהשופט אמור לדרג למטה);
- קבצי PCAP של הצפה אגרגטית מקבלים ציון **רק** על המועמד ברמת
  ה-session, כי למקורות מזויפים אין זהות פר-IP משמעותית.

הדוח נוחת ב-`calibration/results/<prompt_version>.json` ועובר commit;
‏`tests/test_judge_kappa_regression.py` שומר על CI מולו **בלי לקרוא
ל-שום LLM**. לולאת האיטרציה של ה-prompt מתועדת ב-`PROMPT_CHANGELOG.md`.

## סטיות מה-spec (מתועדות בכוונה)

| ה-spec אמר | הוטמע | למה |
|---|---|---|
| candidate kind ‏`ip \| flow` | + `session` | הצפות מזויפות (37k מקורות) צריכות verdict אחד ב-scope של session, לא אלפי verdicts פר-IP חסרי משמעות |
| temperature 0.0 / 0.2 | אין params של sampling על Claude (נדחה על ידי מודלים נוכחיים); 0.0 על ספקים מקומיים | דטרמיניזם מגיע מ-cache הפסיקות |
| timeout של 15 שניות | ברירת מחדל 300 שניות | מודלים מקומיים שנטענים מדיסק צריכים דקות בקריאה הראשונה |
| "JSON קפדני" prompt-בלבד | פלטי מבנה של ספק + אימות client-side | חוקי-schema בבנייה על כל הספקים; retry-once-then-drop עדיין חל |
| ‏LLM verdict הוא סופי | + rule guardrail (הרחבה) | כישלון שנמדד: מודלים קטנים דורסים חוקים גבוהי-דיוק שנדלקו עם "benign"; ה-guardrail הופך את זה לבלתי אפשרי תוך שימור ה-verdict של המודל לשקיפות |
| כרטיס UI של דשבורד + פילת Model Diagnostics | טבלת notebook + ייצוא JSON | ההרחבה הזאת מופרדת במכוון מ-`app/` - הדשבורד נשאר ללא שינוי |
| CLI של ‏`attack_tests/calibrate_judge.py` | סקשני כיול + benchmark בתוך ה-notebook | ה-notebook הוא נקודת הכניסה היחידה לפי התכנון |

</div>
