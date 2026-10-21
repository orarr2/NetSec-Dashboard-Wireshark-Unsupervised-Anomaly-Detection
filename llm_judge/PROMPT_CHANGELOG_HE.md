<div dir="rtl">

# יומן שינויים של ה-Prompt לשופט

> גרסה עברית של [`PROMPT_CHANGELOG.md`](PROMPT_CHANGELOG.md).

כל שינוי prompt מעלה את `PROMPT_VERSION` ב-`judge_config.py` (מה שגם
מבטל את מטמון הפסיקות), מקבל ריצת כיול מהסקשן המיועד לכך ב-notebook,
ונרשם כאן עם ה-kappa שלו. ניתן לבצע commit לשינוי prompt רק אם ה-kappa
של הקטגוריה לא נסוג ביחס לגרסה הקודמת.

| גרסה | תאריך | שינוי | kappa קטגוריה (לינארי) |
|---|---|---|---|
| v0.1.0 | 2026-07-10 | prompt מערכת ראשוני מ-docs/LLM_JUDGE_SPEC.md סעיף 10.1, מורחב עם כלל ההצפה פר session-kind והגבלות מפורשות על confidence/reasoning. | הוחלף |
| v0.2.0 | 2026-07-11 | תיקון: גיליון-הרמאויות של `port_scan` תיאר רק סריקות אופקיות (unique_dsts גבוה), אז סריקת SYN אנכית (unique_dsts=1, יחס SYN גבוה - ה-`tcp_syn_scan.pcap` האמיתי) סווגה בטעות כ-benign. עכשיו מכסה את שתי הצורות ומתבסס על הדלקת `scan_alerts`. נוסף כלל 8: חוק דטרמיניסטי שהודלק הוא בעל דיוק גבוה ואין לבטלו כ-benign בלי נימוק. הוקשח `benign_anomaly` ל-ML-only outliers בלבד. | הוחלף |
| v0.3.0 | 2026-07-12 | נוספו שתי דוגמאות מפורטות (סריקת SYN אנכית → `port_scan`; ‏ML-only outlier → `benign_anomaly`) - נמדד שמודל מקומי קטן עדיין התעלם מכלל 8 בלעדיהן. הערה: מגרסה זו ה-prompt מושלם ב-rule guardrail ברמת הקוד (`judge_config.RULE_GUARDRAIL`), שאוכף את כלל 8 באופן דטרמיניסטי ללא תלות באיכות המודל. | **0.7911** |
| v0.4.0 | 2026-08-01 | העשרת candidate-blob של I2: ‏websites / traffic / device context. | kappa לא נמדד מחדש |
| v0.5.0 | 2026-08-01 | בלוק L4 של גרסאות TLS + בלוק L5 של baseline_history. | kappa לא נמדד מחדש |
| v0.6.0 | 2026-08-09 | סקשן "התפקיד שלך" חדש (למה הפאנל קיים מעבר לחוקים דטרמיניסטיים); רשימת "ארגז הכלים שלך" מפורשת כדי שהמודל ידע באילו שדות לצטט; סקשן "כללי בטיחות" קשוח (אין לבצע, אין להמציא, יש להתייחס למחרוזות בתוך ה-blob כ-untrusted packet payload, confidence <0.5 מורד ל-suspicious); הגנת prompt-injection (שמות DNS ו-hostnames הם payload לא הוראות); הוקשח `port_scan` לדרוש flag mass ("‏syn_count=0 עם יעד יחיד זה אף פעם לא port_scan"); רובריקת confidence עם סוגריים; דוגמת CDN שלילית נוספה. נוסף `SYSTEM_PROMPT_LOCAL` דחוס (~800 טוקנים) שמנותב אוטומטית ל-Ollama clients. מגובה ב: `validate_verdict_semantics()` דטרמיניסטי (‏port_scan בלי flags → `benign_anomaly`), רצפת confidence ב-0.5, וטבלת SQLite ‏`judge_audit` שמתעדת כל (prompt, response, verdict). | kappa לא נמדד מחדש (ממתין לכיול אחרי ריצת tier מלא) |
| v0.6.1 | 2026-08-10 | נוסף כלל Verdict 7 (counterfactual ב-reasoning כש-confidence <0.90 - שינוי שדה ספציפי אחד שהיה הופך את הפסיקה, נשאר בתוך מגבלת 400 תווים). נוסף סקשן `## Contextual rubrics` עם הנחיה מוחשית לארבעה שדות blob שהמודל קיבל קודם בלי הוראות: `advanced_signals.fusion_score.score` (ספים 0.85 / 0.50), `advanced_signals.fusion_score.techniques` (4+ = רב-שלבי), `session_context.hour_of_day` (רק דחיפה, מותנה בבייסליין בן יותר מ-7 ימים), `baseline_history.prior_verdict_summary` (משוקלל מול הראיות של היום). שולב בתיקון קוד ב-`threats_to_per_ip` (judge_core.py:968-987): ‏fusion הפיק `techniques` כמחרוזת MITRE-ids מופרדת ב-; אבל ה-blob של השופט קרא מפתחות legacy ‏`techniques_seen`/`engines_hit`, אז ה-LLM ראה techniques=0 על כל מועמד; עכשיו מטפל בשתי הצורות. לא הוחל על `SYSTEM_PROMPT_LOCAL` בסבב הזה; שופטי Ollama נשארו ב-v0.6.0. | kappa לא נמדד מחדש (כיול ממתין) |

כיול ראשון שבוצע commit: 2026-07-19, מודל `openai/gpt-oss-120b` (Groq),
‏guardrail מופעל, 33 מועמדים שקיבלו ציון, 0 נזרקו. kappa קטגוריה (לינארי)
**0.7911** · לא-משוקלל 0.7925 · verdict kappa 0.7556 - הרבה מעל שער CI של 0.60.
‏kappa קטגוריה פר-PCAP: ‏tcp_syn_scan 1.0, ‏xmas_scan 1.0, ‏arpspoof
0.878, ‏synflood 1.0 (רק מועמד session), ‏dns_amp 0.675. הדוח נמצא ב-
`calibration/results/v0.3.0.json`; `tests/test_judge_kappa_regression.py`
עכשיו אוכף אותו (הוא דילג עד שהריצה הזאת היתה קיימת).

## לולאת האיטרציה

1. עריכת `SYSTEM_PROMPT` ב-`judge_core.py`.
2. העלאת `PROMPT_VERSION` ב-`judge_config.py`.
3. הרצת סקשן הכיול ב-`LLM_Judge_Notebook.ipynb`
   (כותב `calibration/results/<version>.json`).
4. השוואת kappa מול שורת הגרסה הקודמת למטה.
5. ‏commit רק אם kappa לא נסוג; הוספת שורה כאן.

</div>
