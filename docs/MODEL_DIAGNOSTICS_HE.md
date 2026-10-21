<div dir="rtl" align="right">

# דיאגנוסטיקת מודלים

> גרסה עברית של [`MODEL_DIAGNOSTICS.md`](MODEL_DIAGNOSTICS.md).

ערכים פר-session ששלושת המודלים הלא-מפוקחים מייצרים. אלה המספרים
שמוצגים בלשוניות Analysis Insights ומאוחסנים במילון ה-session
לבחינה מאוחרת (‏`ip_agg.attrs`).

## מה קבוע ומה מסתגל

| מודל | שדה | ערך / איך נבחר |
|---|---|---|
| IsolationForest | `contamination` | **קבוע ב-0.10** (`n_estimators=200`, ‏`random_state=42`). סריקת יציבות-seed קודמת על `[0.05, 0.10, 0.15]` × 5 seeds מול ground truth מתויג התאימה ל-F1 של 0.10 הקבוע (0.250 מול 0.247) במחיר של פי-15 fits של היער, אז הסריקה נגרסה. ראו `docs/TRADEOFFS_EN.md`. |
| IsolationForest | `#anomalies / #IPs` | ספירה היכן ש-`predict() == -1` על מטריצת הפיצ'רים הפר-IP |
| DBSCAN | `eps` | מרפק k-distance (‏k=2) במינימום של הנגזרת השנייה. ‏Fallbacks: ‏`1.3` כשיש פחות מ-4 IPs, ו-`max(mean(k_dist), 0.05)` כשהמרפק קורס ל-0 (הצפות עם מקור מזויף). |
| DBSCAN | `min_samples` | קבוע ב-2 |
| DBSCAN | `clusters / noise` | ספירת תוויות non-noise / ספירת תוויות `-1` |
| DBSCAN | `silhouette` | silhouette על נקודות non-noise כשיש ≥ 2 אשכולות, אחרת `n/a` |
| DBSCAN | `>5000 IPs` | **מדלג לגמרי** (כל `cluster = -1`) כדי להימנע מהתפוצצות ה-O(n²) של השכונה שנראתה בהצפות מזויפות |
| LSTM | `threshold` | `val_mean + 2·val_std` של שגיאת החיזוי פר-רצף על ה-split של ה-validation המופרש |
| LSTM | `#flagged / #sequences` | רצפים ששגיאתם חרגה מהסף |
| LSTM | שער אימון | דורש ≥ 20 מקבצי-שנייה שמישים (‏SEQ_LEN=10 מותיר 10 חלונות גולשים). הקלטות קצרות יותר מדלגות על LSTM בשקט; החוקים הדטרמיניסטיים מכסים אותן. |

## מטריצת הפיצ'רים

‏IsolationForest ו-DBSCAN חולקים מטריצת פיצ'רים פר-IP בת 10 עמודות
(מנורמלת ב-`StandardScaler`):

```
mean_len, std_len, count, burst_score, unique_dsts,
syn_count, rst_count, fin_count, null_count, xmas_count
```

‏LSTM רץ על אות זמני נפרד: גודל פקטה ממוצע פר-מקבץ של שנייה
(מולא באפסים לשניות סרק), מורצף ומקבל ציון לפי שגיאת חיזוי.
שניות שעון-קיר - לא "שניות עם תעבורה" - וזה מה שגורם לפערי סרק
ארוכים להופיע כפרצים חריגים בשני הצדדים.

## Attrs מאוחסנים ב-`ip_agg`

נקבעים על ידי `run_ml_on_session`, זמינים ב-`S['ip_agg'].attrs` עבור
תצוגת Model Diagnostics של הדשבורד:

```
_chosen_contamination   0.10 היום (קבוע)
_eps_auto               eps נבחר (מרפק / fallback / רצפה)
_min_samples            2
_silhouette             float או None
_n_clusters             int
_n_noise                int
```

## צ'ארט רגישות ל-contamination

הצ'ארט `sensitivity_sweep` של הדשבורד עדיין מתאים 20 מודלי
IsolationForest לאורך `contamination = 0.02 .. 0.30` ומצייר קו אנכי
על הערך שבפועל בשימוש (`0.10`). זהו ויזואליזציה של ה-tradeoff,
לא בורר - המודל בפרודקשן תמיד משתמש ב-0.10.

</div>
