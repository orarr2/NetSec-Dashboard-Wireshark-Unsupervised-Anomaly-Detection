# המודלים של הפרויקט — הגדרות והסברים

הפרויקט בנוי על **למידה לא-מפוקחת** (אין נתונים מתויגים), ומריץ שלושה מודלים
מובילים במקביל ומצליב ביניהם. כל מודל מכוסה כאן עם קוד ה-Python המדויק
מתוך `Network_Security_Dashboard.ipynb` והסבר על כל פרמטר.

---

## הכנת הנתונים (משותף ל-IsolationForest ול-DBSCAN)

```python
FEATURE_COLS = ["mean_len", "std_len", "count", "burst_score",
                "unique_dsts", "syn_count", "rst_count",
                "fin_count", "null_count", "xmas_count"]
X_raw  = ip_agg[FEATURE_COLS].fillna(0).values
scaler = StandardScaler()
X      = scaler.fit_transform(X_raw)
```

- **10 פיצ'רים פר-IP**: גודל פקטה ממוצע, סטיית תקן של גודל, מספר פקטות,
  ציון פרצים (burst), יעדים ייחודיים, ספירת SYN, ספירת RST, וספירות
  סריקות-חמקניות: FIN-only, NULL, Xmas.
- `fillna(0)` — ערכים חסרים הופכים ל-0.
- `StandardScaler` — מנרמל כל פיצ'ר לממוצע 0 וסטיית תקן 1. **קריטי**, כי גם
  IsolationForest וגם DBSCAN רגישים לסקאלה (count בעשרות-אלפים מול std_len קטן).

---

## 1️⃣ IsolationForest — זיהוי אנומליות פר-IP

```python
# בחירת contamination לפי יציבות-בין-זרעים (seed stability):
# contamination לא משנה את העצים אלא רק את סף הסימון, ולכן השוואת ציונים
# עם זרע קבוע חסרת משמעות. במקום זה: לכל ערך מאמנים כמה יערות עם זרעים
# שונים, מודדים כמה קבוצת המסומנים יציבה בין הזרעים (Jaccard ממוצע בין
# זוגות), ובוחרים את הערך היציב ביותר. תיקו → הערך הקטן יותר.
STABILITY_SEEDS = [7, 17, 42, 99, 123]   # (3 זרעים בלבד מעל 20k IP)
for cont in [0.05, 0.10, 0.15]:
    flag_sets = [frozenset(np.where(
        IsolationForest(n_estimators=100, contamination=cont,
                        random_state=seed).fit(X).predict(X) == -1)[0])
        for seed in STABILITY_SEEDS]
    # stability = ממוצע Jaccard בין כל זוגות ה-flag_sets; votes = הצבעת רוב

# המודל הסופי
iso = IsolationForest(n_estimators=200, contamination=best_cont, random_state=42)
iso.fit(X)
ip_agg["iso_score"]     = iso.decision_function(X)  # ציון רציף
ip_agg["iso_stability"] = votes / n_seeds           # שיעור הזרעים שסימנו את ה-IP
ip_agg["anomaly"]       = ip_agg["iso_stability"] >= 0.5   # הצבעת רוב
```

**הפרמטרים:**
- `n_estimators=200` — מספר עצי הבידוד ביער. יותר עצים = ציון יציב יותר, על
  חשבון זמן ריצה. 200 הוא איזון סביר (100 בריצות ה-sweep, לחיסכון).
- `contamination` — אחוז האנומליות המשוער בנתונים. **לא קבוע** — נבחר
  אוטומטית מתוך `[0.05, 0.10, 0.15]` לפי **יציבות בין זרעים**: מאמנים
  מספר יערות עם זרעים שונים לכל ערך ובוחרים את הערך שקבוצת המסומנים שלו
  הכי עקבית (Jaccard ממוצע). IP נחשב אנומליה רק אם **רוב** הזרעים סימנו
  אותו — הצבעה שעמידה בהרבה לרעש של יער בודד.
- `random_state=42` — זרע קבוע למודל הסופי → ציוני `iso_score` ניתנים לשחזור.
- `decision_function` → ציון אנומליה רציף (שלילי = חריג יותר).
- `iso_stability` → שיעור הזרעים שהסכימו שה-IP חריג (0–1).

---

## 2️⃣ DBSCAN — אשכול לפי צפיפות

```python
# בחירת eps אוטומטית מ-"מרפק" של גרף k-distance
k = 2
nbrs = NearestNeighbors(n_neighbors=k).fit(X)
distances, _ = nbrs.kneighbors(X)
k_dist = np.sort(distances[:, k-1])[::-1]
if len(k_dist) >= 4:
    d1 = np.diff(k_dist)
    d2 = np.diff(d1)
    elbow_idx = int(np.argmin(d2)) + 1
    eps_auto  = float(round(k_dist[elbow_idx], 2))
else:
    eps_auto = 1.3

dbscan = DBSCAN(eps=eps_auto, min_samples=2)
ip_agg["cluster"] = dbscan.fit_predict(X)        # -1 = noise (אנומליה)
```

**הפרמטרים:**
- `eps` — רדיוס השכונה. **לא קבוע** — נגזר אוטומטית מנקודת ה"מרפק" של גרף
  ה-k-distance (הנגזרת השנייה המינימלית), מעוגל ל-2 ספרות. אם יש פחות מ-4
  נקודות → fallback ל-`1.3`. זה הפרמטר הקריטי ב-DBSCAN ולכן הוא מחושב מהנתונים
  ולא מנוחש.
- `min_samples=2` — מינימום שכנים כדי להגדיר אזור צפוף. נמוך בכוונה: מרחב של 10
  ממדים ודאטה קטן (~50–150 IP) — דרישה ל-3+ שכנים הייתה הופכת כמעט הכל ל-noise.
- `metric` — ברירת מחדל `euclidean`.
- `fit_predict` → תווית אשכול לכל IP. תווית **`-1`** = נקודה בודדת ללא שכנים
  התנהגותיים = סימן אנומליה חזק.

**עזר:** `NearestNeighbors(n_neighbors=2)` משמש רק לחישוב גרף ה-k-distance
לבחירת `eps`, לא לאשכול עצמו.

---

## 3️⃣ LSTM (PyTorch) — זיהוי אנומליה זמנית

```python
class LSTMModel(nn.Module):
    def __init__(self, input_size=1, hidden_size=64):
        super().__init__()
        self.lstm = nn.LSTM(input_size, hidden_size, batch_first=True)
        self.fc   = nn.Linear(hidden_size, 1)
    def forward(self, x):
        out, _ = self.lstm(x)
        return self.fc(out[:, -1, :])           # החיזוי מהצעד האחרון ברצף

m   = LSTMModel()
opt = torch.optim.Adam(m.parameters(), lr=0.001)
crit = nn.MSELoss()
loader = DataLoader(TensorDataset(Xt_tr, yt_tr), batch_size=512, shuffle=True)

MAX_EPOCHS, PATIENCE = 15, 2
# לולאת אימון עם early stopping לפי val loss; שומר את המשקלים הטובים ביותר
```

**הפרמטרים:**
- `input_size=1` — משתנה קלט בודד: גודל פקטה ממוצע ב-bin של שנייה.
  שניות ללא תעבורה **ממולאות באפס** (ולא נמחקות) — שקט הוא תצפית אמיתית,
  ומחיקתו הייתה "מדביקה" פערים ומסתירה מהמודל מעברי שקט→פרץ.
- `hidden_size=64` — מספר היחידות הנסתרות ב-LSTM. קובע את קיבולת המודל.
- `nn.LSTM(..., batch_first=True)` — צורת הטנזור היא `(batch, seq, features)`.
- `nn.Linear(hidden_size, 1)` — שכבה מלאה שממירה את הפלט הנסתר לחיזוי יחיד.
- `out[:, -1, :]` — לוקחים רק את הצעד האחרון ברצף לחיזוי הערך הבא.
- `Adam(lr=0.001)` — אופטימייזר עם קצב למידה 0.001.
- `MSELoss` — שגיאה ריבועית ממוצעת (בעיית רגרסיה/חיזוי).
- `batch_size=512`, `shuffle=True` — אצוות גדולות, ערבוב בכל epoch.
- `MAX_EPOCHS=15`, `PATIENCE=2` — **early stopping**: עוצרים אם ה-val loss לא
  השתפר 2 epochs ברצף, ומשחזרים את המשקלים הטובים ביותר. מונע overfitting.
- **קלט נוסף:** `SEQ_LEN=10` (אורך הרצף), `MAX_BINS=20000` (subsampling).

**זיהוי האנומליה:** IP/שנייה מסומנים כשגיאת החיזוי חורגת מ-`val_mean + 2σ`.

---

## למה שילוב של שלושה מודלים?

| מודל | תופס | סוג פלט |
|------|------|---------|
| IsolationForest | outliers גלובליים (פר-IP) | ציון רציף |
| DBSCAN | outliers מקומיים מבוססי-צפיפות | תווית בינארית (-1 / אשכול) |
| LSTM | אנומליות זמניות / רצפיות | שגיאת חיזוי |

כל מודל מכסה חולשה של האחרים, וההסכמה ביניהם ("Model Agreement Matrix")
משמשת כ-cross-validation לא-מפוקח. ההערכה מתבססת על Silhouette Score
(DBSCAN) ועל יציבות-בין-זרעים של IsolationForest, ובנוסף — מאז הוספת
`attack_tests/ground_truth.json` — על precision/recall אמיתיים מול חמשת
ה-PCAP המתויגים (ראו `attack_tests/evaluate.py` ו-`tests/`).
