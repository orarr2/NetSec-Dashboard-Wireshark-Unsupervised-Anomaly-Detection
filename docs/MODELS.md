# המודלים של הפרויקט — הגדרות והסברים

הפרויקט בנוי על **למידה לא-מפוקחת** (אין נתונים מתויגים), ומריץ שלושה מודלים
מובילים במקביל ומצליב ביניהם. כל מודל מכוסה כאן עם קוד ה-Python המדויק
מתוך `Network_Security_Dashboard.ipynb` והסבר על כל פרמטר.

---

## הכנת הנתונים (משותף ל-IsolationForest ול-DBSCAN)

```python
FEATURE_COLS = ["mean_len", "std_len", "count", "burst_score",
                "unique_dsts", "syn_count", "rst_count"]
X_raw  = ip_agg[FEATURE_COLS].fillna(0).values
scaler = StandardScaler()
X      = scaler.fit_transform(X_raw)
```

- **7 פיצ'רים פר-IP**: גודל פקטה ממוצע, סטיית תקן של גודל, מספר פקטות,
  ציון פרצים (burst), יעדים ייחודיים, ספירת SYN, ספירת RST.
- `fillna(0)` — ערכים חסרים הופכים ל-0.
- `StandardScaler` — מנרמל כל פיצ'ר לממוצע 0 וסטיית תקן 1. **קריטי**, כי גם
  IsolationForest וגם DBSCAN רגישים לסקאלה (count בעשרות-אלפים מול std_len קטן).

---

## 1️⃣ IsolationForest — זיהוי אנומליות פר-IP

```python
# בחירת contamination אוטומטית (sensitivity sweep)
best_cont, best_score = 0.10, np.inf
for cont in [0.05, 0.10, 0.15]:
    iso_tmp    = IsolationForest(n_estimators=200, contamination=cont, random_state=42)
    iso_tmp.fit(X)
    flagged    = iso_tmp.decision_function(X)[iso_tmp.predict(X) == -1]
    mean_score = flagged.mean() if len(flagged) else 0
    if mean_score < best_score:
        best_score, best_cont = mean_score, cont

# המודל הסופי
iso = IsolationForest(n_estimators=200, contamination=best_cont, random_state=42)
iso.fit(X)
ip_agg["iso_score"] = iso.decision_function(X)   # ציון רציף
ip_agg["iso_flag"]  = iso.predict(X)             # 1 = רגיל, -1 = אנומליה
ip_agg["anomaly"]   = ip_agg["iso_flag"] == -1
```

**הפרמטרים:**
- `n_estimators=200` — מספר עצי הבידוד ביער. יותר עצים = ציון יציב יותר, על
  חשבון זמן ריצה. 200 הוא איזון סביר.
- `contamination` — אחוז האנומליות המשוער בנתונים. **לא קבוע** — נבחר
  אוטומטית מתוך `[0.05, 0.10, 0.15]`: לכל ערך מודדים את הציון הממוצע של
  ה-IP-ים שסומנו, ובוחרים את הערך שנותן את הציון **הנמוך ביותר** (הכי קיצוני
  סטטיסטית). זה הפרמטר הרגיש ביותר במודל ולכן ה-sweep.
- `random_state=42` — זרע אקראיות קבוע → תוצאות ניתנות לשחזור.
- `decision_function` → ציון אנומליה רציף (שלילי = חריג יותר).
- `predict` → תיוג בינארי: `-1` אנומליה, `1` רגיל.

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
- `min_samples=2` — מינימום שכנים כדי להגדיר אזור צפוף. נמוך בכוונה: מרחב של 7
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
משמשת כ-cross-validation לא-מפוקח. ההערכה מתבססת על Silhouette Score (DBSCAN)
ו-Hopkins statistic (האם בכלל יש מבנה אשכולות בנתונים).
