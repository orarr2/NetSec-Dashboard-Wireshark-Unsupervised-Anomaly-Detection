# המודלים של הפרויקט - הגדרות והסברים

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
- `fillna(0)` - ערכים חסרים הופכים ל-0.
- `StandardScaler` - מנרמל כל פיצ'ר לממוצע 0 וסטיית תקן 1. **קריטי**, כי גם
  IsolationForest וגם DBSCAN רגישים לסקאלה (count בעשרות-אלפים מול std_len קטן).

---

## 1️⃣ IsolationForest - זיהוי אנומליות פר-IP

```python
# contamination=0.10 קבוע. גרסה קודמת סרקה [0.05, 0.10, 0.15] עם 5 זרעים
# ובחרה את הערך היציב ביותר (Jaccard); מדדנו על 5 קבצי ה-ground-truth
# שממוצע F1 = 0.247 (סריקה) לעומת 0.250 (fixed=0.10) - סריקה מעולם לא
# עברה את הבחירה הקבועה, והיא ביצעה 15 fits לפגישה. במקום זה: fit יחיד
# עם contamination=0.10, ועמודת iso_stability נשארת ל-backward compatibility.
CONTAMINATION = 0.10
iso = IsolationForest(n_estimators=200, contamination=CONTAMINATION,
                      random_state=42)
iso.fit(X)
ip_agg["iso_score"]     = iso.decision_function(X)  # ציון רציף (שלילי = חריג)
ip_agg["iso_flag"]      = iso.predict(X)            # -1 חריג / +1 תקין
ip_agg["anomaly"]       = ip_agg["iso_flag"] == -1
ip_agg["iso_stability"] = ip_agg["anomaly"].astype(float)  # compat
```

**הפרמטרים:**
- `n_estimators=200` - מספר עצי הבידוד ביער. יותר עצים = ציון יציב יותר, על
  חשבון זמן ריצה. 200 הוא איזון סביר.
- `contamination=0.10` - אחוז האנומליות המשוער בנתונים. בעבר היה
  seed-stability sweep על `[0.05, 0.10, 0.15]` × 5 seeds; מדידה כמותית
  מול ה-ground-truth של `attack_tests/` הראתה שהקבוע 0.10 נותן את אותו
  F1 (0.250 מול 0.247), פי-15 מהיר יותר לכל הרצה. הנימוק המלא ב-
  `docs/TRADEOFFS_EN.md` §7 - הצ'ארט "Contamination Sensitivity" ממחיש
  את היחס בין ערכים שונים ומסמן את 0.10 בקו אנכי, אבל **הפרודקשן משתמש
  ב-0.10 בלבד**.
- `random_state=42` - זרע קבוע → ציוני `iso_score` ניתנים לשחזור.
- `decision_function` → ציון אנומליה רציף (שלילי = חריג יותר).
- `iso_stability` → עמודת תאימות (1.0 לחריג, 0.0 אחרת) לשמירת ריצת מסכים ישנים.

---

## 2️⃣ DBSCAN - אשכול לפי צפיפות

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
- `eps` - רדיוס השכונה. **לא קבוע** - נגזר אוטומטית מנקודת ה"מרפק" של גרף
  ה-k-distance (הנגזרת השנייה המינימלית), מעוגל ל-2 ספרות. אם יש פחות מ-4
  נקודות → fallback ל-`1.3`. זה הפרמטר הקריטי ב-DBSCAN ולכן הוא מחושב מהנתונים
  ולא מנוחש.
- `min_samples=2` - מינימום שכנים כדי להגדיר אזור צפוף. נמוך בכוונה: מרחב של 10
  ממדים ודאטה קטן (~50-150 IP) - דרישה ל-3+ שכנים הייתה הופכת כמעט הכל ל-noise.
- `metric` - ברירת מחדל `euclidean`.
- `fit_predict` → תווית אשכול לכל IP. תווית **`-1`** = נקודה בודדת ללא שכנים
  התנהגותיים = סימן אנומליה חזק.

**עזר:** `NearestNeighbors(n_neighbors=2)` משמש רק לחישוב גרף ה-k-distance
לבחירת `eps`, לא לאשכול עצמו.

---

## 3️⃣ LSTM (PyTorch) - זיהוי אנומליה זמנית

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
- `input_size=1` - משתנה קלט בודד: גודל פקטה ממוצע ב-bin של שנייה.
  שניות ללא תעבורה **ממולאות באפס** (ולא נמחקות) - שקט הוא תצפית אמיתית,
  ומחיקתו הייתה "מדביקה" פערים ומסתירה מהמודל מעברי שקט→פרץ.
- `hidden_size=64` - מספר היחידות הנסתרות ב-LSTM. קובע את קיבולת המודל.
- `nn.LSTM(..., batch_first=True)` - צורת הטנזור היא `(batch, seq, features)`.
- `nn.Linear(hidden_size, 1)` - שכבה מלאה שממירה את הפלט הנסתר לחיזוי יחיד.
- `out[:, -1, :]` - לוקחים רק את הצעד האחרון ברצף לחיזוי הערך הבא.
- `Adam(lr=0.001)` - אופטימייזר עם קצב למידה 0.001.
- `MSELoss` - שגיאה ריבועית ממוצעת (בעיית רגרסיה/חיזוי).
- `batch_size=512`, `shuffle=True` - אצוות גדולות, ערבוב בכל epoch.
- `MAX_EPOCHS=15`, `PATIENCE=2` - **early stopping**: עוצרים אם ה-val loss לא
  השתפר 2 epochs ברצף, ומשחזרים את המשקלים הטובים ביותר. מונע overfitting.
- **קלט נוסף:** `SEQ_LEN=10` (אורך הרצף), `MAX_BINS=20000` (subsampling).

**זיהוי האנומליה:** רצפי-שנייה מסומנים כשגיאת החיזוי חורגת מ-`val_mean + 2σ`
(‏שווה בפועל ל-`quantile_0.95` - בהנחת התפלגות נורמלית של השגיאות).

**⚠ מגבלה של LSTM - לתעבורה של דקה+ בלבד:** ‏SEQ_LEN=10 דורש
לפחות 20 סלי-זמן של **שניות רצף (‏zero-filled - כולל שניות ללא תעבורה)**
כדי להתאמן; קבצי בסיס קצרים (‏‏‏tcp_syn_scan/xmas_scan/dns_amp - ‏~1-2
שניות בסה"כ) **לא** יריצו LSTM. זה נורמלי, לא באג - הכללים
הדטרמיניסטיים מטפלים בסריקות רועשות. בדיוק: הבינינג הוא לפי `t1-t0`
של הקובץ בשניות שלמות, ואם הבינים המתקבלים < 20 - `train_lstm_for_session`
מדלג בשקט (הודעה ל-stdout, אין flag).

---

## תפקיד כל שכבה - מה תופס מה בפועל

מדידה כמותית מול ה-ground-truth מראה שהשכבות **אינן שוות בכיסוי**:

| PCAP | IF | DBSCAN | Rules | Fusion |
|---|:-:|:-:|:-:|:-:|
| tcp_syn_scan | ✓ | ✓ | ✓ | ✗ |
| xmas_scan | ✗ | ✓ | ✓ | ✗ |
| arpspoof | ✗ | ✓ | ✓ | ✓ |
| dns_amp | חלקי | ✗ | ✓ | ✗ |
| synflood | ✗ | דילוג (>5000 IPs) | ✓ (flood aggregate) | ✗ |

- **Rules (סריקות SYN/XMAS/DNS-amp/‏ARP-multi-MAC)**: workhorse - ‏recall=1.0
  על כל 4 המקרים המתויגים. אם מוסיפים תקיפות דומות, ‏rules ילכדו.
- **IsolationForest / DBSCAN**: זיהוי outliers פר-IP. ‏DBSCAN "מתפוצץ" על
  תעבורה מזויפת עם >5,000 IPs (‏cap פנימי → cluster=-1 לכל).
- **LSTM**: אנומליות זמניות ב-**תעבורה של דקות+** בלבד. לא רלוונטי לקצר.
- **Fusion (על 5 המנועים המתקדמים)**: מכוון ל-**APT stealth** - beaconing,
  DNS tunneling, ‏DGA, ‏TLS anomaly, ‏ARP MITM. ‏Recall=0 על סריקות רועשות
  לפי דיזיין. לא באג, לא top-level threat score על כל תעבורה - הוא
  מתמחה בתת-קבוצה של תקיפות.

התוצאה: אין מודל יחיד שהוא "top-level" - כל אחד תופס את מקומו. ‏IF/DBSCAN/LSTM
נשארים לזיהוי outliers/זמניים, ‏Rules הם רשת ביטחון על סריקות מוכרות, ו-fusion
הוא הזרוע הייעודית ל-APT.
