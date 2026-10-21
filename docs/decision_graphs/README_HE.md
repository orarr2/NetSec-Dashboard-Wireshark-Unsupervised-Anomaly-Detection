<div dir="rtl">

# NetSec - החלטות ודילמות של הפרויקט

> גרסה עברית של [`README.md`](README.md).

הגרפים שבתיקייה הזאת מתעדים את ההחלטות והדילמות שהתעוררו במהלך
הפרויקט, בשני פורמטים של Mermaid ובפורמט אחד של Graphviz.

| קובץ | פורמט | סגנון |
|------|--------|-------|
| `decisions_pipeline_en.mmd` | Mermaid | צינור מתועד (כמו הצילום המצורף) |
| `decisions_dilemmas_en.mmd` | Mermaid | עץ החלטות (אפשרויות שנדחו מול אלה שנבחרו) |
| `decisions_en.dot` | Graphviz | DAG של ההחלטות |

## איך לרנדר

**Mermaid (‏`.mmd`):**
- מדביקים בכתובת <https://mermaid.live> ומקבלים תצוגה מיידית.
- GitHub מרנדר אוטומטית בלוקים מסוג ```` ```mermaid ````.
- דרך CLI: ‏`npx @mermaid-js/mermaid-cli -i decisions_pipeline_en.mmd -o out.png`

**Graphviz (‏`.dot`):**
- `dot -Tpng decisions_en.dot -o decisions_en.png`
- או מדביקים בכתובת <https://dreampuf.github.io/GraphvizOnline>

## ההחלטות שנתפסו בגרפים

1. למידה מפוקחת מול לא-מפוקחת → לא-מפוקחת (אין תוויות; ‏RF/XGBoost/SVM נדחו).
2. מודל יחיד מול אנסמבל → ‏IsolationForest + DBSCAN + LSTM + חוקים דטרמיניסטיים.
3. ‏`contamination` של IsolationForest → קבוע 0.10 (סריקת יציבות-seed התאימה לקבוע 0.10 ב-F1 במחיר של פי-15 fits; לכן נגרסה). ראו `docs/TRADEOFFS_EN.md` §7.
4. ‏`eps` של DBSCAN → מרפק אוטומטי של k-distance, פר-הקלטה (מדידות להמחשה הראו 0.78 ו-4.86 בשתי הקלטות אמיתיות); ה-fallbacks מתועדים ב-`docs/MODEL_DIAGNOSTICS.md`.
5. ‏`min_samples` של DBSCAN → 2 (העלאת הערך קורסת את מרחב ה-10 ממדים ל-noise).
6. דגימת רצפים ל-LSTM → רציפה (לא step-sampling).
7. בייסליין שגיאות ה-LSTM → ‏validation-set מופרש (לא training), דגל כש-mean+2σ חרגו.
8. הערכה מול ground truth מתויג → fixtures של `attack_tests/` + סוויטת רגרסיה.

</div>
