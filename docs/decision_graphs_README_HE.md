<div dir="rtl" align="right">

# NetSec - החלטות ודילמות של הפרויקט

הגרפים שבתיקייה הזו מתעדים את ההחלטות והדילמות שהתעוררו במהלך
הפרויקט, בשני פורמטים של Mermaid ובפורמט נוסף של Graphviz.

| קובץ | פורמט | סגנון |
|------|--------|-------|
| `decisions_pipeline_en.mmd` | Mermaid | צינור מתועד (כמו הצילום המצורף) |
| `decisions_dilemmas_en.mmd` | Mermaid | עץ החלטות (אפשרויות שנדחו מול אלה שנבחרו) |
| `decisions_en.dot` | Graphviz | ‏DAG של ההחלטות |

## איך לרנדר

**‏Mermaid (`.mmd`):**
- להדביק בכתובת <https://mermaid.live> ולקבל תצוגה מיידית.
- GitHub מרנדר אוטומטית בלוקי ```` ```mermaid ```` בקבצי Markdown.
- משורת פקודה: `npx @mermaid-js/mermaid-cli -i decisions_pipeline_en.mmd -o out.png`

**‏Graphviz (`.dot`):**
- `dot -Tpng decisions_en.dot -o decisions_en.png`
- או להדביק בכתובת <https://dreampuf.github.io/GraphvizOnline>

## ההחלטות שתועדו בגרפים

1. למידה מפוקחת מול לא-מפוקחת → לא-מפוקחת (אין תוויות; ‏RF, ‏XGBoost ו-SVM נדחו).
2. מודל יחיד מול אנסמבל → ‏IsolationForest + DBSCAN + LSTM + חוקים דטרמיניסטיים.
3. פרמטר ה-`contamination` של IsolationForest → קבוע על 0.10 (סריקת יציבות הביאה לאותו F1 במחיר של פי-15 אימוני יער, ולכן בוטלה). ראו `docs/TRADEOFFS_EN.md` §7.
4. פרמטר ה-`eps` של DBSCAN → מרפק אוטומטי של k-distance, לכל הקלטה בנפרד (מדידות הדגמה הראו 0.78 ו-4.86 בשתי הקלטות אמיתיות); ה-fallbacks מתועדים ב-`docs/MODEL_DIAGNOSTICS.md`.
5. פרמטר ה-`min_samples` של DBSCAN → 2 (העלאת הערך קורסת את מרחב 10 הממדים להיות כולו רעש).
6. דגימת רצפים ל-LSTM → רציפה (ולא דגימת-צעד).
7. בסיס השוואת שגיאות ה-LSTM → סט ולידציה מופרש (לא סט האימון), עם סימון כש-mean+2σ חרגו.
8. הערכה מול אמת-מידה מתויגת → ה-fixtures של `attack_tests/` + סוויטת רגרסיה.

</div>
