import json
import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.metrics import confusion_matrix, roc_auc_score
from common import FEATURES, load_features, split

df = load_features()
fit, val, test = split(df)

def y_of(d):
    return (d["Label"] != "BENIGN").astype(int).values

print("fit rows:", len(fit), " val rows:", len(val), " test rows:", len(test))

clf = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.1,
                                     early_stopping=True, random_state=0)
clf.fit(fit[FEATURES].values, y_of(fit))

iso = IsolationForest(n_estimators=200, random_state=0, n_jobs=-1)
iso.fit(fit[FEATURES].values[y_of(fit) == 0])

def raw_anomaly(X):
    return -iso.score_samples(X)

v_raw = raw_anomaly(val[FEATURES].values)
lo, hi = np.percentile(v_raw[y_of(val) == 0], [1, 99.9])

def anomaly_norm(X):
    return np.clip((raw_anomaly(X) - lo) / (hi - lo), 0, 1)

v_p = clf.predict_proba(val[FEATURES].values)[:, 1]
v_a = anomaly_norm(val[FEATURES].values)
th = {
    "clf_threshold": float(np.quantile(v_p[y_of(val) == 0], 0.99)),
    "anomaly_lo": float(lo),
    "anomaly_hi": float(hi),
    "anomaly_threshold": float(np.quantile(v_a[y_of(val) == 0], 0.99)),
}
print("thresholds:", th)

X_te, y_te = test[FEATURES].values, y_of(test)
p_te = clf.predict_proba(X_te)[:, 1]
a_te = anomaly_norm(X_te)

def report(name, y_true, score, thr):
    pred = (score >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    print(f"{name:11s} precision={tp/max(tp+fp,1):.3f}  recall={tp/max(tp+fn,1):.3f}  "
          f"false_alarm_rate={fp/max(fp+tn,1):.4f}  roc_auc={roc_auc_score(y_true, score):.3f}")
    return pred

print("\nFlow-level results on held-out Thursday and Friday:")
pred_clf = report("classifier", y_te, p_te, th["clf_threshold"])
pred_anom = report("anomaly", y_te, a_te, th["anomaly_threshold"])

t = test.assign(clf_flag=pred_clf, anom_flag=pred_anom)
print("\nDetection rate per label:")
print(t.groupby("Label")[["clf_flag", "anom_flag"]].mean().round(3))
print("\nFlows per label in test:")
print(t["Label"].value_counts())

joblib.dump(clf, "models/clf.joblib")
joblib.dump(iso, "models/iso.joblib")
json.dump(th, open("models/thresholds.json", "w"), indent=2)
print("\nSaved models and thresholds to models/")

