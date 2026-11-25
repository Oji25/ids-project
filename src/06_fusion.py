import ipaddress
import json
import numpy as np
import joblib
from common import load_features, split, apply_rules, add_scores

df = load_features()
fit, val, test = split(df)
clf = joblib.load("models/clf.joblib")
iso = joblib.load("models/iso.joblib")
th = json.load(open("models/thresholds.json"))
rules = json.load(open("models/rules.json"))

def score_all(d):
    return add_scores(apply_rules(d, rules), clf, iso, th)

def to_windows(d):
    return d.groupby(["Source IP", "bucket"]).agg(
        clf=("p_clf", "mean"),
        anom=("p_anom", "mean"),
        rule_port_scan=("rule_port_scan", "max"),
        rule_host_flood=("rule_host_flood", "max"),
        rule_brute_force=("rule_brute_force", "max"),
        rule_any=("rule_any", "max"),
        attack=("is_attack", "max"),
        flows=("src_flows", "first"),
        uports=("src_unique_dst_ports", "first"),
        udsts=("src_unique_dst_ips", "first"),
        syn=("src_syn_ratio", "first"),
        pkts=("src_packets", "first"),
    ).reset_index()

vw = to_windows(score_all(val))
tw = to_windows(score_all(test))

best = None
attack_mask = vw["attack"].values == 1
for wc in np.arange(0, 1.01, 0.1):
    for wa in np.arange(0, 1.01, 0.1):
        wr =round(1-wc-wa,2)
        if wr < -1e-9:
            continue
        wr = max(0.0, wr)
        f = wc * vw["clf"] + wa * vw["anom"].values + wr * vw["rule_any"].values
        thr= np.quantile(f[~attack_mask], 0.99)
        flagged=f>thr
        fa=flagged[~attack_mask].mean()
        recall = flagged[attack_mask].mean() if attack_mask.any() else0.0
        if fa<=0.01 and (best is None or recall > best[0]):
            best = (recall, round(wc, 1), round(wa, 1), wr, thr)

if best is None:
    raise SystemExit("No fusion weights keep benign false alarms at or below 1%. Recalibrate the rules in 05_rules.py")

_, wc, wa, wr, thr_high = best
f_val = wc * vw["clf"] + wa * vw["anom"] + wr * vw["rule_any"]
thr_low = float(np.quantile(f_val[vw["attack"] == 0], 0.95))
thr_high = float(thr_high)
print(f"thresholds: suspicious>={thr_low:.3f}  intrusion likely>={thr_high:.3f}")

f_te = wc * tw["clf"] + wa * tw["anom"] + wr * tw["rule_any"]
tw["fused"] = f_te
tw["verdict"] = np.where(f_te >= thr_high, "intrusion likely",
                 np.where(f_te >= thr_low, "suspicious", "normal"))

alarm = (tw["verdict"] == "intrusion likely").values
attack = tw["attack"].values == 1
tp = (alarm & attack).sum(); fp = (alarm & ~attack).sum()
fn = (~alarm & attack).sum(); tn = (~alarm & ~attack).sum()
hours = (test["Timestamp"].max() - test["Timestamp"].min()).total_seconds() / 3600
print("\nWindow-level results on test (intrusion likely only):")
print(f"precision={tp/max(tp+fp,1):.3f}  recall={tp/max(tp+fn,1):.3f}  "
      f"false_alarm_rate={fp/max(fp+tn,1):.4f}")
print(f"false alarms per hour (whole network): {fp/hours:.2f}")
print(f"test span: {hours:.1f} hours")

flag = tw[tw["verdict"] != "normal"].sort_values("fused", ascending=False).head(300)
sub = test.set_index(["Source IP", "bucket"])
sub = sub[sub.index.isin(flag.set_index(["Source IP", "bucket"]).index)].reset_index()
top_ports = sub.groupby(["Source IP", "bucket"])["Destination Port"].agg(
    lambda s: [int(p) for p in s.value_counts().head(5).index])

names = {"rule_port_scan": "possible port scan",
         "rule_host_flood": "possible flood toward a host",
         "rule_brute_force": "repeated logins to a remote service"}

def alert_type(row):
    hits = [v for k, v in names.items() if row[k] == 1]
    return hits[0] if hits else "unusual traffic pattern (model-detected)"

pseudo = {ip: f"device-{i+1:02d}" for i, ip in enumerate(sorted(flag["Source IP"].unique()))}

def is_internal(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

with open("results/evidence.jsonl", "w") as out:
    for _, row in flag.iterrows():
        ev = {
            "window_seconds": 60,
            "verdict": row["verdict"],
            "alert_type": alert_type(row),
            "classifier_score": round(float(row["clf"]), 2),
            "anomaly_score": round(float(row["anom"]), 2),
            "source_device": pseudo[row["Source IP"]],
            "source_is_internal": is_internal(row["Source IP"]),
            "flows_in_window": int(row["flows"]),
            "unique_destination_ports": int(row["uports"]),
            "unique_destination_ips": int(row["udsts"]),
            "syn_packet_ratio": round(float(row["syn"]), 2),
            "packets_per_second": round(float(row["pkts"]) / 60, 1),
            "top_destination_ports": top_ports.get((row["Source IP"], row["bucket"]), []),
        }
        out.write(json.dumps(ev) + "\n")

print(f"\nWrote {len(flag)} evidence records to results/evidence.jsonl")
if len(flag):
    print(open("results/evidence.jsonl").readline())
