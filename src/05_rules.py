import json
import numpy as np
from common import split, load_features, apply_rules

df = load_features()
fit, val, test = split(df)
benign = val[val["Label"] == "BENIGN"]

rules = {
    "port_scan_ports": float(max(20, np.quantile(benign["src_unique_dst_ports"], 0.999))),
    "host_flood_flows": float(max(50, np.quantile(benign["dst_flows"], 0.999))),
    "brute_force_auth": float(max(10, np.quantile(benign["src_auth_flows"], 0.999))),
}
print("rule thresholds:", rules)
json.dump(rules, open("models/rules.json", "w"), indent=2)

t = apply_rules(test, rules)
cols = ["rule_port_scan", "rule_host_flood", "rule_brute_force", "rule_any"]
print("\nRule firing rate per label on test (BENIGN row = false alarm rate):")
print(t.groupby("Label")[cols].mean().round(3))
