import numpy as np
import pandas as pd

PER_FLOW = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Mean", "Bwd Packet Length Mean",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std",
    "Fwd IAT Mean", "Bwd IAT Mean", "FIN Flag Count", "SYN Flag Count",
    "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward", "Down/Up Ratio",
    "Average Packet Size",
]

WINDOW_FEATURES = [
    "src_flows", "src_unique_dst_ports", "src_unique_dst_ips", "src_syn_ratio",
    "src_auth_flows", "src_packets",
    "dst_flows", "dst_unique_src_ips",
]

FEATURES = PER_FLOW + WINDOW_FEATURES
AUTH_PORTS = [21, 22, 23, 3389]
TRAIN_END = pd.Timestamp("2017-07-06")

def load_features():
    return pd.read_parquet("data/processed/features.parquet")

def split(df):
    train = df[df["Timestamp"] < TRAIN_END]
    test = df[df["Timestamp"] >= TRAIN_END]
    cut = train["Timestamp"].sort_values().iloc[int(0.8 * len(train))]
    fit = train[train["Timestamp"] < cut]
    val = train[train["Timestamp"] >= cut]
    return fit, val, test

RULE_COLS = ["rule_port_scan", "rule_host_flood", "rule_brute_force"]

def apply_rules(d, r):
    d = d.copy()
    d["rule_port_scan"] = ((d["src_unique_dst_ports"] > r["port_scan_ports"]) &
                           (d["src_syn_ratio"] >= 0.5)).astype(int)
    d["rule_host_flood"] = (d["dst_flows"] > r["host_flood_flows"]).astype(int)
    d["rule_brute_force"] = (d["src_auth_flows"] > r["brute_force_auth"]).astype(int)
    d["rule_any"] = d[RULE_COLS].max(axis=1)
    return d

def add_scores(d, clf, iso, th):
    d = d.copy()
    X = d[FEATURES].values
    d["p_clf"] = clf.predict_proba(X)[:, 1]
    raw = -iso.score_samples(X)
    d["p_anom"] = np.clip((raw - th["anomaly_lo"]) /
                          (th["anomaly_hi"] - th["anomaly_lo"]), 0, 1)
    d["is_attack"] = (d["Label"] != "BENIGN").astype(int)
    return d
