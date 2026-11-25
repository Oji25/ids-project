import pandas as pd
from common import PER_FLOW, WINDOW_FEATURES, AUTH_PORTS

IN = "data/processed/flows.parquet"
OUT = "data/processed/features.parquet"

df = pd.read_parquet(IN)
missing = [c for c in PER_FLOW if c not in df.columns]
assert not missing, f"missing columns: {missing}"

df["bucket"] = df["Timestamp"].dt.floor("60s")
df["has_syn"] = (df["SYN Flag Count"] > 0).astype(int)
df["is_auth"] = df["Destination Port"].isin(AUTH_PORTS).astype(int)
df["pkts"] = df["Total Fwd Packets"] + df["Total Backward Packets"]

src = df.groupby(["Source IP", "bucket"]).agg(
    src_flows=("Flow Duration", "size"),
    src_unique_dst_ports=("Destination Port", "nunique"),
    src_unique_dst_ips=("Destination IP", "nunique"),
    src_syn_ratio=("has_syn", "mean"),
    src_auth_flows=("is_auth", "sum"),
    src_packets=("pkts", "sum"),
).reset_index()

dst = df.groupby(["Destination IP", "bucket"]).agg(
    dst_flows=("Flow Duration", "size"),
    dst_unique_src_ips=("Source IP", "nunique"),
).reset_index()

df = df.merge(src, on=["Source IP", "bucket"], how="left")
df = df.merge(dst, on=["Destination IP", "bucket"], how="left")

keep = PER_FLOW + WINDOW_FEATURES + ["Label", "Timestamp", "Source IP", "Destination IP", "bucket"]
out = df[keep]
out.to_parquet(OUT, index=False)

print(out[PER_FLOW + WINDOW_FEATURES].describe().T[["min", "max", "mean"]].round(2))
print(f"\nSaved {len(out):,} rows to {OUT}")
