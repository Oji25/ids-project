import pandas as pd

df = pd.read_parquet("data/processed/flows.parquet")

print("Columns:", len(df.columns))
print("Time range:", df["Timestamp"].min(), "to", df["Timestamp"].max())

print("\nFlow Duration (microseconds, max should be near 120,000,000):")
print(df["Flow Duration"].describe().round(1))

print("\nFlow IAT Mean (microseconds):")
print(df["Flow IAT Mean"].describe().round(1))

print("\nFlow Bytes/s:")
print(df["Flow Bytes/s"].describe().round(1))

print("\nFlag columns:", [c for c in df.columns if "Flag Count" in c])
print("\nSample Source IPs:", df["Source IP"].unique()[:5])
