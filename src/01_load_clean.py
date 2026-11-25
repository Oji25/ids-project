import glob
import numpy as np
import pandas as pd

RAW_GLOB = "data/raw/TrafficLabelling/*.csv"
OUT = "data/processed/flows.parquet"

def load_raw():
    files=sorted(glob.glob(RAW_GLOB))
    if len(files)!=8:
        raise SystemExit(f"Expected 8 CSVs matching {RAW_GLOB}, found {len(files)}")
    frames = []
    for path in files:
        df = pd.read_csv(path, encoding="latin1", low_memory=False)
        # Column names in this dataset have stray leading or trailing spaces
        df.columns = df.columns.str.strip()
        df["source_file"] = path.split("/")[-1]
        print(f"{path}: {len(df):,} rows, {len(df.columns)} columns")
        frames.append(df)
    return pd.concat(frames, ignore_index=True)

if __name__ == "__main__":
    df = load_raw()

    # Some files contain repeated header rows; remove them
    df["Label"] = df["Label"].astype(str).str.strip()
    df = df[df["Label"] != "Label"]

    # Infinite values appear where a flow has zero duration; treat them as missing
    df = df.replace([np.inf, -np.inf], np.nan)
    before = len(df)
    df = df.dropna()
    print("dropped rows with NaN or inf:", before - len(df))

    before = len(df)
    df = df.drop_duplicates()
    print("dropped exact duplicate rows:", before - len(df))

    # Timestamps are day/month/year in this dataset
    df["Timestamp"] = pd.to_datetime(df["Timestamp"], dayfirst=True, errors="coerce")
    print("unparseable timestamps:", df["Timestamp"].isna().sum())
    df = df.dropna(subset=["Timestamp"])

    print("\nLabel counts:")
    print(df["Label"].value_counts())
    df.to_parquet(OUT, index=False)
    print(f"\nSaved {len(df):,} rows to {OUT}")
