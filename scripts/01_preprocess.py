"""Clean CIC-IDS2017 flow CSVs. Run from the project root: py scripts/01_preprocess.py

Input : data/raw/*.csv  (one file per capture session, named by weekday)
Output: data/clean/cicids2017_clean.csv   full cleaned data, for modelling
        data/clean/cicids2017_sample.csv  stratified sample, for the EDA charts
        data/clean/cleaning_log.csv
        output/tables/label_by_day.csv
"""
import re
from pathlib import Path

import numpy as np
import pandas as pd

RAW = sorted(Path("data/raw").glob("*.csv"))
CLEAN = Path("data/clean")
TABLES = Path("output/tables")
CLEAN.mkdir(parents=True, exist_ok=True)
TABLES.mkdir(parents=True, exist_ok=True)
if not RAW:
    raise SystemExit("No CSV in data/raw/. Run scripts/00_download.py first.")

SAMPLE_PER_LABEL = 5000
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]

FAMILY = {
    "BENIGN": "Benign",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
    "Bot": "Botnet",
    "Infiltration": "Infiltration",
    "Heartbleed": "Other",
    "FTP-Patator": "Brute force",
    "SSH-Patator": "Brute force",
}


def family(label):
    if label in FAMILY:
        return FAMILY[label]
    if label.startswith("DoS"):
        return "DoS"
    if label.startswith("Web Attack"):
        return "Web attack"
    return "Other"


log = []


def note(step, frame):
    log.append({"step": step, "rows": len(frame), "columns": frame.shape[1]})
    print(f"{step:<45} rows={len(frame):>9,} cols={frame.shape[1]}")


frames = []
for f in RAW:
    part = pd.read_csv(f, encoding="latin-1", low_memory=False)
    part.columns = part.columns.str.strip()
    part["source_file"] = f.name
    part["day"] = next((d for d in DAYS if f.name.lower().startswith(d.lower())), "Unknown")
    frames.append(part)
df = pd.concat(frames, ignore_index=True)
note("raw, all files", df)

# Columns pandas renamed because the header repeats (e.g. "Fwd Header Length.1").
dupes = [c for c in df.columns if re.search(r"\.\d+$", c)]
df = df.drop(columns=dupes)
note(f"drop repeated columns: {dupes}", df)

df = df.dropna(subset=["Label"])
# Some labels carry a mis-encoded dash ("Web Attack <?> Brute Force").
df["Label"] = (
    df["Label"].astype(str).str.replace(r"[^\x20-\x7E]+", "-", regex=True)
    .str.replace(r"\s*-\s*", " - ", regex=True).str.replace(" - Patator", "-Patator").str.strip()
)
df["attack_family"] = df["Label"].map(family)
df["is_attack"] = (df["Label"] != "BENIGN").astype(int)

meta = ["Label", "attack_family", "is_attack", "source_file", "day"]
features = [c for c in df.columns if c not in meta]
df[features] = df[features].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
df = df.dropna(subset=features)
note("drop rows with Inf / NaN / non-numeric features", df)

constant = [c for c in features if df[c].nunique() <= 1]
df = df.drop(columns=constant)
features = [c for c in features if c not in constant]
note(f"drop {len(constant)} constant columns", df)

df = df.drop_duplicates(subset=features + ["Label"])
note("drop duplicate flows", df)

label_by_day = df.groupby(["day", "attack_family", "Label"]).size().reset_index(name="flows")
label_by_day.to_csv(TABLES / "label_by_day.csv", index=False)

sample = df.sample(frac=1, random_state=42).groupby("Label").head(SAMPLE_PER_LABEL)
sample.to_csv(CLEAN / "cicids2017_sample.csv", index=False)
df.to_csv(CLEAN / "cicids2017_clean.csv", index=False)
pd.DataFrame(log).to_csv(CLEAN / "cleaning_log.csv", index=False)
print(label_by_day.to_string(index=False))
