"""Download the CIC-IDS2017 flow CSVs from Kaggle into data/raw/.

Run from the project root:  py scripts/00_download.py
Needs: pip install kagglehub  (Kaggle may ask you to log in the first time)
"""
import shutil
from pathlib import Path

import kagglehub

RAW = Path("data/raw")
RAW.mkdir(parents=True, exist_ok=True)

src = Path(kagglehub.dataset_download("chethuhn/network-intrusion-dataset"))
for f in src.rglob("*.csv"):
    shutil.copy2(f, RAW / f.name)
    print("copied", f.name, f"{f.stat().st_size / 1e6:.0f} MB")
