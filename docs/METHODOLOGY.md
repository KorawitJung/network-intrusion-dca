# Methodology

## Objective
Answer four plain questions about attacks in network traffic:

1. How much of the traffic is an attack, and which attack type is most common?
2. What does attack traffic look like next to normal traffic?
3. Can a model tell attacks from normal traffic?
4. Can it catch attack types it has never seen before?

## Data source
CIC-IDS2017, Canadian Institute for Cybersecurity, University of New Brunswick (Sharafaldin, Lashkari and Ghorbani, 2018).
Five days of traffic captured in a testbed, 3-7 July 2017, converted to flow records with CICFlowMeter (about 80 features per flow).
Downloaded from the Kaggle mirror `chethuhn/network-intrusion-dataset`; the original is at unb.ca. See `data/reference/sources.csv`.

## Data collection
`scripts/00_download.py` downloads the eight CSV files with `kagglehub` into `data/raw/`. Raw files are not committed.

## Data cleaning (`scripts/01_preprocess.py`)
Each step and its row and column count is written to `data/clean/cleaning_log.csv`.

| Step | Rule |
|---|---|
| Headers | Strip leading spaces from column names |
| Provenance | Add `source_file` and `day` (from the file name) |
| Repeated columns | Drop columns whose header repeats (e.g. `Fwd Header Length.1`) |
| Labels | Replace mis-encoded characters in labels; map labels to attack families; add `is_attack` |
| Invalid values | Coerce features to numeric; drop rows with Inf or NaN (mostly `Flow Bytes/s`, `Flow Packets/s`) |
| Constant columns | Drop features with a single value |
| Duplicates | Drop flows identical on all features and label |
| EDA sample | Up to 5,000 flows per label, written to `cicids2017_sample.csv` |

Result on the full download: 2,830,743 raw flows; 2,867 dropped for Inf/NaN; 8 constant columns dropped; 307,078 duplicate flows dropped (10.9%); 2,520,798 flows and 69 features remain.

## Analysis
All in Python (pandas, matplotlib, scikit-learn).

| Question | Method |
|---|---|
| Q1 | Flow counts and share of all flows per attack family, on the full cleaned data; attack flows per capture day |
| Q2 | Box plots of four readable features (flow duration, forward packets, bytes per second, mean packet length) per attack family, on the stratified sample |
| Q3 | Random forest (100 trees, balanced class weights, at most 500,000 training rows), attack vs benign, random 70/30 split |
| Q4 | Same model trained on Monday-Thursday and tested on Friday. The chart shows the share of each attack family caught under Q3 and Q4 |

`Destination Port` is excluded from the model because it identifies the targeted service in the testbed rather than flow behaviour.
Also saved: PR-AUC, precision, recall and F1 for both evaluations, and the top 15 feature importances.

## Limitations
- Testbed traffic from 2017; attack tooling and benign traffic differ from current networks.
- Published critiques of CIC-IDS2017 report labelling and flow-construction errors in the original CSVs; this project uses the original files as distributed.
- Friday's attacks (botnet, port scan, DDoS) do not appear on earlier days, so the cross-day test measures detection of unseen attack types, not of the same attacks later in time.
- The EDA sample is stratified by label and does not reflect true class proportions.
