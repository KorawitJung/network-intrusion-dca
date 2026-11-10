"""Run from the project root: py scripts/03_model.py

Q3  Can a model tell attacks from normal traffic?          (random 70/30 split)
Q4  Can it catch attack types it has never seen before?    (train Mon-Thu, test Fri)

Input : data/clean/cicids2017_clean.csv
Output: output/tables/model_metrics.csv, output/tables/recall_by_family.csv,
        output/tables/feature_importance.csv, output/png/04_attacks_caught.png
"""
from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

MAX_TRAIN_ROWS = 500_000
META = ["Label", "attack_family", "is_attack", "source_file", "day"]
# Destination Port identifies the targeted service in this testbed rather than behaviour.
EXCLUDE = META + ["Destination Port"]

df = pd.read_csv("data/clean/cicids2017_clean.csv", low_memory=False)
features = [c for c in df.columns if c not in EXCLUDE]


def fit_eval(name, train, test):
    if len(train) > MAX_TRAIN_ROWS:
        train = train.sample(MAX_TRAIN_ROWS, random_state=42)
    model = RandomForestClassifier(n_estimators=100, n_jobs=-1, class_weight="balanced", random_state=42)
    model.fit(train[features], train["is_attack"])
    prob = model.predict_proba(test[features])[:, 1]
    pred = (prob >= 0.5).astype(int)
    summary = {
        "evaluation": name,
        "train_rows": len(train),
        "test_rows": len(test),
        "test_attack_share": test["is_attack"].mean(),
        "pr_auc": average_precision_score(test["is_attack"], prob),
        "precision": precision_score(test["is_attack"], pred, zero_division=0),
        "recall": recall_score(test["is_attack"], pred, zero_division=0),
        "f1": f1_score(test["is_attack"], pred, zero_division=0),
    }
    by_family = (
        test.assign(pred=pred)[test["is_attack"] == 1]
        .groupby("attack_family")
        .agg(flows=("pred", "size"), recall=("pred", "mean"))
        .reset_index()
        .assign(evaluation=name)
    )
    importance = pd.DataFrame(
        {"evaluation": name, "feature": features, "importance": model.feature_importances_}
    ).nlargest(15, "importance")
    return summary, by_family, importance


runs = []
train, test = train_test_split(df, test_size=0.3, stratify=df["is_attack"], random_state=42)
runs.append(fit_eval("random split", train, test))

is_friday = df["day"].eq("Friday")
if is_friday.any() and (~is_friday).any():
    runs.append(fit_eval("train Mon-Thu, test Fri", df[~is_friday], df[is_friday]))
else:
    print("Skipping cross-day evaluation: need both Friday and non-Friday files.")

out = Path("output/tables")
out.mkdir(parents=True, exist_ok=True)
metrics = pd.DataFrame([r[0] for r in runs])
metrics.to_csv(out / "model_metrics.csv", index=False)
pd.concat([r[1] for r in runs]).to_csv(out / "recall_by_family.csv", index=False)
pd.concat([r[2] for r in runs]).to_csv(out / "feature_importance.csv", index=False)
print(metrics.to_string(index=False))
print(pd.concat([r[1] for r in runs]).to_string(index=False))

# Q3 / Q4 chart: share of each attack type the model catches, per evaluation.
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

recall = pd.concat([r[1] for r in runs]).pivot(index="attack_family", columns="evaluation", values="recall")
recall = recall[[m["evaluation"] for m in (r[0] for r in runs)]]
colors = ["#2a6f97", "#c1121f"][: recall.shape[1]]
ax = recall.plot(kind="barh", figsize=(8, 5), color=colors, width=0.75)
for container, col in zip(ax.containers, recall.columns):
    # A family missing from an evaluation's test set has no recall; say so instead of showing 0%.
    ax.bar_label(container, labels=[f" {v:.0%}" if pd.notna(v) else " not in this test" for v in recall[col]])
ax.set_xlim(0, 1.25)
ax.set_xticks([])
for side in ("top", "right", "bottom"):
    ax.spines[side].set_visible(False)
ax.legend(title=None, frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.02), ncol=2)
ax.set(title="Q3-Q4. Share of attacks caught, by attack type", ylabel="")
ax.figure.tight_layout()
Path("output/png").mkdir(parents=True, exist_ok=True)
ax.figure.savefig("output/png/04_attacks_caught.png", dpi=150)
