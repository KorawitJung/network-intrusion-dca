"""Charts that answer the first two questions. Run from the project root: py scripts/02_eda.py

Q1  How much of the traffic is an attack, and which attack type is most common?
Q2  What does attack traffic look like next to normal traffic?

Input : data/clean/cicids2017_sample.csv, output/tables/label_by_day.csv
Output: output/png/01..03_*.png, output/tables/attack_share.csv
"""
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.ticker import FuncFormatter

PNG = Path("output/png")
TABLES = Path("output/tables")
PNG.mkdir(parents=True, exist_ok=True)
RED, BLUE = "#c1121f", "#2a6f97"
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
plt.rcParams.update({"axes.spines.top": False, "axes.spines.right": False, "font.size": 11})
comma = FuncFormatter(lambda v, _: f"{v:,.0f}")


def save(fig, name):
    fig.tight_layout()
    fig.savefig(PNG / name, dpi=150)
    plt.close(fig)


by_day = pd.read_csv(TABLES / "label_by_day.csv")
sample = pd.read_csv("data/clean/cicids2017_sample.csv", low_memory=False)

# Q1. How much of the traffic is an attack, and which type is most common?
by_family = by_day.groupby("attack_family")["flows"].sum().sort_values()
share = (by_family / by_family.sum()).rename("share_of_all_flows")
pd.concat([by_family, share], axis=1).reset_index().to_csv(TABLES / "attack_share.csv", index=False)

fig, ax = plt.subplots(figsize=(8, 4.5))
bars = ax.barh(by_family.index, by_family.values, color=[BLUE if f == "Benign" else RED for f in by_family.index])
ax.bar_label(bars, labels=[f" {n:,} ({s:.1%})" for n, s in zip(by_family.values, share.values)])
ax.set_xscale("log")
ax.xaxis.set_major_formatter(comma)
ax.set_xlim(right=by_family.max() * 30)
ax.set(title="Q1. How much of the traffic is an attack, and which type?", xlabel="Network flows (log scale)")
save(fig, "01_attack_share.png")

# Q1b. Which attacks happened on which day
attacks = by_day[by_day["attack_family"] != "Benign"]
pivot = attacks.pivot_table(index="day", columns="attack_family", values="flows", aggfunc="sum", fill_value=0)
pivot = pivot.reindex([d for d in DAYS if d in set(by_day["day"])], fill_value=0)
fig, ax = plt.subplots(figsize=(8, 4.5))
pivot.plot(kind="bar", stacked=True, ax=ax, colormap="tab10", width=0.75)
ax.yaxis.set_major_formatter(comma)
ax.tick_params(axis="x", rotation=0)
ax.legend(title=None, frameon=False)
ax.set(title="Q1. Which attacks happened on which day?", xlabel="", ylabel="Attack flows")
save(fig, "02_attacks_by_day.png")

# Q2. What does attack traffic look like next to normal traffic?
wanted = ["Flow Duration", "Total Fwd Packets", "Flow Bytes/s", "Packet Length Mean"]
features = [c for c in wanted if c in sample.columns]
order = ["Benign"] + sorted(f for f in sample["attack_family"].unique() if f != "Benign")
order = [f for f in order if f in set(sample["attack_family"])]
fig, axes = plt.subplots(1, len(features), figsize=(4 * len(features), 4.8), sharey=True, squeeze=False)
for ax, feat in zip(axes[0], features):
    data = [sample.loc[sample["attack_family"] == f, feat].abs() + 1 for f in order]
    box = ax.boxplot(data, orientation="horizontal", showfliers=False, patch_artist=True)
    for patch, f in zip(box["boxes"], order):
        patch.set_facecolor(BLUE if f == "Benign" else RED)
        patch.set_alpha(0.7)
    ax.set_yticks(range(1, len(order) + 1), order)
    ax.set_xscale("log")
    ax.set_title(feat, fontsize=11)
fig.suptitle("Q2. What does attack traffic look like next to normal traffic? (log scale)")
save(fig, "03_attack_vs_normal.png")

print(pd.concat([by_family, share], axis=1).to_string())
print("charts written to", PNG)
