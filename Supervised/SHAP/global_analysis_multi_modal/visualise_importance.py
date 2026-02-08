import os
import pandas as pd
import matplotlib.pyplot as plt

# -----------------------------
# Paths
# -----------------------------
"""untuned dir and name prefix rn"""
CSV_PATH = "Supervised/SHAP/global_analysis_multi_modal/untuned_multimodal_feature_importance_by_tactic.csv"
OUT_DIR = "Supervised/SHAP/global_analysis_multi_modal/untuned_graphs"

os.makedirs(OUT_DIR, exist_ok=True)

# -----------------------------
# Load CSV
# -----------------------------
df = pd.read_csv(CSV_PATH)
df.columns = [c.strip() for c in df.columns]

# -----------------------------
# Feature order (fixed, readable)
# -----------------------------
FEATURE_ORDER = [
    "TEXT_ABSTRACT",
    "TEXT_CWE",
    "TEXT_CPE",
    "EPSS",
    "CVSS_C",
    "CVSS_I",
    "CVSS_A",
]

df["Feature"] = pd.Categorical(
    df["Feature"],
    categories=FEATURE_ORDER,
    ordered=True
)

# -----------------------------
# Feature → colour (modality hint)
# -----------------------------
COLOR_MAP = {
    "TEXT_ABSTRACT": "#4C72B0",
    "TEXT_CWE": "#4C72B0",
    "TEXT_CPE": "#4C72B0",
    "EPSS": "#DD8452",
    "CVSS_C": "#55A868",
    "CVSS_I": "#55A868",
    "CVSS_A": "#55A868",
}

# -----------------------------
# Plot per tactic (save only)
# -----------------------------
tactics = sorted(df["Tactic"].unique())

for tactic in tactics:
    subset = (
        df[df["Tactic"] == tactic]
        .sort_values("Feature")
    )

    fig, ax = plt.subplots(figsize=(8, 4))

    bars = ax.bar(
        subset["Feature"],
        subset["Importance (%)"],
        color=[COLOR_MAP[f] for f in subset["Feature"]]
    )

    # Value labels
    for bar, value in zip(bars, subset["Importance (%)"]):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            value + 1,
            f"{value:.1f}%",
            ha="center",
            va="bottom",
            fontsize=9
        )

    # Formatting
    ax.set_title(f"Global Feature Importance – {tactic}")
    ax.set_ylabel("Importance (%)")
    ax.set_ylim(0, max(60, subset["Importance (%)"].max() * 1.15))

    ax.tick_params(axis="x", rotation=30)
    ax.grid(axis="y", linestyle="--", alpha=0.3)

    plt.tight_layout()

    fname = tactic.lower().replace(" ", "_").replace("/", "_")
    plt.savefig(
        os.path.join(OUT_DIR, f"{fname}_feature_importance.png"),
        dpi=300
    )
    plt.close(fig)

print(f"Saved {len(tactics)} figures to {OUT_DIR}")
