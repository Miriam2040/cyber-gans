"""Generate clean simple visualizations for the README."""
import json
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
from pathlib import Path

# ── Load data ──────────────────────────────────────────────────────────────────
files = sorted(Path("data/ab_experiments").glob("exp_*.json"))
exps  = [json.loads(f.read_text()) for f in files]
n     = len(exps)
if n < 5:
    print(f"Only {n} experiments — run more battles first")
    exit()

# Cumulative bypass rate over time (wins / real injections)
def cum_bypass(exps, track):
    atk = dfn = 0
    rates = []
    for e in exps:
        w = e[track]["true_winner"]
        if w == "attacker": atk += 1
        if w == "defender": dfn += 1
        rates.append(100 * atk / (atk + dfn) if (atk + dfn) > 0 else 0)
    return rates

a_bypass = cum_bypass(exps, "track_a")
b_bypass = cum_bypass(exps, "track_b")
xs = list(range(1, n + 1))

# Per-experiment win icons for strip chart
def win_colors(exps, track):
    colors = []
    for e in exps:
        w = e[track]["true_winner"]
        colors.append("#e74c3c" if w == "attacker" else
                      "#2ecc71" if w == "defender" else
                      "#95a5a6")
    return colors

a_colors = win_colors(exps, "track_a")
b_colors = win_colors(exps, "track_b")

# ── Figure ──────────────────────────────────────────────────────────────────────
fig, axes = plt.subplots(3, 1, figsize=(11, 8),
                          gridspec_kw={"height_ratios": [4, 0.6, 0.6]})
fig.patch.set_facecolor("white")
plt.subplots_adjust(hspace=0.08)

# ─ Main line chart ─────────────────────────────────────────────────────────────
ax = axes[0]
ax.set_facecolor("#f8f9fa")
ax.plot(xs, a_bypass, color="#e74c3c", linewidth=2.5, label="With learning", zorder=3)
ax.plot(xs, b_bypass, color="#3498db", linewidth=2.5, linestyle="--",
        label="No learning (baseline)", zorder=3)
ax.axhline(50, color="#bdc3c7", linewidth=1, linestyle=":")

# Phase bands
phase_ends = [min(7, n), min(13, n), n]
phase_labels = ["Phase 1\nNo shots yet", "Phase 2\nDefender surges", "Phase 3\nAttacker learns"]
phase_colors = ["#fef9e7", "#eaf4fb", "#eafaf1"]
prev = 0
for end, label, color in zip(phase_ends, phase_labels, phase_colors):
    if prev >= n: break
    ax.axvspan(prev + 0.5, end + 0.5, alpha=0.5, color=color, zorder=1)
    mid = (prev + end) / 2 + 0.5
    if mid <= n:
        ax.text(mid, 96, label, ha="center", va="top", fontsize=8,
                color="#7f8c8d", fontweight="bold")
    prev = end

ax.set_xlim(0.5, n + 0.5)
ax.set_ylim(-5, 105)
ax.set_ylabel("Attacker bypass rate (%)\n(wins / real injections)", fontsize=9)
ax.set_title("Cyber GANs — Arms Race on Django Auth Code", fontsize=13, fontweight="bold", pad=12)
ax.legend(loc="upper right", fontsize=9, framealpha=0.9)
ax.set_xticklabels([])
ax.spines[["top", "right"]].set_visible(False)
ax.grid(axis="y", alpha=0.3)

# ─ Win strips ──────────────────────────────────────────────────────────────────
for strip_ax, colors, label in [
    (axes[1], a_colors, "With learning"),
    (axes[2], b_colors, "No learning"),
]:
    strip_ax.set_facecolor("white")
    for i, c in enumerate(colors):
        strip_ax.barh(0, 1, left=i + 0.5, height=0.9, color=c, edgecolor="white", linewidth=0.5)
    strip_ax.set_xlim(0.5, n + 0.5)
    strip_ax.set_ylim(-0.5, 0.5)
    strip_ax.set_yticks([0])
    strip_ax.set_yticklabels([label], fontsize=8)
    strip_ax.set_xticklabels([])
    strip_ax.spines[["top", "right", "bottom", "left"]].set_visible(False)
    if strip_ax == axes[2]:
        strip_ax.set_xticks(range(1, n + 1))
        strip_ax.set_xticklabels(range(1, n + 1), fontsize=7)
        strip_ax.set_xlabel("Experiment number", fontsize=8)

# Legend for strips
patches = [
    mpatches.Patch(color="#e74c3c", label="Attacker wins"),
    mpatches.Patch(color="#2ecc71", label="Defender wins"),
    mpatches.Patch(color="#95a5a6", label="Void"),
]
axes[2].legend(handles=patches, loc="lower right", fontsize=7,
               framealpha=0.9, ncol=3)

plt.savefig("assets/arms_race.png", dpi=150, bbox_inches="tight",
            facecolor="white", edgecolor="none")
print(f"Saved assets/arms_race.png  ({n} experiments)")
plt.close()
