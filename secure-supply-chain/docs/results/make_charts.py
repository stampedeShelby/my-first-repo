"""Chart the benchmark results (docs/results/benchmark.json -> verification_cost.png).

    python docs/results/make_charts.py
"""

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import matplotlib.ticker  # noqa: E402

HERE = Path(__file__).resolve().parent
SERIES = [("sha256_ms", "SHA-256 hash", "#2a78d6"), ("sign_ms", "Ed25519 sign", "#eb6834"),
          ("verify_ms", "Ed25519 verify", "#1baf7a")]


def main() -> None:
    bench = json.loads((HERE / "benchmark.json").read_text())["benchmark"]["primitives_by_size"]
    sizes = list(bench)
    x = [1, 100, 1024, 10240]  # KB
    fig, ax = plt.subplots(figsize=(7.2, 3.9), dpi=200)
    for key, label, colour in SERIES:
        y = [bench[s][key] for s in sizes]
        ax.plot(x, y, color=colour, linewidth=2, marker="o", markersize=5,
                label=f"{label}  ({y[0]:.2f} ms at 1 KB, {y[-1]:.0f} ms at 10 MB)")
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_xticks(x, sizes)
    ax.set_xlabel("Artifact size", color="#52514e"); ax.set_ylabel("Time (ms, log scale)", color="#52514e")
    ax.set_title("Cost of each cryptographic operation vs artifact size", fontsize=11, loc="left", color="#0b0b0b")
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color("#b5b4ad")
    ax.tick_params(colors="#52514e", labelsize=9)
    ax.grid(True, which="major", axis="y", color="#e6e5e0", linewidth=0.8)
    ax.set_xlim(0.7, 15000)
    ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v:g}"))
    ax.legend(frameon=False, fontsize=9, loc="upper left")
    fig.tight_layout()
    fig.savefig(HERE / "verification_cost.png")
    print("wrote", HERE / "verification_cost.png")


if __name__ == "__main__":
    main()
