"""
A/B experiment — does learning actually help?

Runs the SAME PR twice:
  Track A: with shot library (use_learning=True)
  Track B: no shots       (use_learning=False)

Saves both results and prints a side-by-side comparison.
Run N rounds:  python3 run_ab.py --rounds 5
Single round:  python3 run_ab.py
"""

import argparse
import json
from pathlib import Path
from targets.github_prs import load_random
from run_one import run_battle

AB_DIR = Path("data/ab_experiments")


def _next_exp_number() -> int:
    AB_DIR.mkdir(parents=True, exist_ok=True)
    return len(list(AB_DIR.glob("exp_*.json"))) + 1


def run_experiment(pr: dict = None) -> dict:
    if pr is None:
        pr = load_random()

    n = _next_exp_number()
    SEP = "═" * 70
    print(f"\n{SEP}")
    print(f"🧪  A/B EXPERIMENT #{n}  —  PR #{pr['number']}: {pr['title']}")
    print(SEP)

    # ── Track A: WITH learning — knows which CVEs have been tried ──
    # Collect CVEs already attempted on this PR (from all prior battles)
    # Only Track A gets this knowledge — Track B is always cold-start
    from agents.shot_library import failed_cves_for_pr
    used_cves = failed_cves_for_pr(pr["number"])
    if used_cves:
        print(f"  [Track A] Avoiding {len(used_cves)} failed CVEs on this PR (void/caught only)")

    print("\n── TRACK A: WITH LEARNING ──────────────────────────────")
    result_a = run_battle(pr=pr, use_learning=True, forbidden_cves=used_cves)

    # ── Track B: WITHOUT learning — cold start, no memory ────────
    print("\n── TRACK B: NO LEARNING (baseline) ─────────────────────")
    result_b = run_battle(pr=pr, use_learning=False)

    # ── Comparison ────────────────────────────────────────────
    winner_icon = {"attacker": "🔴", "defender": "🟢", "void": "⚪"}
    vc_icon     = {"security": "🔐", "dos": "💥", "functional": "⚙️", "none": "—"}

    print(f"\n{SEP}")
    print(f"📊  EXPERIMENT #{n} COMPARISON")
    print(SEP)
    print(f"{'':30} {'WITH LEARNING':>18}  {'NO LEARNING':>18}")
    print(f"{'─'*30} {'─'*18}  {'─'*18}")

    a_w = result_a["true_winner"]
    b_w = result_b["true_winner"]
    print(f"{'Winner':30} {winner_icon.get(a_w,'?')+' '+a_w.upper():>18}  {winner_icon.get(b_w,'?')+' '+b_w.upper():>18}")

    a_vc = result_a.get("vulnerability_class", "none")
    b_vc = result_b.get("vulnerability_class", "none")
    print(f"{'Vuln class':30} {vc_icon.get(a_vc,'?')+' '+a_vc:>18}  {vc_icon.get(b_vc,'?')+' '+b_vc:>18}")

    a_iv = result_a.get("injection_valid", False)
    b_iv = result_b.get("injection_valid", False)
    print(f"{'Injection valid':30} {str(a_iv):>18}  {str(b_iv):>18}")

    a_dc = result_a.get("defender_correct", False)
    b_dc = result_b.get("defender_correct", False)
    print(f"{'Defender correct':30} {str(a_dc):>18}  {str(b_dc):>18}")

    a_ca = result_a.get("critic_approved", False)
    b_ca = result_b.get("critic_approved", False)
    print(f"{'Critic approved':30} {str(a_ca):>18}  {str(b_ca):>18}")

    print(SEP)
    if a_w == b_w:
        print(f"  Same outcome: {winner_icon.get(a_w,'')} {a_w.upper()} — learning made no difference this round")
    elif a_w == "attacker" and b_w != "attacker":
        print("  ✅ Learning HELPED attacker: won WITH shots but not without")
    elif b_w == "attacker" and a_w != "attacker":
        print("  ⚠️  Learning HURT attacker: won WITHOUT shots but not with")
    elif a_w == "defender" and b_w != "defender":
        print("  ✅ Learning HELPED defender: caught it WITH shots but not without")
    elif b_w == "defender" and a_w != "defender":
        print("  ⚠️  Learning HURT defender: caught it WITHOUT shots but not with")
    print()

    experiment = {
        "experiment_number": n,
        "pr_number": pr["number"],
        "pr_title":  pr["title"],
        "pr_url":    pr["url"],
        "track_a":   {"use_learning": True,  **_summarise(result_a)},
        "track_b":   {"use_learning": False, **_summarise(result_b)},
        "learning_helped_attacker":  (a_w == "attacker" and b_w != "attacker"),
        "learning_helped_defender":  (a_w == "defender" and b_w != "defender"),
        "same_outcome":              (a_w == b_w),
    }

    path = AB_DIR / f"exp_{n:03d}.json"
    path.write_text(json.dumps(experiment, indent=2))
    print(f"Saved → {path}")
    return experiment


def _summarise(r: dict) -> dict:
    return {
        "cve_id":              r.get("cve_id", ""),
        "critic_approved":     r.get("critic_approved"),
        "injection_valid":     r.get("injection_valid"),
        "vulnerability_class": r.get("vulnerability_class", "none"),
        "defender_verdict":    r.get("defender_verdict", ""),
        "defender_correct":    r.get("defender_correct"),
        "true_winner":         r.get("true_winner", ""),
    }


def print_ab_stats() -> None:
    """Print aggregate stats across all A/B experiments."""
    files = sorted(AB_DIR.glob("exp_*.json"))
    if not files:
        print("No experiments yet.")
        return

    total = len(files)
    atk_helped  = sum(1 for f in files if json.loads(f.read_text()).get("learning_helped_attacker"))
    def_helped  = sum(1 for f in files if json.loads(f.read_text()).get("learning_helped_defender"))
    same        = sum(1 for f in files if json.loads(f.read_text()).get("same_outcome"))

    a_wins = sum(1 for f in files if json.loads(f.read_text())["track_a"]["true_winner"] == "attacker")
    b_wins = sum(1 for f in files if json.loads(f.read_text())["track_b"]["true_winner"] == "attacker")

    a_sec = sum(1 for f in files if json.loads(f.read_text())["track_a"].get("vulnerability_class") == "security")
    b_sec = sum(1 for f in files if json.loads(f.read_text())["track_b"].get("vulnerability_class") == "security")

    SEP = "═" * 60
    print(f"\n{SEP}")
    print(f"📊  A/B AGGREGATE STATS  ({total} experiments)")
    print(SEP)
    print(f"  Same outcome both tracks : {same}/{total} ({100*same//total}%)")
    print(f"  Learning helped attacker : {atk_helped}/{total}")
    print(f"  Learning helped defender : {def_helped}/{total}")
    print(f"  Attacker wins  WITH learning : {a_wins}/{total}")
    print(f"  Attacker wins  NO   learning : {b_wins}/{total}")
    print(f"  Security-class WITH learning : {a_sec}/{total}")
    print(f"  Security-class NO   learning : {b_sec}/{total}")
    print(SEP)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--rounds", type=int, default=1,
                        help="Number of A/B experiment pairs to run")
    parser.add_argument("--stats", action="store_true",
                        help="Print aggregate stats and exit")
    parser.add_argument("--pr", type=int, default=None,
                        help="Fix a specific PR number for all rounds (e.g. --pr 21041)")
    args = parser.parse_args()

    if args.stats:
        print_ab_stats()
    else:
        fixed_pr = None
        if args.pr:
            from pathlib import Path as _Path
            import json as _json
            pr_files = list(_Path("data/prs").rglob(f"{args.pr}.json"))
            if not pr_files:
                raise SystemExit(f"PR #{args.pr} not found in cache. Run fetch first.")
            fixed_pr = _json.loads(pr_files[0].read_text())
            print(f"\n🎯  FOCUSED MODE: all {args.rounds} rounds will use PR #{args.pr}: {fixed_pr['title']}")

        for i in range(args.rounds):
            run_experiment(pr=fixed_pr)
        if args.rounds > 1:
            print_ab_stats()
