"""
Cyber GANs — one battle.
Run standalone:  python3 run_one.py
Or import:       from run_one import run_battle
"""

import json
from pathlib import Path
from agents import attacker, defender, judge
from agents import shot_library
from targets.github_prs import load_random

BATTLES_DIR = Path("data/battles")


def _next_battle_number() -> int:
    BATTLES_DIR.mkdir(parents=True, exist_ok=True)
    existing = list(BATTLES_DIR.glob("battle_*.json"))
    return len(existing) + 1


def run_battle(pr: dict = None, use_learning: bool = True,
               forbidden_cves: list = None) -> dict:
    if pr is None:
        pr = load_random()

    SEP = "─" * 60
    n = _next_battle_number()

    mode_tag = "WITH learning" if use_learning else "NO learning (baseline)"
    print(f"\n{SEP}\n⚔  CYBER GANs — Battle #{n}  [{mode_tag}]")
    print(f"PR #{pr['number']}: {pr['title']}\n{SEP}")

    # ── Attacker ──────────────────────────────────────────────
    print("\n🔴 ATTACKER researching CVEs and injecting...")
    atk = attacker.run(pr, use_shots=use_learning,
                       forbidden_cves=forbidden_cves if use_learning else [])
    print(f"CVE selected   : {atk['cve_id']}")
    print(f"Mechanism      : {atk.get('cve_mechanism','')}")
    print(f"Hidden issue   : {atk['hidden_issue']}")
    approved = atk.get('critic_approved', None)
    if approved is not None:
        status = "✅ Critic approved" if approved else "⚠️  Critic rejected (best effort)"
        print(f"Critic verdict : {status} (subtlety {atk.get('critic_subtlety','?')}/5)")

    # ── Defender ──────────────────────────────────────────────
    print(f"\n{SEP}\n🟢 DEFENDER reviewing...")
    dfn = defender.run(atk["diff"], pr["title"], pr["description"], use_shots=use_learning)
    print(f"Verdict      : {dfn['verdict'].upper()} ({dfn['confidence']}%)")
    print(f"Explanation  : {dfn['explanation']}")

    # ── Judge ─────────────────────────────────────────────────
    print(f"\n{SEP}\n⚖️  JUDGE evaluating...")
    jdg = judge.run(pr, atk, dfn)
    print(f"Injection valid  : {jdg['injection_valid']} — {jdg['injection_reasoning']}")
    print(f"Defender correct : {jdg['defender_correct']} — {jdg['defender_reasoning']}")
    vc = jdg.get('vulnerability_class', 'none')
    if vc != 'none':
        vc_icon = {"security": "🔐", "dos": "💥", "functional": "⚙️"}.get(vc, "❓")
        print(f"Vuln class       : {vc_icon} {vc.upper()}")
    winner = jdg['true_winner']
    icon = {"attacker": "🔴", "defender": "🟢", "void": "⚪"}.get(winner, "❓")
    print(f"TRUE WINNER      : {icon} {winner.upper()}")

    # ── Save ──────────────────────────────────────────────────
    battle = {
        "battle_number":       n,
        "pr_number":           pr["number"],
        "pr_url":              pr["url"],
        "pr_title":            pr["title"],
        "pr_description":      pr["description"],
        "real_diff":           pr["diff"],
        "cve_queries":         atk.get("queries", []),
        "cve_id":              atk["cve_id"],
        "cve_description":     atk["cve_description"],
        "cve_rationale":       atk["cve_rationale"],
        "cve_mechanism":       atk.get("cve_mechanism", ""),
        "attacker_diff":       atk["diff"],
        "hidden_issue":        atk["hidden_issue"],
        "critic_approved":     atk.get("critic_approved"),
        "critic_subtlety":     atk.get("critic_subtlety"),
        "critic_reason":       atk.get("critic_reason", ""),
        "defender_verdict":    dfn["verdict"],
        "defender_confidence": dfn["confidence"],
        "defender_explanation":dfn["explanation"],
        "defender_concern":    dfn.get("concern", ""),
        "use_learning":         use_learning,
        "injection_valid":      jdg["injection_valid"],
        "injection_reasoning":  jdg["injection_reasoning"],
        "defender_correct":     jdg["defender_correct"],
        "defender_reasoning":   jdg["defender_reasoning"],
        "vulnerability_class":  jdg.get("vulnerability_class", "none"),
        "true_winner":          jdg["true_winner"],
        "judge_summary":        jdg["summary"],
    }

    battle_path = BATTLES_DIR / f"battle_{n:03d}.json"
    battle_path.write_text(json.dumps(battle, indent=2))
    Path("data/last_battle.json").write_text(json.dumps(battle, indent=2))

    # Store outcome as concrete shot for future battles
    shot_library.store(battle)
    s = shot_library.stats()
    print(f"Shots → atk_wins:{s['attacker_wins']} atk_loss:{s['attacker_losses']} "
          f"def_caught:{s['defender_caught']} def_missed:{s['defender_missed']}")
    print(f"Saved → {battle_path}")

    return battle


def main():
    run_battle()


if __name__ == "__main__":
    main()
