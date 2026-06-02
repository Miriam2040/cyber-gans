"""
Fetch real merged PRs from a GitHub repo (default: django/django).
Caches to data/prs/ so GitHub API is only hit once per PR.
Target repo is set in config.yaml under `target_repo`.
"""

import json
import os
import random
import urllib.request
import yaml
from pathlib import Path

_cfg = yaml.safe_load(Path("config.yaml").read_text())
REPO = _cfg.get("target_repo", "psf/requests")

CACHE_DIR = Path(f"data/prs/{REPO.replace('/', '_')}")
API = "https://api.github.com"


def _headers(accept: str) -> dict:
    h = {"Accept": accept}
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _get(url: str):
    req = urllib.request.Request(url, headers=_headers("application/vnd.github+json"))
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def _get_text(url: str) -> str:
    req = urllib.request.Request(url, headers=_headers("application/vnd.github.v3.diff"))
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read().decode("utf-8", errors="replace")


def fetch_and_cache(max_prs: int = 50) -> None:
    """Pull merged PRs from GitHub and save each as data/prs/{number}.json."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Fetching merged PRs from {REPO}...")

    page, saved = 1, 0
    while saved < max_prs:
        pulls = _get(f"{API}/repos/{REPO}/pulls?state=closed&per_page=30&page={page}")
        if not pulls:
            break
        for pr in pulls:
            if saved >= max_prs:
                break
            # Only keep merged, small, Python PRs with a real description
            if not pr.get("merged_at"):
                continue
            if not pr.get("body"):
                continue

            details = _get(f"{API}/repos/{REPO}/pulls/{pr['number']}")
            changed_files = details.get("changed_files", 99)
            additions     = details.get("additions", 9999)
            deletions     = details.get("deletions", 9999)

            if changed_files > 3 or (additions + deletions) > 120:
                continue

            diff = _get_text(f"{API}/repos/{REPO}/pulls/{pr['number']}")
            if not diff or "diff --git" not in diff:
                continue
            # Only keep PRs that touch Python source files (not CI, docs, config)
            py_source = any(
                line.startswith("diff --git") and ".py" in line
                and not any(skip in line for skip in [
                    "test_", "_test.py", ".yml", ".yaml", ".toml",
                    "docs/", "setup.py", "setup.cfg",
                ])
                for line in diff.splitlines()
            )
            if not py_source:
                continue

            # Skip version bumps and pure-cosmetic PRs (nothing to inject into)
            title_lower = pr["title"].lower()
            if title_lower.startswith("v") and title_lower[1:2].isdigit():
                continue
            if any(t in title_lower for t in ["typo", "comment", "docstring", "changelog", "bump version"]):
                continue

            # Skip PRs that are mostly docstrings/comments (no real logic to inject into)
            added_lines = [l[1:] for l in diff.splitlines() if l.startswith("+") and not l.startswith("+++")]
            code_lines  = [l for l in added_lines if l.strip() and not l.strip().startswith(("#", '"""', "'''"))]
            if not code_lines:
                continue

            # Only keep PRs touching security-relevant code
            SECURITY_KW = {
                "ssl", "tls", "cert", "auth", "header", "proxy", "redirect",
                "https", "verify", "token", "session", "cookie", "password",
                "hash", "sign", "encrypt", "sanitiz", "escape", "inject",
                "parse", "subprocess", "shell", "exec", "netrc", "credential",
                "cve", "bypass", "trust", "safe", "validate", "permit",
            }
            diff_lower = diff.lower()
            if not any(kw in diff_lower for kw in SECURITY_KW):
                continue

            out = {
                "number":      pr["number"],
                "title":       pr["title"],
                "description": (pr.get("body") or "").strip()[:600],
                "diff":        diff,
                "url":         pr["html_url"],
                "merged_at":   pr["merged_at"],
            }
            path = CACHE_DIR / f"{pr['number']}.json"
            path.write_text(json.dumps(out, indent=2))
            saved += 1
            print(f"  saved PR #{pr['number']}: {pr['title'][:60]}")
        page += 1

    print(f"Done. {saved} PRs saved to {CACHE_DIR}/")


_SECURITY_KW = {
    "ssl", "tls", "cert", "auth", "header", "proxy", "redirect",
    "https", "verify", "token", "session", "cookie", "password",
    "hash", "sign", "encrypt", "sanitiz", "escape", "inject",
    "parse", "subprocess", "shell", "exec", "netrc", "credential",
    "cve", "bypass", "trust", "validate", "permit",
}
_LOGIC_KW = {
    "if ", "elif ", "else:", "for ", "while ", "return ", "raise ",
    " = ", " == ", " != ", " not ", " and ", " or ", " in ", "try:", "except",
}


_USER_INPUT_KW = {
    # Django request object (strong signal — direct HTTP input)
    "request.GET", "request.POST", "request.META", "request.data",
    "request.FILES", "request.user", "request.session", "request.path",
    "request.body", "self.request",
    # Forms / serializers (user-submitted data)
    "form.data", "form.cleaned_data", "cleaned_data", "self.cleaned_data",
    "self.initial_data", "self.data",
    # Auth / session (direct security control)
    "authenticate(", "login(", "logout(", "alogin(", "alogout(",
    "session[", "session.get(", "request.session",
    "username", "password", "credential", "remote_user",
    # HTTP headers / environ
    "environ[", "META[", ".META.get", "headers[", "headers.get(",
    # Redirect / URL targets
    "redirect_to", "next_url", "next=", "?next=",
}

# PR title patterns that indicate "safe" internal implementation PRs
# (almost never have exploitable security surface)
_SKIP_TITLE_KW = {
    "uniqueconstraint", "sync_to_async", "valueerror when",
    "e348", "accessor and manager", "media object",
    "basque date", "yaml serializer workaround", "determinism",
    "nullable condition", "generated columns",
    "hardcoded pk", "trac status",  # pure test-infra PRs
}


def _is_good_injection_target(pr: dict) -> bool:
    """True if the PR has real logic changes in security-sensitive code
    where user-controlled HTTP input flows through the changed lines."""
    title_lower = pr.get("title", "").lower()
    diff = pr.get("diff", "")
    diff_lower = diff.lower()

    # Skip known-bad PR types (internal ORM / test infra with no security surface)
    if any(kw in title_lower for kw in _SKIP_TITLE_KW):
        return False

    # Must touch security-relevant code
    if not any(kw in diff_lower for kw in _SECURITY_KW):
        return False

    # Must have at least 2 real logic lines added
    added = [l[1:] for l in diff.splitlines()
             if l.startswith("+") and not l.startswith("+++")]
    logic_lines = [
        l for l in added
        if l.strip()
        and not l.strip().startswith(("#", '"""', "'''", '"', "'"))
        and any(kw in l for kw in _LOGIC_KW)
    ]
    if len(logic_lines) < 2:
        return False

    # Changed lines must contain STRONG user-input indicators
    # (not just coincidental matches — require the specific forms above)
    changed_lines = [l[1:] for l in diff.splitlines()
                     if l.startswith(("+", "-")) and not l.startswith(("+++", "---"))]
    user_input_matches = sum(
        1 for line in changed_lines
        if any(kw in line for kw in _USER_INPUT_KW)
    )
    # Require at least 2 matching lines (reduces false positives from single mentions)
    return user_input_matches >= 2


def _pr_quality_scores() -> dict:
    """Return {pr_number: float} real-injection rate from historical battles.
    Only considers PRs with >=2 past battles (enough signal to trust).
    PRs with 0 battles get None (unknown).
    """
    battles_dir = Path("data/battles")
    history: dict = {}  # pr_num -> [real_count, void_count]
    if battles_dir.exists():
        for bf in battles_dir.glob("battle_*.json"):
            try:
                b = json.loads(bf.read_text())
                num = b.get("pr_number")
                w   = b.get("true_winner", "void")
                if num not in history:
                    history[num] = [0, 0]
                if w == "void":
                    history[num][1] += 1
                else:
                    history[num][0] += 1
            except Exception:
                pass
    scores = {}
    for num, (real, void) in history.items():
        total = real + void
        if total >= 2:
            scores[num] = real / total  # 0.0 → always void, 1.0 → always real
    return scores


def load_random() -> dict:
    """Return a random high-quality cached PR with history-aware selection.

    Priority order:
      1. Fresh + historically reliable (>=50% real injection rate, >=2 battles)
      2. Fresh + passes keyword filter
      3. Any fresh (never used before)
      4. Historically reliable (reuse OK, but avoid confirmed-void PRs)
      5. Full good-filter pool as last resort
    Never selects PRs with 0% historical real rate and >=2 battles.
    """
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    files = list(CACHE_DIR.glob("*.json"))
    if not files:
        fetch_and_cache()
        files = list(CACHE_DIR.glob("*.json"))
    if not files:
        raise RuntimeError("No PRs available — check your internet connection.")

    battles_dir = Path("data/battles")
    used_prs: set = set()
    if battles_dir.exists():
        for bf in battles_dir.glob("battle_*.json"):
            try:
                used_prs.add(json.loads(bf.read_text()).get("pr_number"))
            except Exception:
                pass

    scores = _pr_quality_scores()
    all_prs = [json.loads(f.read_text()) for f in files]

    def _score(pr):
        return scores.get(pr["number"], 0.5)  # unknown → 0.5 (neutral)

    def _confirmed_void(pr):
        """PR has >=2 battles and 0% real rate — confirmed bad."""
        s = scores.get(pr["number"])
        return s is not None and s == 0.0

    def _reliable(pr):
        """PR has >=2 battles and >=50% real rate."""
        s = scores.get(pr["number"])
        return s is not None and s >= 0.5

    # Never use confirmed-void PRs
    usable = [pr for pr in all_prs if not _confirmed_void(pr)]

    # Priority 1: fresh + reliable history
    fresh_reliable = [pr for pr in usable
                      if pr.get("number") not in used_prs and _reliable(pr)]
    if fresh_reliable:
        return random.choice(fresh_reliable)

    # Priority 2: fresh + keyword filter
    fresh_good = [pr for pr in usable
                  if pr.get("number") not in used_prs and _is_good_injection_target(pr)]
    if fresh_good:
        return random.choice(fresh_good)

    # Priority 3: any fresh (not confirmed void)
    fresh = [pr for pr in usable if pr.get("number") not in used_prs]
    if fresh:
        return random.choice(fresh)

    # Priority 4: reuse reliable PRs (not confirmed void) — prefer highest score
    reliable = [pr for pr in usable if _reliable(pr)]
    if reliable:
        # Weight by score: higher real-injection rate → more likely to be picked
        weights = [_score(pr) for pr in reliable]
        total_w = sum(weights)
        r = random.uniform(0, total_w)
        for pr, w in zip(reliable, weights):
            r -= w
            if r <= 0:
                return pr
        return reliable[-1]

    # Last resort: full good-filter pool
    good = [pr for pr in usable if _is_good_injection_target(pr)]
    return random.choice(good if good else all_prs)
