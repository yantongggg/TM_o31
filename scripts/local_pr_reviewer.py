#!/usr/bin/env python3
"""
Deterministic PR reviewer for tm-scan.
- Runs locally (no external LLMs).
- Reads latest evidence from tm-output.
- Posts inline PR comments using reviewer_message and auto_fix_snippet.
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional

import requests
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
KB_PATH = REPO_ROOT / "knowledge-base" / "kb-threats.yaml"
TM_OUTPUT = Path.home() / "tm-output" / "reports"


def load_latest_evidence() -> Dict[str, Any]:
    """Pick the most recently modified evidence.json under tm-output."""
    candidates = list(TM_OUTPUT.glob("*/**/evidence.json"))
    if not candidates:
        raise FileNotFoundError("No evidence.json found under tm-output.")
    latest = max(candidates, key=lambda p: p.stat().st_mtime)
    with latest.open() as f:
        data = json.load(f)
    return data


def load_threats() -> List[Dict[str, Any]]:
    with KB_PATH.open() as f:
        raw = yaml.safe_load(f) or {}
    threats = []
    for threat in raw.get("threats", []) or []:
        if not isinstance(threat, dict):
            continue
        threats.append({
            **threat,
            "keywords": threat.get("keywords", threat.get("keyword_triggers", [])) or [],
            "trigger_rules": threat.get("trigger_rules", []) or [],
            "reviewer_message": threat.get("reviewer_message", ""),
            "auto_fix_snippet": threat.get("auto_fix_snippet", ""),
            "dread_score": threat.get("dread_score", {}) or {},
            "compliance": threat.get("compliance", {}) or {},
        })
    return threats


def match_threats(evidence: Dict[str, Any], threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rule_hit_ids = {h.get("rule_id") for h in evidence.get("rule_hits", [])}
    evidence_keywords = set(h.get("keyword", "").lower() for h in evidence.get("keyword_hits", []))
    relevant = []
    for threat in threats:
        t_keywords = set(k.lower() for k in threat.get("keywords", []))
        trigger_rules = set(threat.get("trigger_rules", []) or [])
        keyword_hits = t_keywords & evidence_keywords
        rule_hits = trigger_rules & rule_hit_ids
        if keyword_hits or rule_hits:
            relevant.append({
                "threat": threat,
                "keyword_hits": keyword_hits,
                "rule_hits": rule_hits,
            })
    return relevant


def get_pr_number() -> int:
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if event_path and Path(event_path).exists():
        with open(event_path) as f:
            event = json.load(f)
        if "pull_request" in event:
            return int(event["pull_request"]["number"])
    ref = os.environ.get("GITHUB_REF") or ""
    if ref.startswith("refs/pull/"):
        try:
            return int(ref.split("/")[2])
        except Exception:
            pass
    raise RuntimeError("Cannot determine PR number from GitHub context.")


def fetch_pr_files(session: requests.Session, repo: str, pr_number: int) -> List[Dict[str, Any]]:
    files = []
    page = 1
    while True:
        resp = session.get(f"https://api.github.com/repos/{repo}/pulls/{pr_number}/files", params={"page": page, "per_page": 100})
        resp.raise_for_status()
        batch = resp.json()
        if not batch:
            break
        files.extend(batch)
        page += 1
    return files


def extract_positions(patch: str, keyword: str) -> List[int]:
    """Find diff positions where keyword appears in added lines."""
    positions = []
    if not patch:
        return positions
    position = 0
    for line in patch.splitlines():
        position += 1
        if not line.startswith("+") or line.startswith("+++"):
            continue
        if keyword.lower() in line.lower():
            positions.append(position)
    return positions


def dread_score(threat: Dict[str, Any]) -> float:
    fields = ["damage", "reproducibility", "exploitability", "affected_users", "discoverability"]
    scores = []
    for f in fields:
        try:
            scores.append(int(threat.get("dread_score", {}).get(f, 0)))
        except Exception:
            scores.append(0)
    return sum(scores) / len(scores) if scores else 0.0


def build_comments(relevant: List[Dict[str, Any]], evidence: Dict[str, Any], pr_files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    comments = []
    pr_files_by_path = {f.get("filename"): f for f in pr_files}

    for item in relevant:
        threat = item["threat"]
        message = threat.get("reviewer_message") or threat.get("description") or "Potential threat detected."
        fix = threat.get("auto_fix_snippet")
        body = f"**{threat.get('id')} - {threat.get('name')}**\n\n{message}"
        if fix:
            body += f"\n\nSuggested fix:\n```\n{fix}\n```"

        # Keyword-based matches to locate lines
        for hit in evidence.get("keyword_hits", []):
            if hit.get("keyword", "").lower() not in item.get("keyword_hits", set()):
                continue
            path = hit.get("file_path")
            pr_file = pr_files_by_path.get(path)
            if not pr_file:
                continue
            patch = pr_file.get("patch") or ""
            positions = extract_positions(patch, hit.get("keyword", ""))
            for pos in positions:
                comments.append({
                    "path": path,
                    "position": pos,
                    "body": body,
                })

        # Rule-based matches without keyword context fall back to file-level comments if possible
        for rule_hit in evidence.get("rule_hits", []):
            if rule_hit.get("rule_id") not in item.get("rule_hits", set()):
                continue
            path = rule_hit.get("file_path")
            pr_file = pr_files_by_path.get(path)
            if not pr_file:
                continue
            patch = pr_file.get("patch") or ""
            positions = extract_positions(patch, rule_hit.get("rule_id", ""))
            if not positions and patch:
                # fallback to first added line
                for pos in extract_positions(patch, "+"):
                    positions = [pos]
                    break
            for pos in positions:
                comments.append({
                    "path": path,
                    "position": pos,
                    "body": body,
                })

    # Deduplicate identical path/position/body
    unique = []
    seen = set()
    for c in comments:
        key = (c["path"], c["position"], c["body"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(c)
    return unique


def post_review(session: requests.Session, repo: str, pr_number: int, comments: List[Dict[str, Any]]):
    if not comments:
        print("No inline comments to post.")
        return
    payload = {
        "event": "COMMENT",
        "body": "tm-scan deterministic reviewer",
        "comments": comments,
    }
    resp = session.post(f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews", json=payload)
    resp.raise_for_status()
    print(f"Posted review with {len(comments)} comment(s).")


def main():
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("GITHUB_TOKEN is required")
        sys.exit(1)

    repo = os.environ.get("GITHUB_REPOSITORY")
    if not repo:
        print("GITHUB_REPOSITORY is required")
        sys.exit(1)

    evidence = load_latest_evidence()
    threats = load_threats()
    relevant = match_threats(evidence, threats)

    pr_number = get_pr_number()

    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "tm-scan-pr-reviewer",
    })

    pr_files = fetch_pr_files(session, repo, pr_number)
    comments = build_comments(relevant, evidence, pr_files)

    if comments:
        post_review(session, repo, pr_number, comments)
    else:
        print("No matching threats or diff locations found; no comments posted.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Error: {exc}")
        sys.exit(1)
