"""
Gitleaks wrapper module for secret scanning.
"""

import subprocess
import json
import re
from pathlib import Path
from typing import Dict, List, Any
from .config import Config


class GitleaksWrapper:
    """Wrapper for gitleaks secret scanning."""

    def __init__(self, config: Config):
        self.config = config
        self.available = self._check_available()

    def _check_available(self) -> bool:
        """Check if gitleaks is installed."""
        try:
            result = subprocess.run(
                ["gitleaks", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def scan_repo(self, repo_path: Path, repo_name: str) -> Dict[str, Any]:
        """
        Scan a repository with gitleaks.

        Returns summary dictionary (redacted - no actual secrets).
        """
        if not self.available:
            return {
                "status": "skipped",
                "reason": "gitleaks not installed",
                "findings_count": 0,
            }

        report_path = self.config.get_repo_report_dir(repo_name) / "gitleaks-report.json"

        try:
            result = subprocess.run(
                [
                    "gitleaks", "detect",
                    "--source", str(repo_path),
                    "--report-format", "json",
                    "--report-path", str(report_path),
                    "--verbose",
                ],
                capture_output=True,
                text=True,
                timeout=600,  # 10 minute timeout
            )
        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "reason": "scan timeout",
                "findings_count": 0,
            }
        except Exception as e:
            return {
                "status": "error",
                "reason": str(e),
                "findings_count": 0,
            }

        # Parse and summarize results (redacted)
        return self._parse_results(report_path)

    def _parse_results(self, report_path: Path) -> Dict[str, Any]:
        """Parse gitleaks results and create redacted summary."""
        if not report_path.exists():
            return {
                "status": "completed",
                "findings_count": 0,
                "findings_by_rule": {},
            }

        try:
            with open(report_path, "r") as f:
                data = json.load(f)
        except (json.JSONDecodeError, Exception):
            return {
                "status": "error",
                "reason": "could not parse report",
                "findings_count": 0,
            }

        # Summarize findings by rule (NEVER include actual matched strings)
        findings_by_rule: Dict[str, Dict] = {}
        total_count = 0

        for finding in data:
            rule_id = finding.get("ruleID", "unknown")
            file_path = finding.get("file", "unknown")

            if rule_id not in findings_by_rule:
                findings_by_rule[rule_id] = {
                    "count": 0,
                    "files": set(),
                }

            findings_by_rule[rule_id]["count"] += 1
            findings_by_rule[rule_id]["files"].add(file_path)
            total_count += 1

        # Convert sets to lists for JSON serialization
        for rule in findings_by_rule:
            findings_by_rule[rule]["files"] = list(findings_by_rule[rule]["files"])

        # Delete the raw report to avoid storing secrets
        try:
            report_path.unlink()
        except Exception:
            pass

        return {
            "status": "completed",
            "findings_count": total_count,
            "findings_by_rule": findings_by_rule,
        }

    def save_summary(self, summary: Dict, repo_name: str):
        """Save redacted gitleaks summary."""
        report_dir = self.config.get_repo_report_dir(repo_name)
        report_dir.mkdir(parents=True, exist_ok=True)

        summary_path = report_dir / "gitleaks-summary.json"
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)

        return summary_path
