"""
Syft wrapper module for SBOM generation.
"""

import subprocess
import json
from pathlib import Path
from typing import Dict, List, Any
from .config import Config


class SyftWrapper:
    """Wrapper for syft SBOM generation."""

    def __init__(self, config: Config):
        self.config = config
        self.available = self._check_available()

    def _check_available(self) -> bool:
        """Check if syft is installed."""
        try:
            result = subprocess.run(
                ["syft", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def scan_repo(self, repo_path: Path, repo_name: str) -> Dict[str, Any]:
        """
        Generate SBOM for a repository using syft.

        Returns summary dictionary.
        """
        if not self.available:
            return {
                "status": "skipped",
                "reason": "syft not installed",
                "package_count": 0,
            }

        report_path = self.config.get_repo_report_dir(repo_name) / "sbom.json"

        try:
            result = subprocess.run(
                [
                    "syft", str(repo_path),
                    "-o", "json",
                    "--file", str(report_path),
                ],
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )
        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "reason": "scan timeout",
                "package_count": 0,
            }
        except Exception as e:
            return {
                "status": "error",
                "reason": str(e),
                "package_count": 0,
            }

        # Parse and summarize results
        return self._parse_results(report_path)

    def _parse_results(self, report_path: Path) -> Dict[str, Any]:
        """Parse syft SBOM and create summary."""
        if not report_path.exists():
            return {
                "status": "completed",
                "package_count": 0,
                "packages_by_type": {},
                "packages_by_language": {},
            }

        try:
            with open(report_path, "r") as f:
                data = json.load(f)
        except (json.JSONDecodeError, Exception):
            return {
                "status": "error",
                "reason": "could not parse SBOM",
                "package_count": 0,
            }

        # Summarize packages
        packages_by_type: Dict[str, int] = {}
        packages_by_language: Dict[str, int] = {}
        total_count = 0

        for artifact in data.get("artifacts", []):
            ptype = artifact.get("type", "unknown")
            language = artifact.get("language", "unknown")

            packages_by_type[ptype] = packages_by_type.get(ptype, 0) + 1
            packages_by_language[language] = packages_by_language.get(language, 0) + 1
            total_count += 1

        # Get high-risk packages (outdated packages with known vulnerabilities would go here)
        # For now, just count packages by severity if syft provides vulnerability data

        return {
            "status": "completed",
            "package_count": total_count,
            "packages_by_type": packages_by_type,
            "packages_by_language": packages_by_language,
        }

    def save_summary(self, summary: Dict, repo_name: str):
        """Save SBOM summary."""
        report_dir = self.config.get_repo_report_dir(repo_name)
        report_dir.mkdir(parents=True, exist_ok=True)

        summary_path = report_dir / "sbom-summary.json"
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)

        return summary_path
