"""
Configuration handling for tm-scan.
"""

import os
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, List


def load_env_file(env_path: Optional[Path] = None) -> dict:
    """Load .env file if it exists."""
    env_vars = {}
    if env_path is None:
        # Look for .env in current directory or script directory
        script_dir = Path(__file__).parent.parent
        env_path = Path(".env")
        if not env_path.exists():
            env_path = script_dir / ".env"

    if env_path.exists():
        try:
            with open(env_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, value = line.split("=", 1)
                        env_vars[key.strip()] = value.strip()
        except Exception:
            pass
    return env_vars


class Config:
    """Configuration for the threat modeling scanner."""

    def __init__(
        self,
        org: str = "mbbgrp",
        since_days: int = 30,
        repos_file: Optional[str] = None,
        max_repos: int = 50,
        depth: int = 1,
        workspace_dir: Optional[str] = None,
        output_dir: Optional[str] = None,
        mode: str = "quick",
        dry_run: bool = False,
        no_gitleaks: bool = False,
        no_sbom: bool = False,
        github_token: Optional[str] = None,
    ):
        # Load .env file if present
        env_vars = load_env_file()

        self.org = org
        self.since_days = since_days
        self.repos_file = repos_file
        self.max_repos = max_repos
        self.depth = depth
        self.mode = mode
        self.dry_run = dry_run
        self.no_gitleaks = no_gitleaks
        self.no_sbom = no_sbom

        # GitHub token priority: parameter > .env file > environment variable
        self.github_token = (
            github_token or
            env_vars.get("GITHUB_TOKEN") or
            env_vars.get("TM_GITHUB_TOKEN") or
            os.environ.get("GITHUB_TOKEN") or
            os.environ.get("TM_GITHUB_TOKEN")
        )

        # Set default paths
        home = Path.home()
        self.workspace_dir = Path(workspace_dir or home / "tm-workspace")
        self.output_dir = Path(output_dir or home / "tm-output")

        # Knowledge base paths
        self.script_dir = Path(__file__).parent.parent
        self.kb_keywords_path = self.script_dir / "knowledge-base" / "kb-keywords.yaml"
        self.kb_threats_path = self.script_dir / "knowledge-base" / "kb-threats.yaml"

        # Run timestamp
        self.run_timestamp = datetime.now().strftime("%Y-%m-%d")
        self.run_id = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Output subdirectories
        self.metadata_dir = self.output_dir / "run-metadata"
        self.reports_dir = self.output_dir / "reports"
        self.logs_dir = self.output_dir / "logs"

    def ensure_directories(self):
        """Create all required output directories."""
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)

    def get_repo_report_dir(self, repo_name: str) -> Path:
        """Get the report directory for a specific repo."""
        return self.reports_dir / repo_name / self.run_timestamp

    def get_log_path(self) -> Path:
        """Get the log file path for this run."""
        return self.logs_dir / f"run-{self.run_id}.log"

    def to_dict(self) -> dict:
        """Convert config to dictionary for JSON serialization."""
        return {
            "org": self.org,
            "since_days": self.since_days,
            "repos_file": self.repos_file,
            "max_repos": self.max_repos,
            "depth": self.depth,
            "mode": self.mode,
            "dry_run": self.dry_run,
            "no_gitleaks": self.no_gitleaks,
            "no_sbom": self.no_sbom,
            "github_token": "***REDACTED***" if self.github_token else None,
            "workspace_dir": str(self.workspace_dir),
            "output_dir": str(self.output_dir),
            "run_timestamp": self.run_timestamp,
            "run_id": self.run_id,
            "kb_keywords_path": str(self.kb_keywords_path),
            "kb_threats_path": str(self.kb_threats_path),
        }

    def save_config(self):
        """Save configuration to run-config.json."""
        self.ensure_directories()
        config_path = self.metadata_dir / "run-config.json"
        with open(config_path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
        return config_path

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        """Create Config from dictionary."""
        return cls(
            org=data.get("org", "mbbgrp"),
            since_days=data.get("since_days", 30),
            repos_file=data.get("repos_file"),
            max_repos=data.get("max_repos", 50),
            depth=data.get("depth", 1),
            workspace_dir=data.get("workspace_dir"),
            output_dir=data.get("output_dir"),
            mode=data.get("mode", "quick"),
            dry_run=data.get("dry_run", False),
            no_gitleaks=data.get("no_gitleaks", False),
            no_sbom=data.get("no_sbom", False),
            github_token=data.get("github_token"),
        )
