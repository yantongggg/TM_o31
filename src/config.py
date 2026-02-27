"""
Configuration handling for tm-scan.
"""

import os
import json
import subprocess
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
        pdf_reports: bool = False,
        github_token: Optional[str] = None,
        github_enterprise_url: Optional[str] = None,
        github_api_url: Optional[str] = None,
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
        self.pdf_reports = pdf_reports

        # GitHub token priority: parameter > .env file > environment variable
        self.github_token = (
        local_dir: Optional[str] = None,
        fail_on_critical: bool = False,
            github_token or
            env_vars.get("GITHUB_TOKEN") or
            env_vars.get("TM_GITHUB_TOKEN") or
            os.environ.get("GITHUB_TOKEN") or
            os.environ.get("TM_GITHUB_TOKEN")
        )

        # GitHub API URL priority: parameter > .env file > environment variable > default
        # GITHUB_API_URL is the new preferred variable; GITHUB_ENTERPRISE_URL kept for backward compatibility
        self.github_api_url = (
            github_api_url or
            env_vars.get("GITHUB_API_URL") or
            os.environ.get("GITHUB_API_URL") or
            github_enterprise_url or
        # GitHub token resolution: CLI arg > CI env > gh CLI
        self.github_token = self._resolve_github_token(github_token)
        self.workspace_dir = Path(workspace_dir or home / "tm-workspace")
        self.output_dir = Path(output_dir or home / "tm-output")

        # Knowledge base paths
        self.script_dir = Path(__file__).parent.parent
        self.kb_keywords_path = self.script_dir / "knowledge-base" / "kb-keywords.yaml"
        self.kb_rules_path = self.script_dir / "knowledge-base" / "kb-rules.yaml"
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

        self.local_dir = Path(local_dir).expanduser().resolve() if local_dir else None
        self.fail_on_critical = fail_on_critical
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
            "pdf_reports": self.pdf_reports,
            "github_token": "***REDACTED***" if self.github_token else None,
            "github_api_url": self.github_api_url,
            "github_enterprise_url": self.github_enterprise_url,
            "workspace_dir": str(self.workspace_dir),
            "output_dir": str(self.output_dir),
            "run_timestamp": self.run_timestamp,
            "run_id": self.run_id,
            "kb_keywords_path": str(self.kb_keywords_path),
            "kb_rules_path": str(self.kb_rules_path),
            "kb_threats_path": str(self.kb_threats_path),
            "local_dir": str(self.local_dir) if self.local_dir else None,
            "fail_on_critical": self.fail_on_critical,
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
            pdf_reports=data.get("pdf_reports", False),
            github_token=data.get("github_token"),
            github_enterprise_url=data.get("github_enterprise_url"),
            github_api_url=data.get("github_api_url"),
            local_dir=data.get("local_dir"),
            fail_on_critical=data.get("fail_on_critical", False),
        )

    def _resolve_github_token(self, token_arg: Optional[str]) -> Optional[str]:
        """Resolve GitHub token using hybrid auth (CI env or gh CLI)."""
        if token_arg:
            return token_arg

        if str(os.environ.get("GITHUB_ACTIONS", "")).lower() == "true":
            return os.environ.get("GITHUB_TOKEN")

        try:
            completed = subprocess.run(
                ["gh", "auth", "token"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            token = (completed.stdout or "").strip()
            return token or None
        except Exception:
            print("GitHub CLI token unavailable. Run 'gh auth login' or set GITHUB_TOKEN.")
            return None
