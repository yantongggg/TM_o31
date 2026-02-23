"""
Git repository cloning module.
"""

import subprocess
import os
from pathlib import Path
from typing import List, Dict
from .config import Config


class RepoCloner:
    """Handles git clone operations for repositories."""

    def __init__(self, config: Config):
        self.config = config

    def clone_repo(self, repo_name: str) -> tuple[bool, str]:
        """
        Clone or update a single repository.

        Returns:
            (success, message) tuple
        """
        repo_path = self.config.workspace_dir / repo_name
        git_url = f"git@github.com:{self.config.org}/{repo_name}.git"

        try:
            if repo_path.exists():
                # Update existing repo
                return self._update_repo(repo_path, repo_name)
            else:
                # Clone new repo
                return self._clone_new_repo(git_url, repo_path, repo_name)
        except Exception as e:
            return False, f"Error: {str(e)}"

    def _clone_new_repo(self, git_url: str, repo_path: Path, repo_name: str) -> tuple[bool, str]:
        """Clone a new repository with shallow depth."""
        depth_arg = f"--depth={self.config.depth}" if self.config.depth > 0 else ""

        result = subprocess.run(
            [
                "git", "clone",
                depth_arg,
                "--single-branch",
                git_url,
                str(repo_path)
            ],
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout
        )

        if result.returncode == 0:
            return True, f"Cloned {repo_name}"
        else:
            return False, f"Failed to clone {repo_name}: {result.stderr.strip()}"

    def _update_repo(self, repo_path: Path, repo_name: str) -> tuple[bool, str]:
        """Update an existing repository."""
        try:
            # Fetch latest changes
            result = subprocess.run(
                ["git", "fetch", "origin"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode != 0:
                return False, f"Failed to fetch {repo_name}: {result.stderr.strip()}"

            # Reset to origin/main or origin/master
            for branch in ["main", "master"]:
                result = subprocess.run(
                    ["git", "reset", "--hard", f"origin/{branch}"],
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                if result.returncode == 0:
                    return True, f"Updated {repo_name} (branch: {branch})"

            return False, f"No main/master branch found in {repo_name}"
        except subprocess.TimeoutExpired:
            return False, f"Timeout updating {repo_name}"

    def get_repo_path(self, repo_name: str) -> Path:
        """Get the local path for a repository."""
        return self.config.workspace_dir / repo_name

    def clone_repos(self, repo_names: List[str]) -> Dict[str, tuple[bool, str]]:
        """
        Clone multiple repositories.

        Returns:
            Dict mapping repo_name to (success, message) tuple
        """
        results = {}
        for repo_name in repo_names:
            results[repo_name] = self.clone_repo(repo_name)
        return results
