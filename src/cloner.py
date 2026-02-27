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

        # Construct git URL - prefer HTTPS with token for authentication
        git_url = self._build_clone_url(repo_name)

        try:
            if repo_path.exists():
                # Update existing repo
                return self._update_repo(repo_path, repo_name)
            else:
                # Clone new repo
                return self._clone_new_repo(git_url, repo_path, repo_name)
        except Exception as e:
            return False, f"Error: {str(e)}"

    def _build_clone_url(self, repo_name: str) -> str:
        """
        Build the git clone URL for a repository.
        
        Uses HTTPS with token authentication when available, which is more
        reliable than SSH in corporate environments.
        """
        # Determine the host
        if self.config.github_api_url:
            # Extract hostname from API URL
            host = self.config.github_api_url.replace("https://", "").replace("http://", "").split("/")[0].rstrip("/")
        else:
            host = "github.com"
        
        # Use HTTPS with token for authentication
        # Format: https://x-access-token:<token>@<host>/<org>/<repo>.git
        # This is the standard format for GitHub PATs
        if self.config.github_token:
            return f"https://x-access-token:{self.config.github_token}@{host}/{self.config.org}/{repo_name}.git"
        else:
            # Fallback to plain HTTPS (may prompt for credentials or fail for private repos)
            return f"https://{host}/{self.config.org}/{repo_name}.git"

    def _clone_new_repo(self, git_url: str, repo_path: Path, repo_name: str) -> tuple[bool, str]:
        """Clone a new repository with shallow depth."""
        # Build git clone command
        cmd = ["git", "clone"]
        if self.config.depth > 0:
            cmd.extend([f"--depth={self.config.depth}", "--single-branch"])
        cmd.extend([git_url, str(repo_path)])

        result = subprocess.run(
            cmd,
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
