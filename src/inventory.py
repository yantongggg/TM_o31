"""
GitHub repository inventory module.
"""

import json
import subprocess
import os
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from .config import Config


class RepoInventory:
    """Manages GitHub repository inventory."""

    # Default public GitHub API URL
    DEFAULT_GITHUB_API_URL = "https://api.github.com"

    def __init__(self, config: Config):
        self.config = config
        self.repos: List[Dict] = []

    def _build_api_url(self, endpoint: str) -> str:
        """
        Build the full API URL for the given endpoint.
        
        For public GitHub (default): https://api.github.com/{endpoint}
        For GitHub Enterprise: https://<host>/api/v3/{endpoint}
        
        Args:
            endpoint: The API endpoint path (e.g., "orgs/{org}/repos")
        
        Returns:
            Full API URL string
        """
        base_url = self.config.github_api_url
        
        if not base_url:
            # Default to public GitHub API
            return f"{self.DEFAULT_GITHUB_API_URL}/{endpoint}"
        
        # Normalize the URL
        if not base_url.startswith("http"):
            base_url = f"https://{base_url}"
        base_url = base_url.rstrip("/")
        
        # Check if this is the public GitHub API (already includes api.github.com)
        if "api.github.com" in base_url:
            return f"{base_url}/{endpoint}"
        
        # For GitHub Enterprise, use /api/v3/ prefix
        # Handle case where user might have already included /api/v3
        if "/api/v3" in base_url:
            return f"{base_url}/{endpoint}"
        
        return f"{base_url}/api/v3/{endpoint}"

    def fetch_repos(self) -> List[Dict]:
        """
        Fetch repositories from GitHub organization.
        Tries methods in order:
        1. GitHub API with token (if provided)
        2. GitHub CLI (gh)
        3. GitHub API without token (public repos only)
        """
        # Method 1: GitHub API with token (preferred for private repos)
        if self.config.github_token:
            print(f"Using GitHub API with token for org: {self.config.org}")
            result = self._fetch_repos_via_api(use_token=True)
            if result:
                return result

        # Method 2: GitHub CLI
        if self._is_gh_available():
            print(f"Using GitHub CLI for org: {self.config.org}")
            result = self._fetch_repos_via_gh()
            if result:
                return result

        # Method 3: GitHub API without token (public repos only)
        print(f"Using GitHub API (no token) for org: {self.config.org}")
        return self._fetch_repos_via_api(use_token=False)

    def _is_gh_available(self) -> bool:
        """Check if GitHub CLI is available and authenticated."""
        try:
            result = subprocess.run(
                ["gh", "auth", "status"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _fetch_repos_via_gh(self) -> List[Dict]:
        """Fetch repos using GitHub CLI."""
        try:
            result = subprocess.run(
                ["gh", "repo", "list", self.config.org, "--limit", "1000",
                 "--json", "name,updatedAt,isArchived,isPrivate,primaryLanguage"],
                capture_output=True,
                text=True,
                check=True,
                timeout=60,
            )
            self.repos = json.loads(result.stdout)
            return self.repos
        except (subprocess.CalledProcessError, json.JSONDecodeError, FileNotFoundError, subprocess.TimeoutExpired) as e:
            print(f"GitHub CLI failed: {e}")
            return []

    def _fetch_repos_via_api(self, use_token: bool = True) -> List[Dict]:
        """Fetch repos using GitHub API via curl."""
        try:
            headers = ["Accept: application/vnd.github.v3+json"]
            if use_token and self.config.github_token:
                headers.append(f"Authorization: token {self.config.github_token}")

            # Build the API URL based on configuration
            api_url = self._build_api_url(f"orgs/{self.config.org}/repos?per_page=100&type=all")
            print(f"  DEBUG: API URL = {api_url}")

            # Build curl command with headers
            curl_cmd = ["curl", "-s", "-k"]  # -k to ignore SSL certificate issues with self-signed certs
            for header in headers:
                curl_cmd.extend(["-H", header])
            curl_cmd.append(api_url)

            result = subprocess.run(
                curl_cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )

            # Debug: show response preview
            response_preview = result.stdout[:500] if result.stdout else "(empty)"
            print(f"  DEBUG: Response preview = {response_preview[:200]}...")

            # Check for empty response
            if not result.stdout.strip():
                print(f"GitHub API error: Empty response received")
                return []

            repos = json.loads(result.stdout)
            
            # Check if the response is an error object
            if isinstance(repos, dict):
                error_msg = repos.get("message", "Unknown error")
                print(f"GitHub API error: {error_msg}")
                return []
            
            if not isinstance(repos, list):
                print(f"GitHub API returned unexpected data format: {type(repos)}")
                return []

            # Transform to match gh CLI format
            self.repos = [
                {
                    "name": r["name"],
                    "updatedAt": r.get("pushed_at"),
                    "isArchived": r.get("archived", False),
                    "isPrivate": r.get("private", False),
                    "primaryLanguage": {"name": r.get("language")} if r.get("language") else None,
                }
                for r in repos
            ]
            return self.repos

        except subprocess.TimeoutExpired:
            print("GitHub API request timed out")
            return []
        except subprocess.CalledProcessError as e:
            print(f"GitHub API request failed: {e}")
            return []
        except (json.JSONDecodeError, KeyError) as e:
            print(f"Failed to parse GitHub API response: {e}")
            return []
        except Exception as e:
            print(f"Unexpected error fetching repos: {e}")
            return []

    def load_allowlist(self) -> Optional[List[str]]:
        """Load repository allowlist from file."""
        if not self.config.repos_file:
            return None

        repos_file = Path(self.config.repos_file)
        if not repos_file.exists():
            print(f"Warning: Repos file not found: {repos_file}")
            return None

        with open(repos_file, "r") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]

    def get_filtered_repos(self) -> List[Dict]:
        """
        Get repos filtered by:
        1. Exclude archived
        2. Apply time filter if since_days > 0
        3. Apply allowlist if provided
        """
        filtered = self.repos

        # Exclude archived
        filtered = [r for r in filtered if not r.get("isArchived", False)]

        # Apply time filter
        if self.config.since_days > 0:
            cutoff_date = datetime.now() - timedelta(days=self.config.since_days)
            filtered = [
                r for r in filtered
                if self._parse_date(r.get("updatedAt")) and self._parse_date(r.get("updatedAt")) > cutoff_date
            ]

        # Apply allowlist
        allowlist = self.load_allowlist()
        if allowlist:
            filtered = [r for r in filtered if r["name"] in allowlist]

        return filtered

    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse ISO date string to datetime."""
        if not date_str:
            return None
        try:
            # Handle ISO 8601 format - strip timezone info to make naive datetime
            date_str = date_str.replace("Z", "").replace("+00:00", "").split("+")[0].split("-")[0] if "+" in date_str or date_str.endswith("Z") else date_str
            return datetime.fromisoformat(date_str)
        except (ValueError, AttributeError):
            return None

    def save_inventory(self, repos: List[Dict]):
        """Save repo inventory to JSON."""
        self.config.ensure_directories()
        inventory_path = self.config.metadata_dir / "repo-inventory.json"
        with open(inventory_path, "w") as f:
            json.dump(repos, f, indent=2)
        return inventory_path

    def get_skipped_repos(self, selected: List[str]) -> List[str]:
        """Get list of repos that were not selected."""
        all_repo_names = {r["name"] for r in self.repos}
        selected_names = set(selected)
        return list(all_repo_names - selected_names)
