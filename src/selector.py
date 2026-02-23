"""
Repository selection and prioritization module.
"""

import re
from typing import List, Dict, Tuple
from .config import Config


class RepoSelector:
    """Selects and prioritizes repositories for scanning."""

    # Patch-specific signal keywords for scoring
    PATCH_SIGNALS = [
        "pvf", "date", "user", "oracle", "jdbc", "risk", "score",
        "transaction", "hold", "review", "deny", "browser", "agent",
        "case", "management", "popup", "interval", "10m", "30m",
        "auth", "security", "payment", "fraud", "compliance"
    ]

    def __init__(self, config: Config):
        self.config = config

    def select_repos(self, repos: List[Dict]) -> List[Dict]:
        """
        Select repos for scanning based on scoring and max_repos limit.

        Args:
            repos: List of repo dictionaries from inventory

        Returns:
            Selected repos sorted by priority score
        """
        # Score each repo
        scored_repos = []
        for repo in repos:
            score = self._score_repo(repo)
            scored_repos.append({**repo, "priority_score": score})

        # Sort by score descending
        scored_repos.sort(key=lambda r: r["priority_score"], reverse=True)

        # Apply max_repos limit
        selected = scored_repos[:self.config.max_repos]

        return selected

    def _score_repo(self, repo: Dict) -> int:
        """
        Calculate priority score for a repo based on metadata.

        Higher score = more likely to contain patch-specific evidence.

        Scoring factors:
        - Name contains patch signals: +10 per signal
        - Language is Java/backend: +5
        - Is private: +3 (more likely business-critical)
        - Recently updated: +2
        """
        score = 0
        name = repo.get("name", "").lower()
        language = (repo.get("primaryLanguage") or {}).get("name", "").lower()

        # Check name for patch signals
        for signal in self.PATCH_SIGNALS:
            if signal in name:
                score += 10

        # Language bonus
        if language in ["java", "kotlin", "c#", "python", "go", "typescript"]:
            score += 5

        # Private repo bonus
        if repo.get("isPrivate", False):
            score += 3

        # Recent update bonus (already filtered by time, but relative recency helps)
        if repo.get("updatedAt"):
            score += 2

        return score

    def save_selection(self, selected: List[Dict], skipped: List[str]):
        """Save selected and skipped repo lists."""
        self.config.ensure_directories()

        # Save selected repos
        selected_path = self.config.metadata_dir / "selected-repos.txt"
        with open(selected_path, "w") as f:
            for repo in selected:
                f.write(f"{repo['name']} (score: {repo.get('priority_score', 0)})\n")

        # Save skipped repos
        skipped_path = self.config.metadata_dir / "skipped-repos.txt"
        with open(skipped_path, "w") as f:
            for repo_name in skipped:
                f.write(f"{repo_name}\n")

        return selected_path, skipped_path

    def print_selection(self, selected: List[Dict]):
        """Print selection summary."""
        print(f"\n{'='*60}")
        print(f"Selected {len(selected)} repositories for scanning")
        print(f"{'='*60}")
        for i, repo in enumerate(selected, 1):
            score = repo.get("priority_score", 0)
            lang = (repo.get("primaryLanguage") or {}).get("name", "Unknown")
            updated = repo.get("updatedAt", "Unknown")[:10] if repo.get("updatedAt") else "Unknown"
            print(f"{i:3}. {repo['name']:30} [Score: {score:3}] Lang: {lang:15} Updated: {updated}")
        print(f"{'='*60}\n")
