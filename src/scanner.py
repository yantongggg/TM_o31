"""
Evidence discovery scanner module.
"""

import os
import re
import json
import yaml
from pathlib import Path
from typing import List, Dict, Set, Any
from .config import Config


class EvidenceScanner:
    """Scans repositories for security-relevant evidence."""

    def __init__(self, config: Config):
        self.config = config
        self.kb_keywords = self._load_keywords()
        self.keywords = self._build_keyword_map()

    def _load_keywords(self) -> Dict:
        """Load keyword knowledge base from YAML."""
        try:
            with open(self.config.kb_keywords_path, "r") as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Warning: Could not load keywords KB: {e}")
            return {}

    def _build_keyword_map(self) -> Dict[str, Dict]:
        """Build a flat keyword map for quick lookup."""
        keyword_map = {}
        for category, items in self.kb_keywords.items():
            if category == "file_patterns":
                continue
            if not isinstance(items, list):
                continue
            for item in items:
                keyword = item.get("keyword", "").lower()
                if keyword:
                    keyword_map[keyword] = {
                        "category": item.get("category", category),
                        "priority": item.get("priority", "medium"),
                        "description": item.get("description", ""),
                    }
        return keyword_map

    def scan_repo(self, repo_name: str, repo_path: Path) -> Dict[str, Any]:
        """
        Scan a repository for evidence.

        Returns evidence dictionary with all findings.
        """
        evidence = {
            "repo_name": repo_name,
            "scan_timestamp": self.config.run_timestamp,
            "openapi_files": [],
            "db_migration_files": [],
            "config_files": [],
            "keyword_hits": [],
            "auth_hints": [],
            "db_hints": [],
            "risky_config_hints": [],
            "file_counts": {},
        }

        if not repo_path.exists():
            return evidence

        # Scan files
        for root, dirs, files in os.walk(repo_path):
            # Skip hidden directories and common exclusions
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in {
                "node_modules", "vendor", "target", "build", "dist", ".git"
            }]

            for file in files:
                file_path = Path(root) / file
                rel_path = file_path.relative_to(repo_path)

                # Check file patterns
                self._check_file_patterns(rel_path, file_path, evidence)

                # Scan content for keywords (in quick mode, limit file size)
                try:
                    file_size = file_path.stat().st_size
                    if file_size > 500_000:  # Skip files > 500KB in quick mode
                        continue
                    self._scan_file_content(file_path, rel_path, evidence)
                except Exception:
                    pass

        # Calculate counts
        for key in ["openapi_files", "db_migration_files", "config_files"]:
            evidence["file_counts"][key] = len(evidence[key])

        return evidence

    def _check_file_patterns(self, rel_path: Path, full_path: Path, evidence: Dict):
        """Check if file matches known security patterns."""
        file_str = str(rel_path).lower()

        # OpenAPI/Swagger files
        for pattern in self.kb_keywords.get("file_patterns", {}).get("openapi", []):
            if self._matches_pattern(file_str, pattern):
                evidence["openapi_files"].append(str(rel_path))
                return

        # DB migration files
        for pattern in self.kb_keywords.get("file_patterns", {}).get("db_migration", []):
            if self._matches_pattern(file_str, pattern):
                evidence["db_migration_files"].append(str(rel_path))
                return

        # Config files
        for pattern in self.kb_keywords.get("file_patterns", {}).get("config", []):
            if self._matches_pattern(file_str, pattern):
                evidence["config_files"].append(str(rel_path))
                self._check_config_hints(full_path, rel_path, evidence)
                return

    def _matches_pattern(self, file_str: str, pattern: str) -> bool:
        """Check if file path matches glob pattern."""
        import fnmatch
        return fnmatch.fnmatch(file_str, pattern.lower())

    def _scan_file_content(self, file_path: Path, rel_path: Path, evidence: Dict):
        """Scan file content for keyword hits."""
        try:
            with open(file_path, "r", errors="ignore") as f:
                content = f.read()
                self._find_keywords(content, str(rel_path), evidence)
        except Exception:
            pass

    def _find_keywords(self, content: str, file_path: str, evidence: Dict):
        """Find keywords in content and categorize them."""
        content_lower = content.lower()

        for keyword, info in self.keywords.items():
            if keyword in content_lower:
                # Check if already found in this file to avoid duplicates
                existing = [
                    h for h in evidence["keyword_hits"]
                    if h["file_path"] == file_path and h["keyword"] == keyword
                ]
                if not existing:
                    hit = {
                        "keyword": keyword,
                        "file_path": file_path,
                        "category": info["category"],
                        "priority": info["priority"],
                    }
                    evidence["keyword_hits"].append(hit)

                    # Categorize for easier analysis
                    if info["category"] in ["authn", "authz", "csrf", "session", "credential"]:
                        evidence["auth_hints"].append({
                            "type": keyword,
                            "file_path": file_path,
                            "category": info["category"],
                        })
                    elif info["category"] == "database":
                        evidence["db_hints"].append({
                            "type": keyword,
                            "file_path": file_path,
                        })
                    elif info["category"] == "secret":
                        evidence["risky_config_hints"].append({
                            "type": "secret_reference",
                            "value": keyword,
                            "file_path": file_path,
                        })

    def _check_config_hints(self, file_path: Path, rel_path: Path, evidence: Dict):
        """Check config files for risky patterns."""
        try:
            with open(file_path, "r", errors="ignore") as f:
                content = f.read()
                self._find_keywords(content, str(rel_path), evidence)

                # Check for URL patterns that might contain secrets
                url_patterns = [
                    r"jdbc:[^\\s'\"]+",
                    r"mongodb://[^\\s'\"]+",
                    r"postgres://[^\\s'\"]+",
                    r"mysql://[^\\s'\"]+",
                    r"redis://[^\\s'\"]+",
                ]

                for pattern in url_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        # Redact the URL
                        redacted = self._redact_url(match)
                        evidence["risky_config_hints"].append({
                            "type": "database_url",
                            "value": redacted,
                            "file_path": str(rel_path),
                        })
        except Exception:
            pass

    def _redact_url(self, url: str) -> str:
        """Redact sensitive parts of a URL."""
        # Keep only scheme and host (redacted), truncate the rest
        parsed = re.match(r"^(\w+)://([^/@]+)(?::[^@]+)?@?([^/:]+)", url, re.IGNORECASE)
        if parsed:
            scheme = parsed.group(1)
            host = parsed.group(3)
            return f"{scheme}://<REDACTED>@{host}/..."
        return url[:20] + "..."

    def save_evidence(self, evidence: Dict, repo_name: str):
        """Save evidence to JSON file."""
        report_dir = self.config.get_repo_report_dir(repo_name)
        report_dir.mkdir(parents=True, exist_ok=True)

        evidence_path = report_dir / "evidence.json"
        with open(evidence_path, "w") as f:
            json.dump(evidence, f, indent=2)

        return evidence_path

    def generate_evidence_summary(self, evidence: Dict, repo_name: str) -> str:
        """Generate human-readable evidence summary (Markdown)."""
        lines = [
            f"# Evidence Summary: {repo_name}",
            f"",
            f"**Scan Date:** {evidence.get('scan_timestamp', 'Unknown')}",
            f"**Repository:** {repo_name}",
            f"",
            f"## Overview",
            f"",
            f"| Category | Count |",
            f"|----------|-------|",
            f"| OpenAPI/Swagger Files | {evidence['file_counts'].get('openapi_files', 0)} |",
            f"| DB Migration Files | {evidence['file_counts'].get('db_migration_files', 0)} |",
            f"| Config Files | {evidence['file_counts'].get('config_files', 0)} |",
            f"| Keyword Hits | {len(evidence.get('keyword_hits', []))} |",
            f"| Auth Hints | {len(evidence.get('auth_hints', []))} |",
            f"| Database Hints | {len(evidence.get('db_hints', []))} |",
            f"| Risky Config Hints | {len(evidence.get('risky_config_hints', []))} |",
            f"",
        ]

        # OpenAPI Files
        if evidence.get("openapi_files"):
            lines.extend([
                f"## OpenAPI/Swagger Specifications",
                f"",
            ])
            for f in evidence["openapi_files"][:20]:  # Limit to 20
                lines.append(f"- `{f}`")
            if len(evidence["openapi_files"]) > 20:
                lines.append(f"- ... and {len(evidence['openapi_files']) - 20} more")
            lines.append("")

        # DB Migration Files
        if evidence.get("db_migration_files"):
            lines.extend([
                f"## Database Migration Files",
                f"",
            ])
            for f in evidence["db_migration_files"][:20]:
                lines.append(f"- `{f}`")
            if len(evidence["db_migration_files"]) > 20:
                lines.append(f"- ... and {len(evidence['db_migration_files']) - 20} more")
            lines.append("")

        # Config Files
        if evidence.get("config_files"):
            lines.extend([
                f"## Configuration Files",
                f"",
            ])
            for f in evidence["config_files"][:20]:
                lines.append(f"- `{f}`")
            if len(evidence["config_files"]) > 20:
                lines.append(f"- ... and {len(evidence['config_files']) - 20} more")
            lines.append("")

        # High Priority Keyword Hits
        high_priority = [h for h in evidence.get("keyword_hits", []) if h.get("priority") == "high"]
        if high_priority:
            lines.extend([
                f"## High Priority Keyword Hits",
                f"",
                f"| Keyword | Category | File |",
                f"|---------|----------|------|",
            ])
            for hit in high_priority[:50]:
                # Truncate long file paths
                file_display = hit["file_path"][:60]
                if len(hit["file_path"]) > 60:
                    file_display += "..."
                lines.append(f"| {hit['keyword']} | {hit['category']} | `{file_display}` |")
            if len(high_priority) > 50:
                lines.append(f"| ... | ... | ... and {len(high_priority) - 50} more |")
            lines.append("")

        # Authentication Hints
        if evidence.get("auth_hints"):
            lines.extend([
                f"## Authentication/Authorization Hints",
                f"",
                f"| Type | Category | File |",
                f"|------|----------|------|",
            ])
            for hint in evidence["auth_hints"][:30]:
                file_display = hint["file_path"][:50]
                if len(hint["file_path"]) > 50:
                    file_display += "..."
                lines.append(f"| {hint['type']} | {hint['category']} | `{file_display}` |")
            if len(evidence["auth_hints"]) > 30:
                lines.append(f"| ... | ... | ... and {len(evidence['auth_hints']) - 30} more |")
            lines.append("")

        # Database Hints
        if evidence.get("db_hints"):
            lines.extend([
                f"## Database Technology Hints",
                f"",
            ])
            db_types = set(h["type"] for h in evidence["db_hints"])
            for db_type in sorted(db_types):
                files = [h["file_path"] for h in evidence["db_hints"] if h["type"] == db_type]
                lines.append(f"- **{db_type}** found in {len(files)} file(s)")
                for f in files[:5]:
                    lines.append(f"  - `{f}`")
                if len(files) > 5:
                    lines.append(f"  - ... and {len(files) - 5} more")
            lines.append("")

        # Risky Config Hints
        if evidence.get("risky_config_hints"):
            lines.extend([
                f"## Risky Configuration Hints",
                f"",
                f"> **Note:** Values are redacted for security",
                f"",
                f"| Type | Value (Redacted) | File |",
                f"|------|------------------|------|",
            ])
            for hint in evidence["risky_config_hints"][:30]:
                value_display = hint.get("value", "")[:30]
                file_display = hint["file_path"][:40]
                if len(hint["file_path"]) > 40:
                    file_display += "..."
                lines.append(f"| {hint['type']} | `{value_display}` | `{file_display}` |")
            if len(evidence["risky_config_hints"]) > 30:
                lines.append(f"| ... | ... | ... and {len(evidence['risky_config_hints']) - 30} more |")
            lines.append("")

        return "\n".join(lines)

    def save_evidence_summary(self, evidence: Dict, repo_name: str):
        """Save evidence summary to markdown file."""
        report_dir = self.config.get_repo_report_dir(repo_name)
        report_dir.mkdir(parents=True, exist_ok=True)

        summary_path = report_dir / "evidence-summary.md"
        summary_content = self.generate_evidence_summary(evidence, repo_name)

        with open(summary_path, "w") as f:
            f.write(summary_content)

        return summary_path
