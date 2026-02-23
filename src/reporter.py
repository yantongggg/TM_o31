"""
Threat model report generation module.
"""

import yaml
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime
from .config import Config


class ThreatModelReporter:
    """Generates STRIDE-based threat model reports."""

    def __init__(self, config: Config):
        self.config = config
        self.kb_threats = self._load_threats()

    def _load_threats(self) -> Dict:
        """Load threat knowledge base from YAML."""
        try:
            with open(self.config.kb_threats_path, "r") as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Warning: Could not load threats KB: {e}")
            return {"threats": [], "assets": [], "sensitivity_levels": []}

    def generate_report(
        self,
        repo_name: str,
        evidence: Dict,
        gitleaks_summary: Dict,
        sbom_summary: Dict,
    ) -> str:
        """
        Generate a complete threat model report in Markdown.

        Returns the report content as string.
        """
        lines = [
            self._generate_header(repo_name),
            self._generate_metadata(repo_name),
            self._generate_executive_summary(evidence, gitleaks_summary, sbom_summary),
            self._generate_asset_table(evidence),
            self._generate_threat_table(evidence),
            self._generate_stride_analysis(evidence),
            self._generate_recommendations(evidence, gitleaks_summary),
            self._generate_questions_to_confirm(evidence),
            self._generate_footer(),
        ]

        return "\n".join(lines)

    def _generate_header(self, repo_name: str) -> str:
        """Generate report header."""
        return "\n".join([
            "# Threat Model Report",
            f"",
            f"**Repository:** {repo_name}",
            f"**Organization:** {self.config.org}",
            f"**Report Date:** {self.config.run_timestamp}",
            f"**Report ID:** {self.config.run_id}",
            f"",
        ])

    def _generate_metadata(self, repo_name: str) -> str:
        """Generate scan metadata section."""
        return "\n".join([
            "## Scan Metadata",
            "",
            f"- **Scan Mode:** {self.config.mode}",
            f"- **Since Days:** {self.config.since_days}",
            f"- **Git Depth:** {self.config.depth}",
            f"",
        ])

    def _generate_executive_summary(
        self,
        evidence: Dict,
        gitleaks_summary: Dict,
        sbom_summary: Dict,
    ) -> str:
        """Generate executive summary."""
        findings_count = len(evidence.get("keyword_hits", []))
        secret_findings = gitleaks_summary.get("findings_count", 0)
        package_count = sbom_summary.get("package_count", 0)

        # Determine risk level
        risk_level = "Low"
        high_priority = [h for h in evidence.get("keyword_hits", []) if h.get("priority") == "high"]
        if secret_findings > 0 or len(high_priority) > 10:
            risk_level = "High"
        elif len(high_priority) > 3 or findings_count > 50:
            risk_level = "Medium"

        return "\n".join([
            "## Executive Summary",
            "",
            f"**Overall Risk Level:** {risk_level}",
            "",
            f"- **Total Evidence Findings:** {findings_count}",
            f"- **High-Priority Keywords:** {len(high_priority)}",
            f"- **Secret Findings (gitleaks):** {secret_findings}",
            f"- **Total Packages (SBOM):** {package_count}",
            f"- **OpenAPI Specs Found:** {evidence['file_counts'].get('openapi_files', 0)}",
            f"- **DB Migration Files:** {evidence['file_counts'].get('db_migration_files', 0)}",
            "",
        ])

    def _generate_asset_table(self, evidence: Dict) -> str:
        """Generate asset/flow table with CIA triad."""
        # Map evidence to relevant assets
        lines = [
            "## Asset/Flow Inventory",
            "",
            "| Asset/Flow | Confidentiality | Integrity | Availability | Sensitivity | Evidence | Notes |",
            "|------------|-----------------|-----------|--------------|-------------|----------|-------|",
        ]

        # Define assets based on evidence
        assets = []

        # User data (USERS table found)
        user_hits = [h for h in evidence.get("keyword_hits", []) if h["keyword"] == "users"]
        if user_hits:
            assets.append({
                "name": "User Data (USERS table)",
                "c": "High",
                "i": "High",
                "a": "Medium",
                "sensitivity": "High",
                "evidence": f"{len(user_hits)} reference(s)",
                "notes": "Contains PII - check for encryption",
            })

        # Database assets
        if evidence.get("db_hints"):
            db_types = set(h["type"] for h in evidence["db_hints"])
            for db_type in list(db_types)[:3]:  # Limit to 3
                count = len([h for h in evidence["db_hints"] if h["type"] == db_type])
                assets.append({
                    "name": f"Database ({db_type})",
                    "c": "High",
                    "i": "High",
                    "a": "High",
                    "sensitivity": "High",
                    "evidence": f"{count} reference(s)",
                    "notes": "Check connection string security",
                })

        # API assets
        if evidence.get("openapi_files"):
            assets.append({
                "name": "REST API",
                "c": "Medium",
                "i": "Medium",
                "a": "High",
                "sensitivity": "Medium",
                "evidence": f"{len(evidence['openapi_files'])} spec file(s)",
                "notes": "Review authentication and rate limiting",
            })

        # Risk scoring (patch-specific)
        risk_hits = [h for h in evidence.get("keyword_hits", []) if "risk" in h["keyword"].lower()]
        if risk_hits:
            assets.append({
                "name": "Risk Assessment Engine",
                "c": "Medium",
                "i": "High",
                "a": "High",
                "sensitivity": "High",
                "evidence": f"{len(risk_hits)} reference(s)",
                "notes": "PATCH-SPECIFIC: Verify server-side calculation",
            })

        # Date/time handling (patch-specific)
        date_hits = [h for h in evidence.get("keyword_hits", []) if "date" in h["keyword"].lower() or "interval" in h["keyword"].lower()]
        if date_hits:
            assets.append({
                "name": "Date/Time Validation",
                "c": "Low",
                "i": "High",
                "a": "Medium",
                "sensitivity": "Medium",
                "evidence": f"{len(date_hits)} reference(s)",
                "notes": "PATCH-SPECIFIC: Verify server-side validation",
            })

        # Transaction management (patch-specific)
        tx_hits = [h for h in evidence.get("keyword_hits", []) if "transaction" in h["keyword"].lower() or "hold" in h["keyword"].lower()]
        if tx_hits:
            assets.append({
                "name": "Transaction Processing",
                "c": "Medium",
                "i": "High",
                "a": "High",
                "sensitivity": "High",
                "evidence": f"{len(tx_hits)} reference(s)",
                "notes": "PATCH-SPECIFIC: Verify hold enforcement",
            })

        # Authentication assets
        if evidence.get("auth_hints"):
            auth_types = set(h["type"] for h in evidence["auth_hints"])
            assets.append({
                "name": "Authentication System",
                "c": "Medium",
                "i": "High",
                "a": "High",
                "sensitivity": "High",
                "evidence": f"{len(auth_types)} type(s)",
                "notes": ", ".join(list(auth_types)[:5]),
            })

        # Add default assets if none found
        if not assets:
            assets.append({
                "name": "Application (General)",
                "c": "TBD",
                "i": "TBD",
                "a": "TBD",
                "sensitivity": "TBD",
                "evidence": "No specific assets identified",
                "notes": "Manual review required",
            })

        # Render table rows
        for asset in assets:
            lines.append(
                f"| {asset['name']} | {asset['c']} | {asset['i']} | {asset['a']} | "
                f"{asset['sensitivity']} | {asset['evidence']} | {asset['notes']} |"
            )

        lines.append("")
        return "\n".join(lines)

    def _generate_threat_table(self, evidence: Dict) -> str:
        """Generate threat table based on STRIDE and evidence."""
        lines = [
            "## Threat Analysis",
            "",
            "| Threat | STRIDE Category | Likelihood | Impact | Priority | Evidence | Recommended Controls | Questions to Confirm |",
            "|--------|-----------------|------------|--------|----------|----------|----------------------|----------------------|",
        ]

        # Match threats to evidence
        relevant_threats = []
        for threat in self.kb_threats.get("threats", []):
            # Check if threat keywords match evidence
            threat_keywords = set(k.lower() for k in threat.get("keywords", []))
            evidence_keywords = set(h["keyword"].lower() for h in evidence.get("keyword_hits", []))

            if threat_keywords & evidence_keywords:  # Intersection exists
                relevant_threats.append({
                    "threat": threat,
                    "evidence_count": len(threat_keywords & evidence_keywords),
                })

        # Sort by evidence relevance
        relevant_threats.sort(key=lambda t: t["evidence_count"], reverse=True)

        # Render relevant threats
        for item in relevant_threats[:20]:  # Limit to 20
            threat = item["threat"]
            evidence_desc = f"{item['evidence_count']} keyword match(es)"

            # Format controls and questions for table
            controls = threat.get("recommended_controls", [])[:2]
            controls_str = "; ".join(controls) if controls else "N/A"
            if len(controls_str) > 50:
                controls_str = controls_str[:47] + "..."

            questions = threat.get("questions_to_confirm", [])[:1]
            questions_str = questions[0] if questions else "N/A"
            if len(questions_str) > 50:
                questions_str = questions_str[:47] + "..."

            lines.append(
                f"| {threat['name']} | {threat['stride_category']} | "
                f"{threat['default_likelihood']} | {threat['default_impact']} | TBD | "
                f"{evidence_desc} | {controls_str} | {questions_str} |"
            )

        # Add generic STRIDE threats if no specific matches
        if not relevant_threats:
            generic_threats = [
                ("Injection Attacks", "Tampering", "SQLi, XSS via user input"),
                ("Authentication Bypass", "Spoofing", "Weak session management"),
                ("Data Exposure", "Information Disclosure", "Sensitive data in logs"),
            ]
            for name, category, notes in generic_threats:
                lines.append(
                    f"| {name} | {category} | TBD | TBD | TBD | {notes} | TBD | TBD |"
                )

        lines.append("")
        return "\n".join(lines)

    def _generate_stride_analysis(self, evidence: Dict) -> str:
        """Generate detailed STRIDE analysis."""
        lines = [
            "## STRIDE Analysis",
            "",
        ]

        stride_categories = {
            "Spoofing": [],
            "Tampering": [],
            "Repudiation": [],
            "Information Disclosure": [],
            "Denial of Service": [],
            "Elevation of Privilege": [],
        }

        # Categorize evidence by STRIDE
        for hit in evidence.get("keyword_hits", []):
            category = hit.get("category", "")
            keyword = hit.get("keyword", "")

            if category in ["authn", "credential", "session"]:
                stride_categories["Spoofing"].append(keyword)
            elif category in ["business_logic", "time_interval"]:
                stride_categories["Tampering"].append(keyword)
            elif category in ["logging"]:
                stride_categories["Repudiation"].append(keyword)
            elif category in ["secret", "database"]:
                stride_categories["Information Disclosure"].append(keyword)
            elif category in ["api_endpoint"]:
                stride_categories["Denial of Service"].append(keyword)
            elif category in ["authz"]:
                stride_categories["Elevation of Privilege"].append(keyword)

        # Generate per-category analysis
        for category, keywords in stride_categories.items():
            if keywords:
                lines.extend([
                    f"### {category}",
                    "",
                    f"**Indicators Found ({len(keywords)}):**",
                ])
                unique_keywords = sorted(set(keywords))[:10]
                for kw in unique_keywords:
                    lines.append(f"- {kw}")
                if len(keywords) > 10:
                    lines.append(f"- ... and {len(keywords) - 10} more")
                lines.append("")

        return "\n".join(lines)

    def _generate_recommendations(self, evidence: Dict, gitleaks_summary: Dict) -> str:
        """Generate prioritized recommendations."""
        lines = [
            "## Recommendations",
            "",
        ]

        recommendations = []

        # Critical: Secret findings
        if gitleaks_summary.get("findings_count", 0) > 0:
            recommendations.append({
                "priority": "CRITICAL",
                "title": f"Remove {gitleaks_summary['findings_count']} potential secret(s)",
                "description": "Gitleaks detected potential secrets. Review and rotate any exposed credentials.",
            })

        # High priority keyword findings
        high_priority = [h for h in evidence.get("keyword_hits", []) if h.get("priority") == "high"]
        if high_priority:
            recommendations.append({
                "priority": "HIGH",
                "title": f"Review {len(high_priority)} high-priority code patterns",
                "description": "Patch-specific keywords detected. Verify server-side validation and business logic enforcement.",
            })

        # Database security
        if evidence.get("db_hints"):
            recommendations.append({
                "priority": "HIGH",
                "title": "Review database connection security",
                "description": "Ensure credentials are stored in environment variables or a secret manager. Use least-privilege database accounts.",
            })

        # Authentication
        auth_count = len(evidence.get("auth_hints", []))
        if auth_count > 5:
            recommendations.append({
                "priority": "MEDIUM",
                "title": "Verify authentication/authorization implementation",
                "description": f"{auth_count} auth-related indicators found. Ensure MFA, proper session management, and JWT validation.",
            })

        # API security
        if evidence.get("openapi_files"):
            recommendations.append({
                "priority": "MEDIUM",
                "title": "Review API security controls",
                "description": "Ensure all endpoints have authentication, rate limiting, and input validation.",
            })

        # Logging/audit
        recommendations.append({
            "priority": "LOW",
            "title": "Implement comprehensive audit logging",
            "description": "Log all security-relevant events with user identity, timestamp, and action. Ensure logs are tamper-evident.",
        })

        # Render recommendations
        for rec in recommendations:
            lines.extend([
                f"### [{rec['priority']}] {rec['title']}",
                "",
                rec['description'],
                "",
            ])

        return "\n".join(lines)

    def _generate_questions_to_confirm(self, evidence: Dict) -> str:
        """Generate questions for security reviewers."""
        lines = [
            "## Questions for Security Reviewers",
            "",
            "Please confirm the following during review:",
            "",
        ]

        # Collect relevant questions from matched threats
        questions = []

        for hit in evidence.get("keyword_hits", []):
            for threat in self.kb_threats.get("threats", []):
                if hit["keyword"].lower() in [k.lower() for k in threat.get("keywords", [])]:
                    for q in threat.get("questions_to_confirm", []):
                        if q not in questions:
                            questions.append(q)

        # Add patch-specific questions
        high_priority_keywords = set(h["keyword"] for h in evidence.get("keyword_hits", []) if h.get("priority") == "high")

        if "pvf_date" in high_priority_keywords or any("date" in k.lower() for k in high_priority_keywords):
            questions.append("Is PVF_DATE (and all date fields) validated server-side?")

        if any("risk" in k.lower() for k in high_priority_keywords):
            questions.append("Are risk scores calculated server-side only?")

        if any("hold" in k.lower() or "transaction" in k.lower() for k in high_priority_keywords):
            questions.append("Are transaction holds enforced in the database (not client-side)?")

        if any("10m" in k.lower() or "30m" in k.lower() or "interval" in k.lower() for k in high_priority_keywords):
            questions.append("Are time intervals calculated server-side using system time?")

        if evidence.get("db_hints"):
            questions.append("Are database credentials stored in a secret manager or environment variables?")

        if evidence.get("auth_hints"):
            questions.append("Is MFA implemented for sensitive operations?")
            questions.append("Are JWT signatures validated on every request?")

        # Render questions
        for i, q in enumerate(questions[:20], 1):
            lines.append(f"{i}. {q}")

        if len(questions) > 20:
            lines.append(f"... and {len(questions) - 20} more questions")

        lines.append("")
        return "\n".join(lines)

    def _generate_footer(self) -> str:
        """Generate report footer."""
        return "\n".join([
            "---",
            "",
            f"*Report generated by tm-scan v1.0.0 on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*",
            f"*This is an automated threat model report based on static analysis. Manual review required.*",
            "",
        ])

    def save_report(self, report_content: str, repo_name: str):
        """Save threat model report to file."""
        report_dir = self.config.get_repo_report_dir(repo_name)
        report_dir.mkdir(parents=True, exist_ok=True)

        report_path = report_dir / "threatmodel-report.md"
        with open(report_path, "w") as f:
            f.write(report_content)

        return report_path
