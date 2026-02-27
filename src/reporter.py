"""
Threat model report generation module.
"""

import json
import yaml
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime
from statistics import mean
from .config import Config
from . import __version__


class ThreatModelReporter:
    """Generates STRIDE-based threat model reports."""

    def __init__(self, config: Config):
        self.config = config
        self.kb_threats = self._load_threats()

    def _load_threats(self) -> Dict:
        """Load threat knowledge base from YAML."""
        try:
            with open(self.config.kb_threats_path, "r") as f:
                raw_data = yaml.safe_load(f) or {}
            return self._normalize_threats(raw_data)
        except Exception as e:
            print(f"Warning: Could not load threats KB: {e}")
            return {"threats": [], "assets": [], "sensitivity_levels": []}

    def _normalize_threats(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize threat entries to include extended schema fields."""
        normalized_threats: List[Dict[str, Any]] = []

        for threat in raw_data.get("threats", []) or []:
            if not isinstance(threat, dict):
                continue

            compliance = threat.get("compliance") or {}
            pasta_context = threat.get("pasta_context") or {}
            dread_score = threat.get("dread_score") or {}

            normalized_threats.append({
                **threat,
                "keywords": threat.get("keywords", threat.get("keyword_triggers", [])) or [],
                "trigger_rules": threat.get("trigger_rules", []) or [],
                "recommended_controls": threat.get("recommended_controls", []) or [],
                "questions_to_confirm": threat.get("questions_to_confirm", []) or [],
                "linddun_category": threat.get("linddun_category"),
                "compliance": {
                    "cwe_id": compliance.get("cwe_id"),
                    "owasp_api": compliance.get("owasp_api"),
                },
                "pasta_context": {
                    "threat_actor": pasta_context.get("threat_actor"),
                    "attack_surface": pasta_context.get("attack_surface"),
                    "attack_vector": pasta_context.get("attack_vector"),
                    "business_impact": pasta_context.get("business_impact"),
                },
                "dread_score": self._normalize_dread_score(dread_score),
                "reviewer_message": threat.get("reviewer_message", ""),
                "auto_fix_snippet": threat.get("auto_fix_snippet", ""),
            })

        return {
            "threats": normalized_threats,
            "assets": raw_data.get("assets", []) or [],
            "sensitivity_levels": raw_data.get("sensitivity_levels", []) or [],
        }

    def _normalize_dread_score(self, dread: Dict[str, Any]) -> Dict[str, int]:
        """Coerce DREAD scores to integers with safe defaults."""

        def _to_int(value: Any) -> int:
            try:
                return int(value)
            except (TypeError, ValueError):
                return 0

        fields = [
            "damage",
            "reproducibility",
            "exploitability",
            "affected_users",
            "discoverability",
        ]

        return {field: _to_int(dread.get(field)) for field in fields}

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
        relevant_threats = self._match_threats(evidence)
        lines = [
            self._generate_header(repo_name),
            self._generate_mermaid_dfd(relevant_threats, evidence),
            self._generate_metadata(repo_name),
            self._generate_executive_summary(evidence, gitleaks_summary, sbom_summary),
            self._generate_risk_summary(evidence),
            self._generate_stride_distribution(relevant_threats),
            self._generate_page_break(),
            self._generate_detailed_threat_models(relevant_threats, evidence),
            self._generate_asset_table(evidence),
            self._generate_threat_table(relevant_threats),
            self._generate_stride_analysis(evidence),
            self._generate_recommendations(evidence, gitleaks_summary),
            self._generate_questions_to_confirm(evidence, relevant_threats),
            self._generate_footer(),
        ]

        return "\n".join(lines)

    def _generate_header(self, repo_name: str) -> str:
        """Generate report header."""
        return "\n".join([
            "# Automated Threat Modeling and Security Scan Report",
            f"",
            f"**Repository:** {repo_name}",
            f"**Organization:** {self.config.org}",
            f"**Report Date:** {self.config.run_timestamp}",
            f"**Report Version:** tm-scan v{__version__}",
            f"**Report ID:** {self.config.run_id}",
            f"**Report Classification:** Confidential",
            f"",
        ])

    def _generate_mermaid_dfd(self, relevant_threats: List[Dict[str, Any]], evidence: Dict) -> str:
        """Generate a Mermaid flowchart DFD based on inferred architecture."""
        has_db = bool(evidence.get("db_hints")) or any(
            h.get("category") == "database" for h in evidence.get("keyword_hits", [])
        )
        has_ai = any(
            "ai" in (h.get("category") or "").lower() or "llm" in h.get("keyword", "").lower()
            for h in evidence.get("keyword_hits", [])
        )

        high_threat_ids = []
        for item in relevant_threats:
            threat = item.get("threat", {})
            impact = (threat.get("default_impact") or "").upper()
            dread_score = self._average_dread(threat.get("dread_score", {}))
            if impact in {"HIGH", "CRITICAL"} or dread_score >= 8.0:
                high_threat_ids.append(threat.get("id"))

        node_defs = ["    attacker((Threat Actor))", "    app[Application]"]
        edges = ["    attacker -->|Threats| app"]

        if has_db:
            node_defs.append("    db[(Database)]")
            edges.append("    app -->|Data Flows| db")
        if has_ai:
            node_defs.append("    llm((External LLM))")
            edges.append("    app -->|API Calls| llm")

        high_nodes = []
        if high_threat_ids:
            high_nodes.extend(["app", "attacker"])
            if has_db:
                high_nodes.append("db")
            if has_ai:
                high_nodes.append("llm")

        threat_labels = ",".join(t for t in high_threat_ids if t)
        if threat_labels:
            edges = [edge.replace("|Threats|", f"|{threat_labels}|") for edge in edges]

        class_lines = []
        if high_nodes:
            class_lines.append("    classDef highRisk fill:#ffcccc,stroke:#cc0000;")
            class_lines.append(f"    class {' '.join(high_nodes)} highRisk;")

        lines = ["## Architecture Overview", "", "```mermaid", "flowchart TD"]
        lines.extend(node_defs)
        lines.extend(edges)
        lines.extend(class_lines)
        lines.append("```\n")
        return "\n".join(lines)

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
        rule_findings = len(evidence.get("rule_hits", []))
        secret_findings = gitleaks_summary.get("findings_count", 0)
        package_count = sbom_summary.get("package_count", 0)

        # Determine risk level
        risk_level = "Low"
        high_priority = [h for h in evidence.get("keyword_hits", []) if h.get("priority") == "high"]
        high_severity_rules = [
            r for r in evidence.get("rule_hits", [])
            if r.get("severity") in ["CRITICAL", "HIGH"]
        ]
        if secret_findings > 0 or len(high_priority) > 10 or high_severity_rules:
            risk_level = "High"
        elif len(high_priority) > 3 or findings_count > 50:
            risk_level = "Medium"

        return "\n".join([
            "## Executive Summary",
            "",
            f"**Overall Risk Level:** {risk_level}",
            "",
            f"- **Total Evidence Findings:** {findings_count}",
            f"- **Rule Hits:** {rule_findings}",
            f"- **High-Priority Keywords:** {len(high_priority)}",
            f"- **Secret Findings (gitleaks):** {secret_findings}",
            f"- **Total Packages (SBOM):** {package_count}",
            f"- **OpenAPI Specs Found:** {evidence['file_counts'].get('openapi_files', 0)}",
            f"- **DB Migration Files:** {evidence['file_counts'].get('db_migration_files', 0)}",
            "",
        ])

    def _generate_risk_summary(self, evidence: Dict) -> str:
        """Generate risk level summary based on rule severity."""
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        counts = {level: 0 for level in severity_order}
        for hit in evidence.get("rule_hits", []):
            severity = (hit.get("severity") or "MEDIUM").upper()
            if severity in counts:
                counts[severity] += 1
            else:
                counts["MEDIUM"] += 1

        return "\n".join([
            "### Risk Level Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
            f"| CRITICAL | {counts['CRITICAL']} |",
            f"| HIGH | {counts['HIGH']} |",
            f"| MEDIUM | {counts['MEDIUM']} |",
            f"| LOW | {counts['LOW']} |",
            "",
        ])

    def _generate_stride_distribution(self, relevant_threats: List[Dict[str, Any]]) -> str:
        """Generate STRIDE distribution table from matched threats."""
        stride_order = [
            "Spoofing",
            "Tampering",
            "Repudiation",
            "Information Disclosure",
            "Denial of Service",
            "Elevation of Privilege",
        ]
        counts = {name: 0 for name in stride_order}
        for item in relevant_threats:
            category = item["threat"].get("stride_category")
            if category in counts:
                counts[category] += 1

        lines = [
            "### STRIDE Distribution",
            "",
            "| STRIDE Category | Count |",
            "|-----------------|-------|",
        ]
        for name in stride_order:
            lines.append(f"| {name} | {counts[name]} |")
        lines.append("")
        return "\n".join(lines)

    def _generate_page_break(self) -> str:
        """Insert a page break marker for PDF rendering."""
        return "<div class=\"page-break\"></div>\n"

    def _match_threats(self, evidence: Dict) -> List[Dict[str, Any]]:
        """Match threats to evidence using keyword and rule triggers."""
        relevant_threats = []
        rule_hit_ids = {h.get("rule_id") for h in evidence.get("rule_hits", [])}
        evidence_keywords = set(h["keyword"].lower() for h in evidence.get("keyword_hits", []))

        for threat in self.kb_threats.get("threats", []):
            threat_keywords = set(k.lower() for k in threat.get("keywords", []))
            trigger_rules = set(threat.get("trigger_rules", []) or [])

            keyword_hits = threat_keywords & evidence_keywords
            rule_hits = trigger_rules & rule_hit_ids

            if keyword_hits or rule_hits:
                relevant_threats.append({
                    "threat": threat,
                    "keyword_hits": keyword_hits,
                    "rule_hits": rule_hits,
                    "evidence_count": len(keyword_hits) + len(rule_hits),
                })

        relevant_threats.sort(key=lambda t: t["evidence_count"], reverse=True)
        return relevant_threats

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

    def _generate_threat_table(self, relevant_threats: List[Dict[str, Any]]) -> str:
        """Generate threat table based on STRIDE and evidence."""
        lines = [
            "## Threat Analysis",
            "",
            "| Threat | STRIDE Category | Likelihood | Impact | Priority | Evidence | Recommended Controls | Questions to Confirm |",
            "|--------|-----------------|------------|--------|----------|----------|----------------------|----------------------|",
        ]

        # Render relevant threats
        for item in relevant_threats[:20]:  # Limit to 20
            threat = item["threat"]
            keyword_hit_count = len(item.get("keyword_hits", []))
            rule_hit_count = len(item.get("rule_hits", []))
            evidence_desc = f"keywords: {keyword_hit_count}, rules: {rule_hit_count}"

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

    def _generate_detailed_threat_models(
        self,
        relevant_threats: List[Dict[str, Any]],
        evidence: Dict,
    ) -> str:
        """Generate detailed threat model sections."""
        lines = [
            "## Detailed Threat Models",
            "",
        ]

        if not relevant_threats:
            lines.extend([
                "No rule- or keyword-based threat matches were detected.",
                "",
            ])
            return "\n".join(lines)

        rule_hits_by_id = {}
        for hit in evidence.get("rule_hits", []):
            rule_id = hit.get("rule_id")
            if not rule_id:
                continue
            rule_hits_by_id.setdefault(rule_id, []).append(hit)

        for item in relevant_threats[:10]:
            threat = item["threat"]
            trigger_rules = threat.get("trigger_rules", []) or []
            rule_hits = []
            for rule_id in trigger_rules:
                rule_hits.extend(rule_hits_by_id.get(rule_id, []))

            cwe_refs = ", ".join(threat.get("cwe_references", []) or []) or "N/A"

            lines.extend([
                f"### [{threat['id']}] {threat['name']}",
                f"**STRIDE Category:** {threat.get('stride_category', 'TBD')} | "
                f"**Default Impact:** {threat.get('default_impact', 'TBD')} | "
                f"**CWE References:** {cwe_refs}",
                "",
                "**Description:**",
                threat.get("description", "N/A"),
                "",
                "**Evidence:**",
            ])

            if rule_hits:
                lines.extend([
                    "| File Path | Trigger Rule | Line |",
                    "|----------|--------------|------|",
                ])
                for hit in rule_hits[:20]:
                    lines.append(
                        f"| {hit['file_path']} | {hit['rule_id']} | N/A |"
                    )
                if len(rule_hits) > 20:
                    lines.append(f"| ... | ... | ... ({len(rule_hits) - 20} more) |")
            else:
                lines.append("No rule-based evidence captured.")

            lines.extend([
                "",
                "**Recommended Controls:**",
            ])
            for control in threat.get("recommended_controls", [])[:4]:
                lines.append(f"- {control}")

            lines.extend([
                "",
                "**Questions for Review:**",
            ])
            for question in threat.get("questions_to_confirm", [])[:4]:
                lines.append(f"- {question}")
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

    def _generate_questions_to_confirm(self, evidence: Dict, relevant_threats: List[Dict[str, Any]]) -> str:
        """Generate questions for security reviewers."""
        lines = [
            "## Questions for Security Reviewers",
            "",
            "Please confirm the following during review:",
            "",
        ]

        # Collect relevant questions from matched threats
        questions = []

        matched_rule_ids = {h.get("rule_id") for h in evidence.get("rule_hits", [])}

        for hit in evidence.get("keyword_hits", []):
            for threat in self.kb_threats.get("threats", []):
                if hit["keyword"].lower() in [k.lower() for k in threat.get("keywords", [])]:
                    for q in threat.get("questions_to_confirm", []):
                        if q not in questions:
                            questions.append(q)

        for item in relevant_threats:
            threat = item["threat"]
            trigger_rules = set(threat.get("trigger_rules", []) or [])
            if trigger_rules & matched_rule_ids:
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

    def generate_sarif(self, repo_name: str, relevant_threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate SARIF representation for matched threats."""

        def rule_id(threat: Dict[str, Any]) -> str:
            compliance = threat.get("compliance") or {}
            cwe_id = compliance.get("cwe_id")
            return str(cwe_id) if cwe_id else threat.get("id", "TM-UNKNOWN")

        rules = []
        rule_ids = set()
        results = []

        for item in relevant_threats:
            threat = item.get("threat", {})
            rid = rule_id(threat)
            if rid not in rule_ids:
                rules.append({
                    "id": rid,
                    "name": threat.get("name"),
                    "shortDescription": {"text": threat.get("description", "")},
                    "helpUri": None,
                })
                rule_ids.add(rid)

            dread_score = self._average_dread(threat.get("dread_score", {}))
            level = "error" if dread_score >= 8.0 else "warning"

            results.append({
                "ruleId": rid,
                "level": level,
                "message": {"text": threat.get("reviewer_message") or threat.get("description", "")},
                "properties": {
                    "threatId": threat.get("id"),
                    "strideCategory": threat.get("stride_category"),
                    "linddunCategory": threat.get("linddun_category"),
                    "dreadScore": dread_score,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": repo_name},
                        }
                    }
                ],
            })

        sarif = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "tm-scan",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }

        return sarif

    def save_sarif(self, sarif_content: Dict[str, Any], repo_name: str):
        """Save SARIF output to file."""
        report_dir = self.config.get_repo_report_dir(repo_name)
        report_dir.mkdir(parents=True, exist_ok=True)

        sarif_path = report_dir / "threatmodel-report.sarif"
        with open(sarif_path, "w") as f:
            json.dump(sarif_content, f, indent=2)

        return sarif_path

    def _average_dread(self, dread: Dict[str, Any]) -> float:
        fields = [
            "damage",
            "reproducibility",
            "exploitability",
            "affected_users",
            "discoverability",
        ]
        scores = []
        for key in fields:
            try:
                scores.append(int(dread.get(key, 0)))
            except (TypeError, ValueError):
                scores.append(0)
        return mean(scores) if scores else 0.0
