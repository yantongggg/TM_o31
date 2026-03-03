"""Threat model report generation module."""

import json
from datetime import datetime
from statistics import mean
from typing import Any, Dict, List, Set, Tuple

import yaml

from . import __version__
from .config import Config


class ThreatModelReporter:
    """Generates deterministic, evidence-driven threat model reports."""

    SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

    def __init__(self, config: Config):
        self.config = config
        self.kb_threats = self._load_threats()

    def _load_threats(self) -> Dict[str, Any]:
        """Load and normalize threat knowledge base."""
        try:
            with open(self.config.kb_threats_path, "r") as file:
                raw_data = yaml.safe_load(file) or {}
            return self._normalize_threats(raw_data)
        except Exception as exc:
            print(f"Warning: Could not load threats KB: {exc}")
            return {"threats": [], "assets": [], "sensitivity_levels": []}

    def _normalize_threats(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize threat entries to guarantee a stable schema."""
        normalized: List[Dict[str, Any]] = []
        for threat in raw_data.get("threats", []) or []:
            if not isinstance(threat, dict):
                continue

            compliance = threat.get("compliance") or {}
            pasta_context = threat.get("pasta_context") or {}
            normalized.append({
                "id": threat.get("id", "TM-UNKNOWN"),
                "name": threat.get("name", "Unnamed Threat"),
                "description": threat.get("description", "No description available."),
                "stride_category": threat.get("stride_category", "Unknown"),
                "linddun_category": threat.get("linddun_category", "Unknown"),
                "default_likelihood": threat.get("default_likelihood", "Medium"),
                "default_impact": threat.get("default_impact", "Medium"),
                "keywords": threat.get("keywords", threat.get("keyword_triggers", [])) or [],
                "trigger_rules": threat.get("trigger_rules", []) or [],
                "compliance": {
                    "cwe_id": compliance.get("cwe_id", "Unknown"),
                    "owasp_api": compliance.get("owasp_api", "Unknown"),
                },
                "dread_score": self._normalize_dread_score(threat.get("dread_score") or {}),
                "pasta_context": {
                    "threat_actor": pasta_context.get("threat_actor", "Unknown actor"),
                    "attack_surface": pasta_context.get("attack_surface", "Unknown surface"),
                    "attack_vector": pasta_context.get("attack_vector", "Unknown vector"),
                    "business_impact": pasta_context.get("business_impact", "Business impact requires manual validation."),
                },
                "recommended_controls": threat.get("recommended_controls", []) or [],
                "questions_to_confirm": threat.get("questions_to_confirm", []) or [],
                "reviewer_message": threat.get("reviewer_message", ""),
            })

        normalized.sort(key=lambda item: item.get("id", ""))
        return {
            "threats": normalized,
            "assets": raw_data.get("assets", []) or [],
            "sensitivity_levels": raw_data.get("sensitivity_levels", []) or [],
        }

    def _normalize_dread_score(self, dread: Dict[str, Any]) -> Dict[str, int]:
        """Coerce DREAD fields to integers with safe defaults."""

        def safe_int(value: Any) -> int:
            try:
                return int(value)
            except (TypeError, ValueError):
                return 0

        fields = ["damage", "reproducibility", "exploitability", "affected_users", "discoverability"]
        return {field: safe_int(dread.get(field, 0)) for field in fields}

    def generate_report(
        self,
        repo_name: str,
        evidence: Dict[str, Any],
        gitleaks_summary: Dict[str, Any],
        sbom_summary: Dict[str, Any],
    ) -> str:
        """Generate a deterministic, sectioned Markdown report."""
        relevant_threats = self._match_threats(evidence)

        lines: List[str] = []
        lines.extend(self._generate_header(repo_name))
        lines.extend(self._generate_scan_metadata(evidence, gitleaks_summary, sbom_summary))
        lines.extend(self._generate_system_context(evidence))
        lines.extend(self._generate_architecture_model(evidence, relevant_threats))
        lines.extend(self._generate_data_flow_matrix(evidence))
        lines.extend(self._generate_5d_threat_analysis(relevant_threats, evidence))
        lines.extend(self._generate_pasta_analysis(relevant_threats, evidence))
        lines.extend(self._generate_risk_summary_quality_gate(relevant_threats))
        lines.extend(self._generate_footer())

        return "\n".join(lines)

    def _generate_header(self, repo_name: str) -> List[str]:
        return [
            "# Automated Threat Modeling and Security Scan Report",
            "",
            f"**Repository:** {repo_name}",
            f"**Organization:** {self.config.org}",
            f"**Report Date:** {self.config.run_timestamp}",
            f"**Report Version:** tm-scan v{__version__}",
            f"**Report ID:** {self.config.run_id}",
            "**Report Classification:** Confidential",
            "",
        ]

    def _generate_scan_metadata(
        self,
        evidence: Dict[str, Any],
        gitleaks_summary: Dict[str, Any],
        sbom_summary: Dict[str, Any],
    ) -> List[str]:
        keyword_hits = evidence.get("keyword_hits", []) or []
        rule_hits = evidence.get("rule_hits", []) or []
        sast_hits = evidence.get("sast_hits", []) or []
        file_counts = evidence.get("file_counts", {}) or {}

        return [
            "## Scan Metadata",
            "",
            f"- **Scan Mode:** {self.config.mode}",
            f"- **Since Days:** {self.config.since_days}",
            f"- **Git Depth:** {self.config.depth}",
            f"- **Keyword Hits:** {len(keyword_hits)}",
            f"- **Rule Hits:** {len(rule_hits)}",
            f"- **SAST Hits (line-level):** {len(sast_hits)}",
            f"- **OpenAPI Specs Found:** {file_counts.get('openapi_files', len(evidence.get('openapi_files', []) or []))}",
            f"- **DB Migration Files:** {file_counts.get('db_migration_files', len(evidence.get('db_migration_files', []) or []))}",
            f"- **Secret Findings (gitleaks):** {(gitleaks_summary or {}).get('findings_count', 0)}",
            f"- **Total Packages (SBOM):** {(sbom_summary or {}).get('package_count', 0)}",
            "",
        ]

    def _match_threats(self, evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Match threats using trigger rules and keywords; include concrete evidence rows."""
        keyword_hits = evidence.get("keyword_hits", []) or []
        rule_hits = evidence.get("rule_hits", []) or []
        sast_hits = evidence.get("sast_hits", []) or []

        evidence_keywords = {str(hit.get("keyword", "")).lower() for hit in keyword_hits if hit.get("keyword")}
        evidence_rule_ids = {str(hit.get("rule_id", "")) for hit in rule_hits if hit.get("rule_id")}

        matched: List[Dict[str, Any]] = []
        for threat in self.kb_threats.get("threats", []):
            threat_keywords = {str(item).lower() for item in (threat.get("keywords") or []) if item}
            trigger_rules = {str(item) for item in (threat.get("trigger_rules") or []) if item}

            matched_keywords = sorted(threat_keywords & evidence_keywords)
            matched_rule_ids = sorted(trigger_rules & evidence_rule_ids)

            matched_rule_hits = [
                hit for hit in rule_hits
                if str(hit.get("rule_id", "")) in matched_rule_ids
            ]
            matched_keyword_hits = [
                hit for hit in keyword_hits
                if str(hit.get("keyword", "")).lower() in matched_keywords
            ]
            matched_sast_hits = [
                hit for hit in sast_hits
                if str(hit.get("rule_id", "")) in matched_rule_ids
            ]

            if matched_keywords or matched_rule_ids:
                matched.append({
                    "threat": threat,
                    "matched_keywords": matched_keywords,
                    "matched_rule_ids": matched_rule_ids,
                    "matched_keyword_hits": matched_keyword_hits,
                    "matched_rule_hits": matched_rule_hits,
                    "matched_sast_hits": matched_sast_hits,
                    "evidence_count": len(matched_keyword_hits) + len(matched_rule_hits) + len(matched_sast_hits),
                })

        matched.sort(
            key=lambda item: (
                -item.get("evidence_count", 0),
                -self._average_dread(item.get("threat", {}).get("dread_score", {})),
                item.get("threat", {}).get("id", ""),
            )
        )
        return matched

    def _generate_system_context(self, evidence: Dict[str, Any]) -> List[str]:
        """Generate mandatory SYSTEM CONTEXT section."""
        auth_hints = evidence.get("auth_hints", []) or []
        db_hints = evidence.get("db_hints", []) or []
        keyword_hits = evidence.get("keyword_hits", []) or []
        openapi_files = evidence.get("openapi_files", []) or []

        actors: List[str] = ["External Attacker", "Unauthenticated Internet User"]
        if auth_hints:
            actors.append("Authenticated User")
            actors.append("Identity Provider / Session Authority")
        if openapi_files:
            actors.append("API Consumer (Client App / Partner Service)")
        actors = sorted(set(actors))

        db_types = sorted({str(hit.get("type", "database")) for hit in db_hints if hit.get("type")})
        secret_hits = [hit for hit in keyword_hits if str(hit.get("category", "")).lower() == "secret"]
        pii_keywords = {"email", "ssn", "phone", "users", "password", "token", "jwt"}
        pii_hits = [hit for hit in keyword_hits if str(hit.get("keyword", "")).lower() in pii_keywords]

        assets: List[str] = []
        if pii_hits:
            assets.append(f"User/PII Data (High sensitivity) - {len(pii_hits)} evidence indicator(s)")
        if secret_hits:
            assets.append(f"Credentials/Secrets (High sensitivity) - {len(secret_hits)} evidence indicator(s)")
        if db_types:
            assets.append(f"Datastores ({', '.join(db_types)}) (High sensitivity)")
        if not assets:
            assets.append("Application business data (Sensitivity: Medium, pending manual classification)")

        entry_points: List[str] = []
        for path in sorted(set(str(item) for item in openapi_files))[:8]:
            entry_points.append(f"OpenAPI-described endpoint surface from `{path}`")

        auth_types = sorted({str(hit.get("type", "")) for hit in auth_hints if hit.get("type")})
        if auth_types:
            entry_points.append(f"Authentication-related endpoints/signals: {', '.join(auth_types[:8])}")
        if not entry_points:
            entry_points.append("Application source entry points detected via static code scan (manual endpoint confirmation required)")

        assumptions = [
            "Internet -> Application boundary is untrusted by default.",
            "Application -> Data store boundary is privileged and must enforce least privilege.",
            "Application -> External services boundary assumes network egress controls and TLS.",
            "All client-supplied business fields are treated as untrusted until server validation.",
        ]

        lines = ["## SYSTEM CONTEXT", "", "### Actors"]
        lines.extend([f"- {actor}" for actor in actors])
        lines.extend(["", "### Assets"])
        lines.extend([f"- {asset}" for asset in assets])
        lines.extend(["", "### Entry points"])
        lines.extend([f"- {entry}" for entry in entry_points])
        lines.extend(["", "### Trust boundaries & Assumptions"])
        lines.extend([f"- {item}" for item in assumptions])
        lines.append("")
        return lines

    def _generate_architecture_model(
        self,
        evidence: Dict[str, Any],
        relevant_threats: List[Dict[str, Any]],
    ) -> List[str]:
        """Generate mandatory ARCHITECTURE MODEL section with Mermaid Flowchart TD."""
        has_db = bool(evidence.get("db_hints"))
        has_auth = bool(evidence.get("auth_hints"))
        has_openapi = bool(evidence.get("openapi_files"))

        high_risk = any(self._classify_risk_level(item.get("threat", {}), item.get("evidence_count", 0)) in {"Critical", "High"}
                        for item in relevant_threats[:5])
        medium_risk = not high_risk and bool(relevant_threats)

        lines = [
            "## ARCHITECTURE MODEL",
            "",
            "```mermaid",
            "flowchart TD",
            "    subgraph z1[Untrusted Zone]",
            "        attacker((Threat Actor))",
            "        client[Web/Mobile Client]",
            "    end",
            "",
            "    subgraph z2[Application Trust Zone]",
            "        api[API Gateway / Controller]",
            "        svc[Business Service Layer]",
            "    end",
            "",
            "    subgraph z3[Data Trust Zone]",
            "        db[(Primary Database)]",
            "        logs[(Audit / App Logs)]",
            "    end",
            "",
            "    subgraph z4[External Systems]",
            "        idp[(Identity Provider)]",
            "        ext[(Third-Party Service)]",
            "    end",
            "",
            "    attacker -->|HTTPS 443 / unauthenticated probes| api",
            "    client -->|HTTPS 443 / bearer session| api",
            "    api -->|mTLS internal / service auth| svc",
            "    svc -->|SQL/TCP 5432 / DB credentials| db",
            "    svc -->|JSON over HTTPS / OAuth2| ext",
            "    api -->|OIDC/OAuth2 token validation| idp",
            "    svc -->|Structured event logs| logs",
        ]

        if not has_auth:
            lines.append("    api -.->|Auth controls require verification| idp")
        if not has_openapi:
            lines.append("    client -.->|Endpoint inventory inferred from code| api")
        if not has_db:
            lines.append("    svc -.->|Data store evidence limited; validate architecture manually| db")

        lines.extend([
            "",
            "    classDef highRisk fill:#ffcccc,stroke:#cc0000;",
            "    classDef mediumRisk fill:#ffe6cc,stroke:#cc7a00;",
        ])

        if high_risk:
            lines.append("    class api highRisk;")
            lines.append("    class svc highRisk;")
            lines.append("    class db highRisk;")
            lines.append("    class attacker highRisk;")
        elif medium_risk:
            lines.append("    class api mediumRisk;")
            lines.append("    class svc mediumRisk;")
            lines.append("    class db mediumRisk;")

        lines.extend(["```", ""])
        return lines

    def _generate_data_flow_matrix(self, evidence: Dict[str, Any]) -> List[str]:
        """Generate mandatory DATA FLOW MATRIX section."""
        rows: List[Tuple[str, str, str, str, str, str]] = [
            ("External User", "API Gateway / Controller", "Credentials + Request Payload", "HTTPS", "Session/JWT", "Y"),
            ("API Gateway / Controller", "Business Service Layer", "Validated Domain Request", "Internal RPC/HTTP", "Service Identity", "N"),
            ("Business Service Layer", "Primary Database", "PII/Business Records", "SQL/TCP", "DB Credential", "Y"),
            ("Business Service Layer", "Audit / App Logs", "Security Events", "Structured Logging", "N/A", "N"),
        ]

        if evidence.get("auth_hints"):
            rows.append(("API Gateway / Controller", "Identity Provider", "Token Introspection / Claims", "HTTPS", "OAuth2/OIDC", "Y"))
        if evidence.get("openapi_files"):
            rows.append(("API Consumer", "API Gateway / Controller", "OpenAPI-defined Requests", "HTTPS", "API Key/JWT", "Y"))
        if evidence.get("risky_config_hints"):
            rows.append(("Application Config", "Business Service Layer", "Connection Strings / Secrets", "Env/File", "Runtime Process Access", "N"))

        rows = sorted(set(rows), key=lambda item: (item[0], item[1], item[2]))

        lines = [
            "## DATA FLOW MATRIX",
            "",
            "| Source | Destination | Data type | Protocol | Authentication | Crosses trust boundary (Y/N) |",
            "|--------|-------------|-----------|----------|----------------|-------------------------------|",
        ]
        for source, destination, data_type, protocol, auth, crossing in rows:
            lines.append(f"| {source} | {destination} | {data_type} | {protocol} | {auth} | {crossing} |")
        lines.append("")
        return lines

    def _generate_5d_threat_analysis(
        self,
        relevant_threats: List[Dict[str, Any]],
        evidence: Dict[str, Any],
    ) -> List[str]:
        """Generate mandatory 5-D THREAT ANALYSIS section."""
        lines: List[str] = ["## 5-D THREAT ANALYSIS (STRIDE + LINDDUN + CWE + DREAD)", ""]

        if not relevant_threats:
            lines.extend([
                "No knowledge-base threats matched current rule/keyword evidence.",
                "",
            ])
            return lines

        for item in relevant_threats:
            threat = item.get("threat", {})
            threat_id = threat.get("id", "TM-UNKNOWN")
            threat_name = threat.get("name", "Unnamed Threat")
            cwe_ref = (threat.get("compliance") or {}).get("cwe_id", "Unknown")
            dread = threat.get("dread_score", {}) or {}
            dread_avg = self._average_dread(dread)
            evidence_rows = self._build_threat_evidence_rows(item, evidence)

            pasta_context = threat.get("pasta_context", {}) or {}
            scenario = (
                f"Preconditions: {pasta_context.get('threat_actor', 'Unknown actor')} has access to "
                f"{pasta_context.get('attack_surface', 'the application surface')}. "
                f"Exploitation: {pasta_context.get('attack_vector', 'a relevant weakness')} is abused using observed code evidence."
            )
            business_impact = pasta_context.get("business_impact", "Business impact requires manual confirmation.")

            lines.extend([
                f"### [{threat_id}] {threat_name}",
                f"**STRIDE & LINDDUN Categories:** {threat.get('stride_category', 'Unknown')} | {threat.get('linddun_category', 'Unknown')}",
                f"**CWE Reference:** {cwe_ref}",
                (
                    f"**DREAD Score Breakdown:** Damage={dread.get('damage', 0)}, "
                    f"Reproducibility={dread.get('reproducibility', 0)}, "
                    f"Exploitability={dread.get('exploitability', 0)}, "
                    f"Affected Users={dread.get('affected_users', 0)}, "
                    f"Discoverability={dread.get('discoverability', 0)} (Avg={dread_avg:.2f})"
                ),
                "",
                "**Attack Scenario & Business Impact (PASTA Context)**",
                f"- {scenario}",
                f"- Business Impact: {business_impact}",
                "",
                "**Evidence Table**",
                "| File Path | Line Number | Rule/Keyword | Severity |",
                "|-----------|-------------|--------------|----------|",
            ])

            if evidence_rows:
                for row in evidence_rows:
                    lines.append(
                        f"| {row['file_path']} | {row['line_number']} | {row['trigger']} | {row['severity']} |"
                    )
            else:
                lines.append("| No direct evidence rows found for this threat | - | - | - |")

            lines.extend(["", "**Recommended Technical Mitigations (Implementable)**"])
            controls = threat.get("recommended_controls", []) or []
            if controls:
                for control in controls[:8]:
                    lines.append(f"- {control}")
            else:
                lines.append("- Add targeted validation, authorization, and secure defaults based on this threat class.")

            lines.append("")

        return lines

    def _build_threat_evidence_rows(
        self,
        matched_threat: Dict[str, Any],
        evidence: Dict[str, Any],
    ) -> List[Dict[str, str]]:
        """Build deterministic evidence rows with line-level preference from sast_hits."""
        rule_hits = matched_threat.get("matched_rule_hits", []) or []
        keyword_hits = matched_threat.get("matched_keyword_hits", []) or []
        sast_hits = matched_threat.get("matched_sast_hits", []) or []

        sast_by_rule_file: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        for hit in sast_hits:
            key = (str(hit.get("rule_id", "")), str(hit.get("file_path", "")))
            sast_by_rule_file.setdefault(key, []).append(hit)

        rows: List[Dict[str, str]] = []
        seen: Set[Tuple[str, str, str, str]] = set()

        for hit in sorted(sast_hits, key=lambda item: (
            str(item.get("file_path", "")),
            self._safe_int(item.get("line"), default=10**9),
            str(item.get("rule_id", "")),
        )):
            file_path = str(hit.get("file_path", "unknown"))
            line_number = str(self._safe_int(hit.get("line"), default=0))
            if line_number == "0":
                line_number = "unknown"
            trigger = str(hit.get("rule_id", "unknown"))
            severity = self._normalize_severity(hit.get("severity", "MEDIUM"))
            row_key = (file_path, line_number, trigger, severity)
            if row_key not in seen:
                rows.append({
                    "file_path": file_path,
                    "line_number": line_number,
                    "trigger": trigger,
                    "severity": severity,
                })
                seen.add(row_key)

        for hit in sorted(rule_hits, key=lambda item: (str(item.get("file_path", "")), str(item.get("rule_id", "")))):
            file_path = str(hit.get("file_path", "unknown"))
            rule_id = str(hit.get("rule_id", "unknown"))
            severity = self._normalize_severity(hit.get("severity", "MEDIUM"))

            linked_sast = sast_by_rule_file.get((rule_id, file_path), [])
            if linked_sast:
                for sast_hit in sorted(linked_sast, key=lambda item: self._safe_int(item.get("line"), default=10**9)):
                    line_number = str(self._safe_int(sast_hit.get("line"), default=0))
                    if line_number == "0":
                        line_number = "unknown"
                    row_key = (file_path, line_number, rule_id, severity)
                    if row_key not in seen:
                        rows.append({
                            "file_path": file_path,
                            "line_number": line_number,
                            "trigger": rule_id,
                            "severity": severity,
                        })
                        seen.add(row_key)
            else:
                row_key = (file_path, "unknown", rule_id, severity)
                if row_key not in seen:
                    rows.append({
                        "file_path": file_path,
                        "line_number": "unknown",
                        "trigger": rule_id,
                        "severity": severity,
                    })
                    seen.add(row_key)

        for hit in sorted(keyword_hits, key=lambda item: (str(item.get("file_path", "")), str(item.get("keyword", "")))):
            file_path = str(hit.get("file_path", "unknown"))
            keyword = str(hit.get("keyword", "unknown"))
            priority = str(hit.get("priority", "medium"))
            severity = self._priority_to_severity(priority)
            row_key = (file_path, "unknown", keyword, severity)
            if row_key not in seen:
                rows.append({
                    "file_path": file_path,
                    "line_number": "unknown",
                    "trigger": keyword,
                    "severity": severity,
                })
                seen.add(row_key)

        rows.sort(
            key=lambda row: (
                row["file_path"],
                self._line_sort_value(row["line_number"]),
                -self.SEVERITY_ORDER.get(row["severity"], 2),
                row["trigger"],
            )
        )
        return rows

    def _generate_pasta_analysis(
        self,
        relevant_threats: List[Dict[str, Any]],
        evidence: Dict[str, Any],
    ) -> List[str]:
        """Generate mandatory PASTA ANALYSIS section with attack path Mermaid."""
        lines: List[str] = ["## PASTA ANALYSIS (Attack Trees & Paths)", ""]

        top_threats = relevant_threats[:3]
        weakness_labels: List[str] = []
        for item in top_threats:
            threat = item.get("threat", {})
            weakness_labels.append(f"{threat.get('id', 'TM-UNKNOWN')} ({threat.get('name', 'Threat')})")

        if not weakness_labels:
            weakness_labels = ["No high-confidence threat chains matched; manual attack path exercise required"]

        preconditions = "External attacker can reach API entry points and submit crafted inputs"
        exploited = "; ".join(weakness_labels[:3])
        lateral = "Pivot from API layer to service/data layer via weak validation/authz/rate-limit controls"
        impact = "Data exposure, service abuse, and material business loss"

        lines.extend([
            f"- **Preconditions:** {preconditions}",
            f"- **Exploited Weaknesses:** {exploited}",
            f"- **Lateral Movement:** {lateral}",
            f"- **Business Impact:** {impact}",
            "",
            "```mermaid",
            "flowchart TD",
            "    p0[Preconditions: External reachability + attacker capability]",
            "    p1[Initial Access: Abuse API/Auth surface]",
            "    p2[Exploit Weakness: Validation/Authz/Rate-limit gap]",
            "    p3[Lateral Movement: Service to data-plane pivot]",
            "    p4[Business Impact: Data breach/fraud/outage]",
            "",
            "    p0 -.-> p1",
            "    p1 -.-> p2",
            "    p2 -.-> p3",
            "    p3 -.-> p4",
            "",
            "    classDef highRisk fill:#ffcccc,stroke:#cc0000;",
            "    class p1 highRisk;",
            "    class p2 highRisk;",
            "    class p3 highRisk;",
            "    linkStyle 0 stroke:#cc0000,stroke-width:2px,stroke-dasharray: 5 5;",
            "    linkStyle 1 stroke:#cc0000,stroke-width:2px,stroke-dasharray: 5 5;",
            "    linkStyle 2 stroke:#cc0000,stroke-width:2px,stroke-dasharray: 5 5;",
            "    linkStyle 3 stroke:#cc0000,stroke-width:2px,stroke-dasharray: 5 5;",
            "```",
            "",
        ])
        return lines

    def _generate_risk_summary_quality_gate(self, relevant_threats: List[Dict[str, Any]]) -> List[str]:
        """Generate mandatory RISK SUMMARY & QUALITY GATE TABLE section."""
        lines = [
            "## RISK SUMMARY & QUALITY GATE TABLE",
            "",
            "| Threat ID | Risk Level | DREAD Avg | Business Impact | Mitigation Priority |",
            "|-----------|------------|-----------|-----------------|---------------------|",
        ]

        if not relevant_threats:
            lines.append("| No matched threats | Low | 0.00 | Manual review required | Backlog |")
            lines.append("")
            return lines

        for item in relevant_threats:
            threat = item.get("threat", {})
            dread_avg = self._average_dread(threat.get("dread_score", {}))
            risk_level = self._classify_risk_level(threat, item.get("evidence_count", 0))
            business_impact = (threat.get("pasta_context") or {}).get(
                "business_impact",
                "Business impact requires manual validation.",
            )
            mitigation_priority = self._mitigation_priority(risk_level)
            lines.append(
                f"| {threat.get('id', 'TM-UNKNOWN')} | {risk_level} | {dread_avg:.2f} | {business_impact} | {mitigation_priority} |"
            )

        lines.append("")
        return lines

    def _generate_footer(self) -> List[str]:
        return [
            "---",
            "",
            f"*Report generated by tm-scan v{__version__} on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*",
            "*This is an automated threat model report based on static analysis. Manual review required.*",
            "",
        ]

    def save_report(self, report_content: str, repo_name: str):
        """Save threat model report to file."""
        report_dir = self.config.get_repo_report_dir(repo_name)
        report_dir.mkdir(parents=True, exist_ok=True)

        report_path = report_dir / "threatmodel-report.md"
        with open(report_path, "w") as file:
            file.write(report_content)

        return report_path

    def generate_sarif(self, repo_name: str, relevant_threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate SARIF representation for matched threats."""

        def rule_id(threat: Dict[str, Any]) -> str:
            compliance = threat.get("compliance") or {}
            cwe_id = compliance.get("cwe_id")
            return str(cwe_id) if cwe_id and cwe_id != "Unknown" else threat.get("id", "TM-UNKNOWN")

        rules: List[Dict[str, Any]] = []
        rule_ids: Set[str] = set()
        results: List[Dict[str, Any]] = []

        for item in relevant_threats:
            threat = item.get("threat", {})
            rid = rule_id(threat)
            if rid not in rule_ids:
                rule_obj: Dict[str, Any] = {
                    "id": rid,
                    "name": threat.get("name"),
                    "shortDescription": {"text": threat.get("description", "")},
                }
                rules.append(rule_obj)
                rule_ids.add(rid)

            dread_score = self._average_dread(threat.get("dread_score", {}))
            level = "error" if dread_score >= 8.0 else "warning"

            results.append({
                "ruleId": rid,
                "level": level,
                "message": {
                    "text": threat.get("reviewer_message") or threat.get("description", "")
                },
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

        return {
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

    def save_sarif(self, sarif_content: Dict[str, Any], repo_name: str):
        """Save SARIF output to file."""
        report_dir = self.config.get_repo_report_dir(repo_name)
        report_dir.mkdir(parents=True, exist_ok=True)

        sarif_path = report_dir / "threatmodel-report.sarif"
        with open(sarif_path, "w") as file:
            json.dump(sarif_content, file, indent=2)

        return sarif_path

    def _average_dread(self, dread: Dict[str, Any]) -> float:
        fields = ["damage", "reproducibility", "exploitability", "affected_users", "discoverability"]
        scores: List[int] = []
        for field in fields:
            scores.append(self._safe_int((dread or {}).get(field), default=0))
        return mean(scores) if scores else 0.0

    def _safe_int(self, value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _normalize_severity(self, value: Any) -> str:
        severity = str(value or "MEDIUM").upper()
        if severity not in self.SEVERITY_ORDER:
            return "MEDIUM"
        return severity

    def _priority_to_severity(self, priority: str) -> str:
        normalized = str(priority or "medium").lower()
        if normalized == "high":
            return "HIGH"
        if normalized == "low":
            return "LOW"
        return "MEDIUM"

    def _line_sort_value(self, line_value: str) -> int:
        try:
            return int(line_value)
        except (TypeError, ValueError):
            return 10**9

    def _classify_risk_level(self, threat: Dict[str, Any], evidence_count: int) -> str:
        dread_avg = self._average_dread(threat.get("dread_score", {}))
        impact = str(threat.get("default_impact", "")).upper()

        if dread_avg >= 8.5 or impact == "CRITICAL" or evidence_count >= 12:
            return "Critical"
        if dread_avg >= 7.0 or impact == "HIGH" or evidence_count >= 6:
            return "High"
        if dread_avg >= 5.0 or evidence_count >= 3:
            return "Medium"
        return "Low"

    def _mitigation_priority(self, risk_level: str) -> str:
        mapping = {
            "Critical": "P0 - Immediate",
            "High": "P1 - Current Sprint",
            "Medium": "P2 - Planned",
            "Low": "P3 - Backlog",
        }
        return mapping.get(risk_level, "P3 - Backlog")
