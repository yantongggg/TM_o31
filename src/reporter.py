"""Threat model report generation module."""

import json
import os
from datetime import datetime
from statistics import mean
from typing import Any, Dict, List, Set, Tuple

import yaml

from . import __version__
from .config import Config


class ThreatModelReporter:
    """Generates deterministic, evidence-rich threat model reports."""

    SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

    def __init__(self, config: Config):
        self.config = config
        self.kb_threats = self._load_threats()

    def _load_threats(self) -> Dict[str, Any]:
        """Load threat KB with safe defaults."""
        try:
            with open(self.config.kb_threats_path, "r") as file:
                raw_data = yaml.safe_load(file) or {}
            return self._normalize_threats(raw_data)
        except Exception as exc:
            print(f"Warning: Could not load threats KB: {exc}")
            return {"threats": [], "assets": [], "sensitivity_levels": []}

    def _normalize_threats(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize threat records for deterministic rendering."""
        normalized_threats: List[Dict[str, Any]] = []
        for threat in raw_data.get("threats", []) or []:
            if not isinstance(threat, dict):
                continue

            compliance = threat.get("compliance") or {}
            pasta_context = threat.get("pasta_context") or {}

            normalized_threats.append({
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
                "pasta_context": {
                    "threat_actor": pasta_context.get("threat_actor", "Unknown actor"),
                    "attack_surface": pasta_context.get("attack_surface", "Unknown surface"),
                    "attack_vector": pasta_context.get("attack_vector", "Unknown attack vector"),
                    "business_impact": pasta_context.get("business_impact", "Business impact requires manual validation."),
                },
                "dread_score": self._normalize_dread_score(threat.get("dread_score") or {}),
                "recommended_controls": threat.get("recommended_controls", []) or [],
                "questions_to_confirm": threat.get("questions_to_confirm", []) or [],
                "reviewer_message": threat.get("reviewer_message", ""),
            })

        normalized_threats.sort(key=lambda item: item.get("id", ""))
        return {
            "threats": normalized_threats,
            "assets": raw_data.get("assets", []) or [],
            "sensitivity_levels": raw_data.get("sensitivity_levels", []) or [],
        }

    def _normalize_dread_score(self, dread: Dict[str, Any]) -> Dict[str, int]:
        """Normalize DREAD score values to integer."""

        def safe_int(value: Any) -> int:
            try:
                return int(value)
            except (TypeError, ValueError):
                return 0

        fields = ["damage", "reproducibility", "exploitability", "affected_users", "discoverability"]
        return {field: safe_int((dread or {}).get(field)) for field in fields}

    def generate_report(
        self,
        repo_name: str,
        evidence: Dict[str, Any],
        gitleaks_summary: Dict[str, Any],
        sbom_summary: Dict[str, Any],
    ) -> str:
        """Generate markdown report with exact structured sections."""
        relevant_threats = self._match_threats(evidence)

        lines: List[str] = []
        lines.extend(self._generate_header(repo_name))
        lines.extend(self._generate_system_context(evidence))
        lines.extend(self._generate_architecture_model(evidence, relevant_threats))
        lines.extend(self._generate_data_flow_matrix(evidence))
        lines.extend(self._generate_5d_threat_analysis(relevant_threats, evidence))
        lines.extend(self._generate_pasta_analysis(relevant_threats, evidence))
        lines.extend(self._generate_risk_summary(relevant_threats))
        lines.extend(self._generate_footer(gitleaks_summary, sbom_summary))

        return "\n".join(lines)

    def _generate_header(self, repo_name: str) -> List[str]:
        """Generate report header with GitHub owner/repo context at the top."""
        repo_owner = os.environ.get("REPO_OWNER", "").strip() or self.config.org
        repo_name_env = os.environ.get("REPO_NAME", "").strip()

        if repo_name_env and "/" in repo_name_env:
            full_repo_name = repo_name_env
            display_repo_name = repo_name_env.split("/", 1)[1] or repo_name
        elif repo_name_env:
            full_repo_name = f"{repo_owner}/{repo_name_env}"
            display_repo_name = repo_name_env
        else:
            full_repo_name = f"{repo_owner}/{repo_name}"
            display_repo_name = repo_name

        return [
            "# Automated Threat Modeling and Security Scan Report",
            "",
            "## Repository Identity",
            "",
            f"**GitHub Owner / Username:** {repo_owner}",
            f"**Repository Name:** {display_repo_name}",
            f"**Full Repository Name:** {full_repo_name}",
            "",
            f"**Organization:** {self.config.org}",
            f"**Report Date:** {self.config.run_timestamp}",
            f"**Report Version:** tm-scan v{__version__}",
            f"**Report ID:** {self.config.run_id}",
            "**Report Classification:** Confidential",
            "",
        ]

    def _match_threats(self, evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Match threats using trigger rules and keyword evidence."""
        keyword_hits = evidence.get("keyword_hits", []) or []
        rule_hits = evidence.get("rule_hits", []) or []
        sast_hits = evidence.get("sast_hits", []) or []

        evidence_keywords = {
            str(hit.get("keyword", "")).lower()
            for hit in keyword_hits
            if hit.get("keyword")
        }
        evidence_rule_ids = {
            str(hit.get("rule_id", ""))
            for hit in rule_hits
            if hit.get("rule_id")
        }

        relevant_threats: List[Dict[str, Any]] = []

        for threat in self.kb_threats.get("threats", []):
            threat_keywords = {
                str(word).lower()
                for word in (threat.get("keywords") or [])
                if word
            }
            trigger_rules = {
                str(rule)
                for rule in (threat.get("trigger_rules") or [])
                if rule
            }

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
                relevant_threats.append({
                    "threat": threat,
                    "matched_keywords": matched_keywords,
                    "matched_rule_ids": matched_rule_ids,
                    "matched_rule_hits": matched_rule_hits,
                    "matched_keyword_hits": matched_keyword_hits,
                    "matched_sast_hits": matched_sast_hits,
                    "evidence_count": len(matched_rule_hits) + len(matched_keyword_hits) + len(matched_sast_hits),
                })

        relevant_threats.sort(
            key=lambda item: (
                -item.get("evidence_count", 0),
                -self._average_dread(item.get("threat", {}).get("dread_score", {})),
                item.get("threat", {}).get("id", ""),
            )
        )
        return relevant_threats

    def _generate_system_context(self, evidence: Dict[str, Any]) -> List[str]:
        """1) SYSTEM CONTEXT."""
        auth_hints = evidence.get("auth_hints", []) or []
        db_hints = evidence.get("db_hints", []) or []
        keyword_hits = evidence.get("keyword_hits", []) or []

        actors: List[str] = ["External Threat Actor", "Internet User"]
        if auth_hints:
            actors.append("Authenticated User")
            actors.append("Identity/Session Provider")

        assets: List[str] = []
        high_sensitive_tokens = {"password", "token", "jwt", "secret", "apikey", "api_key", "users", "ssn", "email", "phone"}
        high_hits = [
            hit for hit in keyword_hits
            if str(hit.get("keyword", "")).lower() in high_sensitive_tokens
            or str(hit.get("category", "")).lower() in {"secret", "credential", "database"}
        ]

        if high_hits:
            assets.append(f"Sensitive User/Secret Data (High) - {len(high_hits)} evidence indicator(s)")
        if db_hints:
            db_types = sorted({str(hit.get("type", "database")) for hit in db_hints if hit.get("type")})
            assets.append(f"Datastores ({', '.join(db_types) if db_types else 'database'}) (High)")
        if not assets:
            assets.append("Application business data (Medium; requires manual classification)")

        assumptions = [
            "Boundary 1: Internet to Application is untrusted.",
            "Boundary 2: Application to Data Layer is trusted-only via server authorization.",
            "Boundary 3: Application to External Services must use authenticated encrypted channels.",
            "All client input is untrusted until server-side validation succeeds.",
        ]

        lines: List[str] = ["## SYSTEM CONTEXT", "", "### Actors"]
        for actor in sorted(set(actors)):
            lines.append(f"- {actor}")

        lines.extend(["", "### Assets"])
        for asset in assets:
            lines.append(f"- {asset}")

        lines.extend(["", "### Trust boundaries & Assumptions"])
        for assumption in assumptions:
            lines.append(f"- {assumption}")

        lines.append("")
        return lines

    def _generate_architecture_model(
        self,
        evidence: Dict[str, Any],
        relevant_threats: List[Dict[str, Any]],
    ) -> List[str]:
        """2) ARCHITECTURE MODEL with strict Mermaid syntax."""
        has_auth = bool(evidence.get("auth_hints"))
        has_db = bool(evidence.get("db_hints"))

        top_risk = "Low"
        for item in relevant_threats[:5]:
            risk = self._classify_risk_level(item.get("threat", {}), item.get("evidence_count", 0))
            if risk == "Critical":
                top_risk = "Critical"
                break
            if risk == "High":
                top_risk = "High"

        lines: List[str] = [
            "## ARCHITECTURE MODEL",
            "",
            "```mermaid",
            "flowchart TD",
            "    subgraph z1[Untrusted Zone]",
            "        attacker((Threat Actor))",
            "        user[End User / Browser]",
            "    end",
            "",
            "    subgraph z2[Application Zone]",
            "        gateway[API Gateway / Web Layer]",
            "        appsvc[Application Services]",
            "    end",
            "",
            "    subgraph z3[Data Zone]",
            "        datastore[(Primary Database)]",
            "        audit[(Audit/Telemetry Store)]",
            "    end",
            "",
            "    subgraph z4[External Services Zone]",
            "        idp[(Identity Provider)]",
            "        external[(3rd Party APIs)]",
            "    end",
            "",
            "    attacker -->|HTTPS / untrusted input| gateway",
            "    user -->|HTTPS / auth token| gateway",
            "    gateway -->|internal authn/authz context| appsvc",
            "    appsvc -->|SQL/TCP + db credentials| datastore",
            "    appsvc -->|security events| audit",
            "    gateway -->|OIDC/JWT validation| idp",
            "    appsvc -->|TLS API call| external",
            "",
            "    classDef highRisk fill:#ffcccc,stroke:#cc0000;",
            "    classDef mediumRisk fill:#ffe6cc,stroke:#cc7a00;",
        ]

        if top_risk in {"Critical", "High"}:
            lines.append("    class gateway highRisk;")
            lines.append("    class appsvc highRisk;")
            lines.append("    class datastore highRisk;")
            lines.append("    class attacker highRisk;")
        else:
            lines.append("    class gateway mediumRisk;")
            lines.append("    class appsvc mediumRisk;")
            lines.append("    class datastore mediumRisk;")

        if not has_auth:
            lines.append("    gateway -.->|Auth evidence limited; verify controls| idp")
        if not has_db:
            lines.append("    appsvc -.->|DB evidence limited; verify persistence layer| datastore")

        lines.extend(["```", ""])
        return lines

    def _generate_data_flow_matrix(self, evidence: Dict[str, Any]) -> List[str]:
        """3) DATA FLOW MATRIX with exact requested columns."""
        rows: List[Tuple[str, str, str, str, str]] = [
            ("Internet User", "API Gateway / Web Layer", "Credentials + Request Data", "HTTPS", "Y"),
            ("API Gateway / Web Layer", "Application Services", "Validated Request Context", "Internal HTTP/RPC", "N"),
            ("Application Services", "Primary Database", "PII + Business Records", "SQL/TCP", "Y"),
            ("Application Services", "Audit/Telemetry Store", "Security Audit Events", "Structured Logging", "N"),
        ]

        if evidence.get("auth_hints"):
            rows.append(("API Gateway / Web Layer", "Identity Provider", "JWT/OIDC Claims", "HTTPS", "Y"))
        if evidence.get("risky_config_hints"):
            rows.append(("Runtime Configuration", "Application Services", "Secrets/Connection Strings", "ENV/File", "N"))

        unique_rows = sorted(set(rows), key=lambda value: (value[0], value[1], value[2]))

        lines: List[str] = [
            "## DATA FLOW MATRIX",
            "",
            "| Source | Destination | Data type | Protocol | Crosses trust boundary (Y/N) |",
            "|--------|-------------|-----------|----------|-------------------------------|",
        ]
        for source, destination, data_type, protocol, boundary in unique_rows:
            lines.append(f"| {source} | {destination} | {data_type} | {protocol} | {boundary} |")

        lines.append("")
        return lines

    def _generate_5d_threat_analysis(
        self,
        relevant_threats: List[Dict[str, Any]],
        evidence: Dict[str, Any],
    ) -> List[str]:
        """4) 5-D THREAT ANALYSIS (STRIDE + LINDDUN + CWE + DREAD)."""
        lines: List[str] = ["## 5-D THREAT ANALYSIS (STRIDE + PASTA + LINDDUN + CWE + DREAD)", ""]

        if not relevant_threats:
            lines.extend([
                "No threats matched current evidence using KB rules/keywords.",
                "",
            ])
            return lines

        for item in relevant_threats:
            threat = item.get("threat", {})
            threat_id = threat.get("id", "TM-UNKNOWN")
            threat_name = threat.get("name", "Unnamed Threat")
            stride = threat.get("stride_category", "Unknown")
            linddun = threat.get("linddun_category", "Unknown")
            cwe_id = (threat.get("compliance") or {}).get("cwe_id", "Unknown")
            dread = threat.get("dread_score", {}) or {}
            dread_avg = self._average_dread(dread)

            pasta_context = threat.get("pasta_context", {}) or {}
            precondition = pasta_context.get("threat_actor", "External actor") + " has access to " + pasta_context.get("attack_surface", "application surface")
            exploitation = pasta_context.get("attack_vector", "exploits weak validation/authz path")
            business_impact = pasta_context.get("business_impact", "Business impact requires manual validation")

            evidence_rows = self._build_threat_evidence_rows(threat, evidence)
            mitigations = self._build_language_specific_mitigations(threat)

            lines.extend([
                f"### [{threat_id}] {threat_name}",
                f"**STRIDE & LINDDUN Categories & CWE Reference:** {stride} | {linddun} | {cwe_id}",
                (
                    f"**DREAD:** Damage={dread.get('damage', 0)}, Reproducibility={dread.get('reproducibility', 0)}, "
                    f"Exploitability={dread.get('exploitability', 0)}, AffectedUsers={dread.get('affected_users', 0)}, "
                    f"Discoverability={dread.get('discoverability', 0)}, Avg={dread_avg:.2f}"
                ),
                "",
                "**PASTA Attack Scenario:**",
                f"- Precondition: {precondition}",
                f"- Exploitation: {exploitation}",
                f"- Business Impact: {business_impact}",
                "",
                "**Evidence Table:**",
                "| File Path | Line Number | Trigger | Severity |",
                "|-----------|-------------|---------|----------|",
            ])

            if evidence_rows:
                lines.extend(evidence_rows)
            else:
                lines.append("| No matched evidence found | - | - | - |")

            lines.extend(["", "**Recommended Technical Mitigations:**"])
            for mitigation in mitigations:
                lines.append(f"- {mitigation}")

            lines.append("")

        return lines

    def _build_threat_evidence_rows(self, threat: Dict[str, Any], evidence: Dict[str, Any]) -> List[str]:
        """Build evidence rows using exact SAST/rule/keyword logic."""
        trigger_rules = set(threat.get("trigger_rules", []) or [])
        keyword_triggers = [str(item).lower() for item in (threat.get("keywords", []) or [])]

        table_rows: List[str] = []

        # 1. Process SAST hits (which have line numbers)
        for hit in evidence.get("sast_hits", []) or []:
            rule_id = str(hit.get("rule_id", ""))
            if rule_id in trigger_rules:
                line_num = hit.get("line", "N/A")
                severity = hit.get("severity", "HIGH")
                filepath = hit.get("file_path", "Unknown")
                table_rows.append(f"| {filepath} | {line_num} | {rule_id} | {severity} |")

        # 2. Process Rule hits (might have line numbers)
        for hit in evidence.get("rule_hits", []) or []:
            rule_id = str(hit.get("rule_id", ""))
            if rule_id in trigger_rules:
                line_num = hit.get("line", "N/A")
                severity = hit.get("severity", "HIGH")
                filepath = hit.get("file_path", "Unknown")
                table_rows.append(f"| {filepath} | {line_num} | {rule_id} | {severity} |")

        # 3. Process Keyword hits (no line numbers, just print '-')
        for hit in evidence.get("keyword_hits", []) or []:
            kw = str(hit.get("keyword", "")).lower()
            if kw in keyword_triggers:
                severity = str(hit.get("priority", "MEDIUM")).upper()
                filepath = hit.get("file_path", "Unknown")
                table_rows.append(f"| {filepath} | - | {kw} | {severity} |")

        # Deduplicate rows
        table_rows = sorted(list(set(table_rows)))
        return table_rows

    def _build_language_specific_mitigations(self, threat: Dict[str, Any]) -> List[str]:
        """Build actionable mitigations with Python/React/TS relevance."""
        controls = [str(item) for item in (threat.get("recommended_controls") or []) if item]
        threat_text = f"{threat.get('name', '')} {threat.get('description', '')}".lower()

        defaults = [
            "Python: enforce server-side validation using Pydantic/FastAPI validators and reject unsafe payload shapes.",
            "TypeScript/React: never trust client-side computed security/business fields; send minimal inputs and recalculate on server.",
            "TypeScript backend: apply strict schema validation (zod/joi) and centralized authorization middleware per route.",
        ]

        if "jwt" in threat_text or "auth" in threat_text or "credential" in threat_text:
            defaults.append("Python/TS APIs: verify JWT signature, issuer, audience, expiry on every protected request.")
        if "sql" in threat_text or "injection" in threat_text:
            defaults.append("Python DB layer: use parameterized queries/ORM binds only; ban string-concatenated SQL in code review gates.")
        if "logging" in threat_text or "secret" in threat_text:
            defaults.append("React/Python logs: redact Authorization headers, tokens, passwords, and PII at logger middleware.")
        if "rate" in threat_text or "stuffing" in threat_text:
            defaults.append("Python/TS gateway: enforce IP + account rate-limits, lockout/backoff, and anomaly detection.")

        merged = controls + defaults
        deduped: List[str] = []
        seen: Set[str] = set()
        for item in merged:
            if item not in seen:
                deduped.append(item)
                seen.add(item)

        return deduped[:8]

    def _generate_pasta_analysis(
        self,
        relevant_threats: List[Dict[str, Any]],
        evidence: Dict[str, Any],
    ) -> List[str]:
        """5) PASTA ANALYSIS with Mermaid attack path."""
        top_threats = relevant_threats[:3]

        weakness_nodes: List[str] = []
        for item in top_threats:
            threat = item.get("threat", {})
            weakness_nodes.append(f"{threat.get('id', 'TM-UNKNOWN')} {threat.get('name', 'Threat')}")

        if not weakness_nodes:
            weakness_nodes = ["No high-confidence weakness chain detected"]

        first = weakness_nodes[0]
        second = weakness_nodes[1] if len(weakness_nodes) > 1 else weakness_nodes[0]
        third = weakness_nodes[2] if len(weakness_nodes) > 2 else weakness_nodes[0]

        lines: List[str] = [
            "## PASTA ANALYSIS (Attack Trees & Paths)",
            "",
            "```mermaid",
            "flowchart TD",
            "    a0[Preconditions: Internet reachability and attacker capability]",
            f'    a1["Initial Exploitation: {first}"]',
            f'    a2["Privilege/Logic Abuse: {second}"]',
            f'    a3["Lateral Movement: {third}"]',
            "    a4[Business Impact: Data breach, fraud, or service disruption]",
            "",
            "    a0 -.-> a1",
            "    a1 -.-> a2",
            "    a2 -.-> a3",
            "    a3 -.-> a4",
            "",
            "    classDef highRisk fill:#ffcccc,stroke:#cc0000;",
            "    class a1 highRisk;",
            "    class a2 highRisk;",
            "    class a3 highRisk;",
            "    linkStyle 0 stroke:#cc0000,stroke-width:2px,stroke-dasharray: 5 5;",
            "    linkStyle 1 stroke:#cc0000,stroke-width:2px,stroke-dasharray: 5 5;",
            "    linkStyle 2 stroke:#cc0000,stroke-width:2px,stroke-dasharray: 5 5;",
            "    linkStyle 3 stroke:#cc0000,stroke-width:2px,stroke-dasharray: 5 5;",
            "```",
            "",
        ]
        return lines

    def _generate_risk_summary(self, relevant_threats: List[Dict[str, Any]]) -> List[str]:
        """6) RISK SUMMARY."""
        lines: List[str] = [
            "## RISK SUMMARY",
            "",
            "| Threat ID | Risk Level | DREAD Avg | Mitigation Priority |",
            "|-----------|------------|-----------|---------------------|",
        ]

        if not relevant_threats:
            lines.append("| No matched threats | Low | 0.00 | P3 - Backlog |")
            lines.append("")
            return lines

        for item in relevant_threats:
            threat = item.get("threat", {})
            threat_id = threat.get("id", "TM-UNKNOWN")
            dread_avg = self._average_dread(threat.get("dread_score", {}))
            risk_level = self._classify_risk_level(threat, item.get("evidence_count", 0))
            priority = self._mitigation_priority(risk_level)
            lines.append(f"| {threat_id} | {risk_level} | {dread_avg:.2f} | {priority} |")

        lines.append("")
        return lines

    def _generate_footer(self, gitleaks_summary: Dict[str, Any], sbom_summary: Dict[str, Any]) -> List[str]:
        """Render report footer with supporting scan stats."""
        gitleaks_findings = (gitleaks_summary or {}).get("findings_count", 0)
        sbom_packages = (sbom_summary or {}).get("package_count", 0)

        return [
            "---",
            "",
            f"*Secret Findings (gitleaks): {gitleaks_findings}*",
            f"*Total Packages (SBOM): {sbom_packages}*",
            f"*Report generated by tm-scan v{__version__} on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*",
            "*Automated output from static analysis; manual security review is required.*",
            "",
        ]

    def save_report(self, report_content: str, repo_name: str):
        """Save markdown report to file."""
        report_dir = self.config.get_repo_report_dir(repo_name)
        report_dir.mkdir(parents=True, exist_ok=True)

        report_path = report_dir / "threatmodel-report.md"
        with open(report_path, "w") as file:
            file.write(report_content)

        return report_path

    def generate_sarif(self, repo_name: str, relevant_threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate SARIF output for matched threats."""

        def rule_id(threat: Dict[str, Any]) -> str:
            compliance = threat.get("compliance") or {}
            cwe_id = compliance.get("cwe_id")
            if cwe_id and str(cwe_id).strip() and str(cwe_id) != "Unknown":
                return str(cwe_id)
            return str(threat.get("id", "TM-UNKNOWN"))

        rules: List[Dict[str, Any]] = []
        results: List[Dict[str, Any]] = []
        existing_rule_ids: Set[str] = set()

        for item in relevant_threats:
            threat = item.get("threat", {})
            rid = rule_id(threat)

            if rid not in existing_rule_ids:
                rules.append({
                    "id": rid,
                    "name": threat.get("name", "Unnamed Threat"),
                    "shortDescription": {"text": threat.get("description", "")},
                })
                existing_rule_ids.add(rid)

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
                            "artifactLocation": {"uri": repo_name}
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
        """Compute DREAD average robustly."""
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
