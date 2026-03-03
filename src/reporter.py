"""
Threat model report generation module.
"""

import os
import json
import yaml
from typing import Dict, List, Any
from datetime import datetime
from statistics import mean

from .config import Config
from . import __version__


class ThreatModelReporter:
    """Generates STRIDE and PASTA-based enterprise threat model reports."""

    def __init__(self, config: Config):
        self.config = config
        self.kb_threats = self._load_threats()

    def _load_threats(self) -> Dict:
        try:
            with open(self.config.kb_threats_path, "r") as file:
                raw_data = yaml.safe_load(file) or {}
            return self._normalize_threats(raw_data)
        except Exception as exc:
            print(f"Warning: Could not load threats KB: {exc}")
            return {"threats": []}

    def _normalize_threats(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        normalized_threats = []
        for threat in raw_data.get("threats", []) or []:
            if isinstance(threat, dict):
                normalized_threats.append(threat)
        return {"threats": normalized_threats}

    def generate_report(self, repo_name: str, evidence: Dict, gitleaks_summary: Dict, sbom_summary: Dict) -> str:
        relevant_threats = self._match_threats(evidence)
        lines = [
            self._generate_header(repo_name),
            self._generate_system_context(evidence),
            self._generate_mermaid_dfd(relevant_threats, evidence),
            self._generate_data_flow_matrix(evidence),
            self._generate_5d_analysis(relevant_threats, evidence),
            self._generate_pasta_analysis(relevant_threats),
            self._generate_risk_summary(relevant_threats),
            self._generate_footer(gitleaks_summary, sbom_summary),
        ]
        return "\n".join(lines)

    def _match_threats(self, evidence: Dict) -> List[Dict[str, Any]]:
        relevant_threats = []

        rule_hits = evidence.get("rule_hits", []) or []
        sast_hits = evidence.get("sast_hits", []) or []
        keyword_hits = evidence.get("keyword_hits", []) or []

        rule_hit_ids = {str(hit.get("rule_id", "")) for hit in rule_hits + sast_hits if hit.get("rule_id")}
        evidence_keywords = {str(hit.get("keyword", "")).lower() for hit in keyword_hits if hit.get("keyword")}
        evidence_cwes = {str(hit.get("cwe", "")).strip().upper() for hit in rule_hits + sast_hits if hit.get("cwe")}

        for threat in self.kb_threats.get("threats", []):
            threat_keywords = {str(word).lower() for word in (threat.get("keywords", []) or []) if word}
            trigger_rules = {str(rule) for rule in (threat.get("trigger_rules", []) or []) if rule}
            threat_cwe = str((threat.get("compliance", {}) or {}).get("cwe_id", "")).strip().upper()

            keyword_match = bool(threat_keywords & evidence_keywords)
            rule_match = bool(trigger_rules & rule_hit_ids)
            cwe_match = bool(threat_cwe and threat_cwe in evidence_cwes)

            if keyword_match or rule_match or cwe_match:
                score = (
                    len(threat_keywords & evidence_keywords)
                    + len(trigger_rules & rule_hit_ids)
                    + (1 if cwe_match else 0)
                )
                relevant_threats.append({
                    "threat": threat,
                    "evidence_count": score,
                })

        relevant_threats.sort(key=lambda item: item.get("evidence_count", 0), reverse=True)
        return relevant_threats

    def _generate_header(self, repo_name: str) -> str:
        repo_owner = os.environ.get("REPO_OWNER", "Unknown Owner")
        full_repo_name = os.environ.get("REPO_NAME", repo_name)
        return "\n".join([
            "# Enterprise Threat Modeling & Security Audit",
            "",
            "## Repository Identity",
            f"**GitHub Owner / Username:** {repo_owner}",
            f"**Repository Name:** {full_repo_name}",
            f"**Report Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Report Version:** tm-scan v{__version__}",
            "**Classification:** Highly Confidential",
            "",
        ])

    def _generate_system_context(self, evidence: Dict) -> str:
        db_count = len(evidence.get("db_hints", []) or [])
        auth_count = len(evidence.get("auth_hints", []) or [])
        return "\n".join([
            "## 1. SYSTEM CONTEXT",
            "",
            "### Actors",
            "- Authenticated End User",
            "- External Threat Actor",
            "- Identity & Access Management (IAM)",
            "",
            "### Assets",
            f"- Sensitive User/PII Data (High Value) - {db_count} evidence trace(s)",
            f"- Authentication Context/Tokens (High Value) - {auth_count} evidence trace(s)",
            "",
            "### Trust Boundaries & Assumptions",
            "- **Boundary 1:** Internet to Application Gateway is inherently untrusted.",
            "- **Boundary 2:** API Layer to Data Store relies on strict server-side authorization.",
            "- **Assumption:** Client-side biometric/eKYC controls can be bypassed; server-side validation is mandatory.",
            "",
        ])

    def _generate_mermaid_dfd(self, relevant_threats: List[Dict[str, Any]], evidence: Dict) -> str:
        """Generate a Mermaid flowchart DFD dynamically based on evidence."""

        file_paths = [
            hit.get("file_path", "")
            for hit in (evidence.get("keyword_hits", []) or []) + (evidence.get("sast_hits", []) or [])
        ]
        db_types = [hit.get("type", "") for hit in evidence.get("db_hints", []) or []]

        has_react = any(str(path).endswith((".tsx", ".jsx")) for path in file_paths)
        has_python = any(str(path).endswith(".py") for path in file_paths)
        has_supabase = "supabase" in str(file_paths).lower() or "postgres" in str(db_types).lower()

        lines = [
            "## 2. ARCHITECTURE MODEL",
            "",
            "```mermaid",
            "flowchart TD",
            "    subgraph TB1 [TB1: Untrusted Internet Zone]",
            "        attacker((Threat Actor))",
            "        user((End User / Browser))",
        ]

        if has_react:
            lines.append("        client[React Frontend / SPA]")

        lines.extend([
            "    end",
            "",
            "    subgraph TB2 [TB2: Application Internal Services]",
            "        gateway[API Gateway / Auth Controller]",
        ])

        if has_python:
            lines.append("        backend[Python Backend / ML Service]")

        lines.extend([
            "    end",
            "",
            "    subgraph TB3 [TB3: Secure Data Zone]",
        ])

        if has_supabase:
            lines.append("        db[(Supabase PostgreSQL)]")
        else:
            lines.append("        db[(Primary Database)]")

        lines.extend([
            "    end",
            "",
            "    %% Data Flows",
            "    attacker -->|HTTPS / Untrusted Probes| gateway",
            "    user -->|HTTPS / Auth Token| gateway",
        ])

        if has_react:
            lines.append("    user -->|UI Interaction| client")
            lines.append("    client -->|HTTPS / API Payload| gateway")

        if has_python:
            lines.append("    gateway -->|Internal RPC / Authz Context| backend")
            lines.append("    backend -->|SQL / DB Credentials| db")
        else:
            lines.append("    gateway -->|SQL / DB Credentials| db")

        lines.extend([
            "",
            "    classDef highRisk fill:#ffcccc,stroke:#cc0000;",
            "    class gateway highRisk;",
            "    class db highRisk;",
            "    class attacker highRisk;",
        ])

        if has_python:
            lines.append("    class backend highRisk;")

        lines.extend([
            "```",
            "",
        ])

        return "\n".join(lines)

    def _generate_data_flow_matrix(self, evidence: Dict) -> str:
        has_python = any(
            str(hit.get("file_path", "")).endswith(".py")
            for hit in (evidence.get("keyword_hits", []) or []) + (evidence.get("sast_hits", []) or [])
        )

        lines = [
            "## 3. DATA FLOW MATRIX",
            "",
            "| Source | Destination | Data Type | Protocol | Auth | Crosses Trust Boundary? |",
            "|--------|-------------|-----------|----------|------|-------------------------|",
            "| Frontend Client | API Gateway | User/eKYC Payload | HTTPS | JWT | **Yes** |",
        ]

        if has_python:
            lines.append("| API Gateway | ML Backend | Image/Biometric Data | Internal RPC | Service | No |")
            lines.append("| Backend Service | Database | SQL Queries / PII | TCP/5432 | Password | **Yes** |")
        else:
            lines.append("| API Gateway | Database | SQL Queries / PII | TCP/5432 | Password | **Yes** |")

        lines.extend([
            "| App Config | Runtime | DB Secrets / API Keys | ENV | OS Level | No |",
            "",
        ])

        return "\n".join(lines)

    def _resolve_trigger_rules_for_threat(self, threat: Dict[str, Any], evidence: Dict) -> set:
        resolved = {str(rule) for rule in (threat.get("trigger_rules", []) or []) if rule}

        threat_cwe = str((threat.get("compliance", {}) or {}).get("cwe_id", "")).strip().upper()
        if threat_cwe:
            for hit in (evidence.get("sast_hits", []) or []) + (evidence.get("rule_hits", []) or []):
                hit_cwe = str(hit.get("cwe", "")).strip().upper()
                if hit_cwe == threat_cwe and hit.get("rule_id"):
                    resolved.add(str(hit.get("rule_id")))

        return resolved

    def _rule_hit_matches_threat(self, hit: Dict[str, Any], threat: Dict[str, Any], trigger_rules: set, keywords: List[str]) -> bool:
        rule_id = str(hit.get("rule_id", ""))
        if rule_id and rule_id in trigger_rules:
            return True

        threat_cwe = str((threat.get("compliance", {}) or {}).get("cwe_id", "")).strip().upper()
        hit_cwe = str(hit.get("cwe", "")).strip().upper()
        if threat_cwe and hit_cwe and threat_cwe == hit_cwe:
            return True

        threat_text = f"{threat.get('name', '')} {threat.get('description', '')}".lower()
        hit_cat = str(hit.get("category", "")).lower()
        hit_subcat = str(hit.get("sub_category", "")).lower()
        if hit_cat and hit_cat in threat_text:
            return True
        if hit_subcat and hit_subcat in threat_text:
            return True

        rule_text = f"{rule_id} {hit_cat} {hit_subcat}".lower()
        return any(keyword and keyword in rule_text for keyword in keywords[:12])

    def _generate_5d_analysis(self, relevant_threats: List[Dict[str, Any]], evidence: Dict) -> str:
        lines = ["## 4. 5-D THREAT ANALYSIS (STRIDE + PASTA + LINDDUN + CWE + DREAD)", ""]
        if not relevant_threats:
            return "\n".join(lines + ["No specific threats matched."])

        for item in relevant_threats:
            threat = item.get("threat", {})
            threat_id = threat.get("id", "UNKNOWN")
            dread = threat.get("dread_score", {}) or {}
            avg_dread = self._average_dread(dread)

            lines.extend([
                f"### [{threat_id}] {threat.get('name')}",
                f"**STRIDE / LINDDUN:** {threat.get('stride_category', 'TBD')} / {threat.get('linddun_category', 'TBD')} | **CWE:** {threat.get('compliance', {}).get('cwe_id', 'TBD')}",
                f"**DREAD Score:** Damage={dread.get('damage', 0)}, Repro={dread.get('reproducibility', 0)}, Exploit={dread.get('exploitability', 0)}, Users={dread.get('affected_users', 0)}, Discover={dread.get('discoverability', 0)} (Avg: {avg_dread:.2f})",
                "",
                "**PASTA Attack Scenario:**",
                f"- **Precondition:** {threat.get('pasta_context', {}).get('attack_surface', 'Attacker reaches exposed interface.')}",
                f"- **Exploitation:** {threat.get('pasta_context', {}).get('attack_vector', 'Manipulates input or bypasses controls.')}",
                f"- **Business Impact:** {threat.get('pasta_context', {}).get('business_impact', 'Data breach or operational outage.')}",
                "",
                "**Evidence Context (Actionable Trace):**",
            ])

            table_rows = []
            seen_hits = set()
            trigger_rules = self._resolve_trigger_rules_for_threat(threat, evidence)
            keywords = [str(keyword).lower() for keyword in (threat.get("keywords", []) or [])]
            exclude_files = {"evidence.json", "evidence-summary.md"}

            def _normalize_path(file_path: str) -> str:
                normalized = str(file_path or "unknown").strip().replace("\\", "/")
                if normalized.startswith("./"):
                    normalized = normalized[2:]
                return normalized

            def _should_exclude_path(file_path: str) -> bool:
                lower_path = str(file_path or "").lower().replace("\\", "/")
                base_name = os.path.basename(lower_path)
                return base_name in exclude_files or "/evidence.json" in lower_path or "/evidence-summary.md" in lower_path

            def _add_row(file_path: str, rule_or_keyword: str, row_str: str) -> bool:
                dedupe_key = (_normalize_path(file_path), str(rule_or_keyword or "").strip().lower())
                if dedupe_key in seen_hits:
                    return False
                seen_hits.add(dedupe_key)
                table_rows.append(row_str)
                return True

            has_high_fidelity_evidence = False

            # 1) Highest fidelity: SAST hits with exact lines
            for hit in evidence.get("sast_hits", []) or []:
                if self._rule_hit_matches_threat(hit, threat, trigger_rules, keywords):
                    file_path = _normalize_path(hit.get("file_path", "unknown"))
                    if _should_exclude_path(file_path):
                        continue
                    rule_id = str(hit.get("rule_id", "UNKNOWN_RULE"))
                    line_val = str(hit.get("line", "N/A"))
                    severity = str(hit.get("severity", "HIGH")).upper()
                    row_str = f"| `{file_path}` | **Line {line_val}** | Rule: `{rule_id}` | **{severity}** |"
                    if _add_row(file_path, f"rule:{rule_id}", row_str):
                        has_high_fidelity_evidence = True

            # 2) Medium fidelity: rule hits
            for hit in evidence.get("rule_hits", []) or []:
                if self._rule_hit_matches_threat(hit, threat, trigger_rules, keywords):
                    file_path = _normalize_path(hit.get("file_path", "unknown"))
                    if _should_exclude_path(file_path):
                        continue
                    rule_id = str(hit.get("rule_id", "UNKNOWN_RULE"))
                    line_val = str(hit.get("line", "N/A")) if hit.get("line") else "-"
                    severity = str(hit.get("severity", "HIGH")).upper()
                    row_str = f"| `{file_path}` | Line {line_val} | Rule: `{rule_id}` | {severity} |"
                    if _add_row(file_path, f"rule:{rule_id}", row_str):
                        has_high_fidelity_evidence = True

            # 3) Low fidelity fallback: keyword hits (only when no SAST/Rule evidence exists)
            if not has_high_fidelity_evidence:
                for hit in evidence.get("keyword_hits", []) or []:
                    keyword = str(hit.get("keyword", "")).lower()
                    if keyword in keywords:
                        file_path = _normalize_path(hit.get("file_path", "unknown"))
                        if _should_exclude_path(file_path):
                            continue
                        severity = str(hit.get("priority", "MEDIUM")).upper()
                        row_str = f"| `{file_path}` | - | Keyword: `{keyword}` | {severity} |"
                        _add_row(file_path, f"keyword:{keyword}", row_str)

            # Preserve fidelity-first insertion order, cap size
            table_rows = table_rows[:30]

            if table_rows:
                lines.extend([
                    "| File Path | Exact Line | Trigger (Rule/Keyword) | Severity |",
                    "|-----------|------------|------------------------|----------|",
                ])
                lines.extend(table_rows)
            else:
                lines.append("No specific code-level evidence captured.")

            lines.extend(["", "**Mitigation Requirements:**"])
            for control in (threat.get("recommended_controls", []) or [])[:3]:
                lines.append(f"- {control}")
            lines.append("")

        return "\n".join(lines)

    def _generate_pasta_analysis(self, relevant_threats: List[Dict[str, Any]]) -> str:
        threat_names = []
        for item in relevant_threats[:3]:
            threat = item.get("threat", {})
            clean_name = str(threat.get("name", "Unknown")).replace('"', '').replace('(', '[').replace(')', ']')
            threat_names.append(f"{threat.get('id', '')}: {clean_name}")

        while len(threat_names) < 3:
            threat_names.append("Placeholder Threat")

        return "\n".join([
            "## 5. PASTA ANALYSIS (Attack Trees & Paths)",
            "",
            "```mermaid",
            "flowchart TD",
            "    a0[\"Precondition: Attacker maps attack surface\"]",
            f"    a1[\"Initial Exploit: {threat_names[0]}\"]",
            f"    a2[\"Pivot/Escalate: {threat_names[1]}\"]",
            f"    a3[\"Objective Reached: {threat_names[2]}\"]",
            "    a4[\"Business Impact: High regulatory and financial loss\"]",
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
        ])

    def _generate_risk_summary(self, relevant_threats: List[Dict[str, Any]]) -> str:
        lines = [
            "## 6. RISK SUMMARY & ACTION PLAN",
            "",
            "| Threat ID | Threat Name | Risk Level | DREAD Avg | Mitigation Priority |",
            "|-----------|-------------|------------|-----------|---------------------|",
        ]

        for item in relevant_threats[:10]:
            threat = item.get("threat", {})
            avg = self._average_dread(threat.get("dread_score", {}) or {})
            level = "Critical" if avg >= 8.0 else ("High" if avg >= 6.0 else "Medium")
            priority = "P0 - Immediate" if level == "Critical" else "P1 - Current Sprint"
            lines.append(f"| {threat.get('id')} | {threat.get('name')} | **{level}** | {avg:.2f} | {priority} |")

        return "\n".join(lines + [""])

    def _generate_footer(self, gitleaks_summary: Dict, sbom_summary: Dict) -> str:
        secret_findings = int((gitleaks_summary or {}).get("findings_count", 0))
        package_count = int((sbom_summary or {}).get("package_count", 0))
        return "\n".join([
            "---",
            f"*Secret Findings (gitleaks): {secret_findings}*",
            f"*Total Packages (SBOM): {package_count}*",
            f"*Report generated automatically by tm-scan v{__version__} on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*",
            "*End of Threat Model Report*",
        ])

    def _average_dread(self, dread: Dict[str, Any]) -> float:
        values = [
            self._to_int((dread or {}).get("damage", 0)),
            self._to_int((dread or {}).get("reproducibility", 0)),
            self._to_int((dread or {}).get("exploitability", 0)),
            self._to_int((dread or {}).get("affected_users", 0)),
            self._to_int((dread or {}).get("discoverability", 0)),
        ]
        return mean(values) if values else 0.0

    def _to_int(self, value: Any) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    def generate_sarif(self, repo_name: str, relevant_threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        rules, rule_ids, results = [], set(), []
        for item in relevant_threats:
            threat = item.get("threat", {})
            rid = str(threat.get("compliance", {}).get("cwe_id") or threat.get("id", "TM-UNKNOWN"))
            if rid not in rule_ids:
                rules.append({
                    "id": rid,
                    "name": threat.get("name"),
                    "shortDescription": {"text": threat.get("description", "")},
                })
                rule_ids.add(rid)

            dread_score = self._average_dread(threat.get("dread_score", {}) or {})
            results.append({
                "ruleId": rid,
                "level": "error" if dread_score >= 8.0 else "warning",
                "message": {"text": threat.get("reviewer_message") or threat.get("description", "")},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": repo_name}}}],
            })

        return {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "tm-scan", "rules": rules}}, "results": results}],
        }

    def save_report(self, report_content: str, repo_name: str):
        report_dir = self.config.get_repo_report_dir(repo_name)
        report_dir.mkdir(parents=True, exist_ok=True)
        path = report_dir / "threatmodel-report.md"
        with open(path, "w") as file:
            file.write(report_content)
        return path

    def save_sarif(self, sarif_content: Dict[str, Any], repo_name: str):
        report_dir = self.config.get_repo_report_dir(repo_name)
        report_dir.mkdir(parents=True, exist_ok=True)
        path = report_dir / "threatmodel-report.sarif"
        with open(path, "w") as file:
            json.dump(sarif_content, file, indent=2)
        return path
