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
            with open(self.config.kb_threats_path, "r") as f:
                raw_data = yaml.safe_load(f) or {}
            return self._normalize_threats(raw_data)
        except Exception as e:
            print(f"Warning: Could not load threats KB: {e}")
            return {"threats": []}

    def _normalize_threats(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        normalized_threats = []
        for threat in raw_data.get("threats", []) or []:
            if not isinstance(threat, dict):
                continue
            normalized_threats.append(threat)
        return {"threats": normalized_threats}

    def generate_report(self, repo_name: str, evidence: Dict, gitleaks_summary: Dict, sbom_summary: Dict) -> str:
        relevant_threats = self._match_threats(evidence)
        lines = [
            self._generate_header(repo_name),
            self._generate_system_context(evidence),
            self._generate_mermaid_dfd(relevant_threats, evidence),
            self._generate_data_flow_matrix(),
            self._generate_5d_analysis(relevant_threats, evidence),
            self._generate_pasta_analysis(relevant_threats),
            self._generate_risk_summary(relevant_threats),
            self._generate_footer()
        ]
        return "\n".join(lines)

    def _match_threats(self, evidence: Dict) -> List[Dict[str, Any]]:
        relevant_threats = []
        rule_hit_ids = {h.get("rule_id") for h in evidence.get("rule_hits", []) + evidence.get("sast_hits", [])}
        evidence_keywords = {h.get("keyword", "").lower() for h in evidence.get("keyword_hits", [])}

        for threat in self.kb_threats.get("threats", []):
            threat_keywords = {k.lower() for k in threat.get("keywords", [])}
            trigger_rules = set(threat.get("trigger_rules", []) or [])
            keyword_hits = threat_keywords & evidence_keywords
            rule_hits = trigger_rules & rule_hit_ids
            if keyword_hits or rule_hits:
                relevant_threats.append({
                    "threat": threat,
                    "evidence_count": len(keyword_hits) + len(rule_hits)
                })
        relevant_threats.sort(key=lambda t: t["evidence_count"], reverse=True)
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
            ""
        ])

    def _generate_system_context(self, evidence: Dict) -> str:
        db_count = len(evidence.get("db_hints", []))
        auth_count = len(evidence.get("auth_hints", []))
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
            ""
        ])

    def _generate_mermaid_dfd(self, relevant_threats: List[Dict[str, Any]], evidence: Dict) -> str:
        """Generate a Mermaid flowchart DFD dynamically based on evidence."""

        file_paths = [h.get("file_path", "") for h in evidence.get("keyword_hits", []) + evidence.get("sast_hits", [])]
        db_types = [h.get("type", "") for h in evidence.get("db_hints", [])]

        has_react = any(f.endswith((".tsx", ".jsx")) for f in file_paths)
        has_python = any(f.endswith(".py") for f in file_paths)
        has_supabase = "supabase" in str(file_paths).lower() or "postgres" in str(db_types).lower()

        lines = [
            "## 2. ARCHITECTURE MODEL",
            "",
            "```mermaid",
            "flowchart TD",
            "    subgraph TB1 [TB1: Untrusted Internet Zone]",
            "        attacker((Threat Actor))",
            "        user((End User / Browser))"
        ]

        if has_react:
            lines.append("        client[React Frontend / SPA]")

        lines.extend([
            "    end",
            "",
            "    subgraph TB2 [TB2: Application Internal Services]",
            "        gateway[API Gateway / Auth Controller]"
        ])

        if has_python:
            lines.append("        backend[Python Backend / ML Service]")

        lines.extend([
            "    end",
            "",
            "    subgraph TB3 [TB3: Secure Data Zone]"
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
            "    user -->|HTTPS / Auth Token| gateway"
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
            ""
        ])

        return "\n".join(lines)

    def _generate_data_flow_matrix(self) -> str:
        return "\n".join([
            "## 3. DATA FLOW MATRIX",
            "",
            "| Source | Destination | Data Type | Protocol | Auth | Crosses Trust Boundary? |",
            "|--------|-------------|-----------|----------|------|-------------------------|",
            "| Frontend Client | API Gateway | User/eKYC Payload | HTTPS | JWT | **Yes** |",
            "| API Gateway | ML Backend | Image/Biometric Data | Internal RPC | Service | No |",
            "| Backend Service | Database | SQL Queries / PII | TCP/5432 | Password | **Yes** |",
            "| App Config | Runtime | DB Secrets / API Keys | ENV | OS Level | No |",
            ""
        ])

    def _generate_5d_analysis(self, relevant_threats: List[Dict[str, Any]], evidence: Dict) -> str:
        lines = ["## 4. 5-D THREAT ANALYSIS (STRIDE + PASTA + LINDDUN + CWE + DREAD)", ""]
        if not relevant_threats:
            return "\n".join(lines + ["No specific threats matched."])

        for item in relevant_threats:
            t = item["threat"]
            tid = t.get("id", "UNKNOWN")
            dread = t.get("dread_score", {})
            avg_dread = mean([int(v) for v in dread.values()]) if dread else 0.0

            lines.extend([
                f"### [{tid}] {t.get('name')}",
                f"**STRIDE / LINDDUN:** {t.get('stride_category', 'TBD')} / {t.get('linddun_category', 'TBD')} | **CWE:** {t.get('compliance', {}).get('cwe_id', 'TBD')}",
                f"**DREAD Score:** Damage={dread.get('damage',0)}, Repro={dread.get('reproducibility',0)}, Exploit={dread.get('exploitability',0)}, Users={dread.get('affected_users',0)}, Discover={dread.get('discoverability',0)} (Avg: {avg_dread:.2f})",
                "",
                "**PASTA Attack Scenario:**",
                f"- **Precondition:** {t.get('pasta_context', {}).get('attack_surface', 'Attacker reaches exposed interface.')}",
                f"- **Exploitation:** {t.get('pasta_context', {}).get('attack_vector', 'Manipulates input or bypasses controls.')}",
                f"- **Business Impact:** {t.get('pasta_context', {}).get('business_impact', 'Data breach or operational outage.')}",
                "",
                "**Evidence Context (Actionable Trace):**",
            ])

            table_rows = []
            trigger_rules = t.get("trigger_rules", [])
            keywords = [k.lower() for k in t.get("keywords", [])]

            for h in evidence.get("sast_hits", []):
                if h.get("rule_id") in trigger_rules:
                    line_val = str(h.get("line", "N/A"))
                    table_rows.append(f"| `{h.get('file_path', 'unknown')}` | **Line {line_val}** | Rule: `{h.get('rule_id')}` | **{h.get('severity', 'HIGH').upper()}** |")

            for h in evidence.get("rule_hits", []):
                if h.get("rule_id") in trigger_rules:
                    line_val = str(h.get("line", "N/A")) if h.get("line") else "-"
                    row_str = f"| `{h.get('file_path', 'unknown')}` | Line {line_val} | Rule: `{h.get('rule_id')}` | {h.get('severity', 'HIGH').upper()} |"
                    if row_str not in table_rows:
                        table_rows.append(row_str)

            for h in evidence.get("keyword_hits", []):
                kw = h.get("keyword", "").lower()
                if kw in keywords:
                    row_str = f"| `{h.get('file_path', 'unknown')}` | - | Keyword: `{kw}` | {h.get('priority', 'MEDIUM').upper()} |"
                    if row_str not in table_rows:
                        table_rows.append(row_str)

            table_rows = sorted(list(set(table_rows)))[:30]

            if table_rows:
                lines.extend([
                    "| File Path | Exact Line | Trigger (Rule/Keyword) | Severity |",
                    "|-----------|------------|------------------------|----------|",
                ])
                lines.extend(table_rows)
            else:
                lines.append("No specific code-level evidence captured.")

            lines.extend(["", "**Mitigation Requirements:**"])
            for m in t.get("recommended_controls", [])[:3]:
                lines.append(f"- {m}")
            lines.append("")

        return "\n".join(lines)

    def _generate_pasta_analysis(self, relevant_threats: List[Dict[str, Any]]) -> str:
        t_names = []
        for item in relevant_threats[:3]:
            t = item["threat"]
            clean_name = t.get('name', 'Unknown').replace('"', '').replace('(', '[').replace(')', ']')
            t_names.append(f"{t.get('id', '')}: {clean_name}")

        while len(t_names) < 3:
            t_names.append("Placeholder Threat")

        return "\n".join([
            "## 5. PASTA ANALYSIS (Attack Trees & Paths)",
            "",
            "```mermaid",
            "flowchart TD",
            "    a0[\"Precondition: Attacker maps attack surface\"]",
            f"    a1[\"Initial Exploit: {t_names[0]}\"]",
            f"    a2[\"Pivot/Escalate: {t_names[1]}\"]",
            f"    a3[\"Objective Reached: {t_names[2]}\"]",
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
            ""
        ])

    def _generate_risk_summary(self, relevant_threats: List[Dict[str, Any]]) -> str:
        lines = [
            "## 6. RISK SUMMARY & ACTION PLAN",
            "",
            "| Threat ID | Threat Name | Risk Level | DREAD Avg | Mitigation Priority |",
            "|-----------|-------------|------------|-----------|---------------------|"
        ]
        for item in relevant_threats[:10]:
            t = item["threat"]
            dread = t.get("dread_score", {})
            avg = mean([int(v) for v in dread.values()]) if dread else 0.0
            level = "Critical" if avg >= 8.0 else ("High" if avg >= 6.0 else "Medium")
            priority = "P0 - Immediate" if level == "Critical" else "P1 - Current Sprint"
            lines.append(f"| {t.get('id')} | {t.get('name')} | **{level}** | {avg:.2f} | {priority} |")

        return "\n".join(lines + [""])

    def _generate_footer(self) -> str:
        return "\n".join([
            "---",
            f"*Report generated automatically by tm-scan engine on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*",
            "*End of Threat Model Report*"
        ])

    def generate_sarif(self, repo_name: str, relevant_threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        rules, rule_ids, results = [], set(), []
        for item in relevant_threats:
            t = item.get("threat", {})
            rid = str(t.get("compliance", {}).get("cwe_id") or t.get("id", "TM-UNKNOWN"))
            if rid not in rule_ids:
                rules.append({"id": rid, "name": t.get("name"), "shortDescription": {"text": t.get("description", "")}})
                rule_ids.add(rid)
            dread_score = mean([int(v) for v in t.get("dread_score", {}).values()]) if t.get("dread_score") else 0.0
            results.append({
                "ruleId": rid,
                "level": "error" if dread_score >= 8.0 else "warning",
                "message": {"text": t.get("reviewer_message") or t.get("description", "")},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": repo_name}}}]
            })
        return {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "tm-scan", "rules": rules}}, "results": results}]
        }

    def save_report(self, report_content: str, repo_name: str):
        report_dir = self.config.get_repo_report_dir(repo_name)
        report_dir.mkdir(parents=True, exist_ok=True)
        path = report_dir / "threatmodel-report.md"
        with open(path, "w") as f:
            f.write(report_content)
        return path

    def save_sarif(self, sarif_content: Dict[str, Any], repo_name: str):
        report_dir = self.config.get_repo_report_dir(repo_name)
        report_dir.mkdir(parents=True, exist_ok=True)
        path = report_dir / "threatmodel-report.sarif"
        with open(path, "w") as f:
            json.dump(sarif_content, f, indent=2)
        return path
