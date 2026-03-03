# Enterprise Threat Modeling & Security Audit

## Repository Identity
**GitHub Owner / Username:** yantongggg
**Repository Name:** TM_o31
**Report Date:** 2026-03-03 06:49:22
**Report Version:** tm-scan v1.0.0
**Classification:** Highly Confidential

## 1. SYSTEM CONTEXT

### Actors
- Authenticated End User
- External Threat Actor
- Identity & Access Management (IAM)

### Assets
- Sensitive User/PII Data (High Value) - 22 evidence trace(s)
- Authentication Context/Tokens (High Value) - 33 evidence trace(s)

### Trust Boundaries & Assumptions
- **Boundary 1:** Internet to Application Gateway is inherently untrusted.
- **Boundary 2:** API Layer to Data Store relies on strict server-side authorization.
- **Assumption:** Client-side biometric/eKYC controls can be bypassed; server-side validation is mandatory.

## 2. ARCHITECTURE MODEL

```mermaid
flowchart TD
    subgraph TB1 [TB1: Untrusted Internet Zone]
        attacker((Threat Actor))
        user((End User / Browser))
    end

    subgraph TB2 [TB2: Application Internal Services]
        gateway[API Gateway / Auth Controller]
        backend[Python Backend / ML Service]
    end

    subgraph TB3 [TB3: Secure Data Zone]
        db[(Supabase PostgreSQL)]
    end

    %% Data Flows
    attacker -->|HTTPS / Untrusted Probes| gateway
    user -->|HTTPS / Auth Token| gateway
    gateway -->|Internal RPC / Authz Context| backend
    backend -->|SQL / DB Credentials| db

    classDef highRisk fill:#ffcccc,stroke:#cc0000;
    class gateway highRisk;
    class db highRisk;
    class attacker highRisk;
    class backend highRisk;
```

## 2.5 FULL THREAT-MODEL DIAGRAM

```mermaid
flowchart LR
    subgraph EXT [External / Untrusted Zone]
        ta((Threat Actor))
        eu((End User))
    end

    subgraph APP [Application Trust Zone]
        api[API Gateway / Auth Controller]
        svc[Backend Services]
    end

    subgraph DATA [Data / Secrets Zone]
        db[(Primary DB / Supabase)]
        sec[(Secrets / Config)]
    end

    %% Primary Flows
    eu -->|HTTPS| api
    ta -->|Recon / Probe| api
    api -->|Validated Context| svc
    svc -->|SQL / ORM| db
    svc -->|Secret Access| sec

    subgraph THR [Top Threat Scenarios]
        t1["TM-API-003: SQL Injection via String Concatenation / Unsafe Query Construction"]
        t2["TM-CRYPTO-001: Broken / Weak Cryptography [MD5/SHA1/DES/ECB] for Secrets or Sensitive Data"]
        t3["TM-PRIV-001: Improper Logging of PII/Secrets [Tokens, Passwords, Full User Objects]"]
        t4["TM-BIZ-001: Client-Side Trust of Financial Fields [Price/Quantity/Risk Score Manipulation]"]
        t5["TM-BIZ-002: KYC/AML Gate Bypass via Parameter Tampering or Workflow Skips"]
        t6["TM-AUTH-002: Credential Stuffing / Missing Rate Limiting on Auth Endpoints"]
    end

    %% Threat Mapping
    ta -.-> t1
    t1 -.-> svc
    ta -.-> t2
    t2 -.-> svc
    ta -.-> t3
    t3 -.-> svc
    ta -.-> t4
    t4 -.-> svc
    ta -.-> t5
    t5 -.-> svc
    ta -.-> t6
    t6 -.-> svc

    classDef highRisk fill:#ffcccc,stroke:#cc0000;
    class ta highRisk;
    class api highRisk;
    class sec highRisk;
    class svc highRisk;
    class db highRisk;
    class t1 highRisk;
    class t2 highRisk;
    class t3 highRisk;
    class t4 highRisk;
    class t5 highRisk;
    class t6 highRisk;
```

## 3. DATA FLOW MATRIX

| Source | Destination | Data Type | Protocol | Auth | Crosses Trust Boundary? |
|--------|-------------|-----------|----------|------|-------------------------|
| Frontend Client | API Gateway | User/eKYC Payload | HTTPS | JWT | **Yes** |
| API Gateway | ML Backend | Image/Biometric Data | Internal RPC | Service | No |
| Backend Service | Database | SQL Queries / PII | TCP/5432 | Password | **Yes** |
| App Config | Runtime | DB Secrets / API Keys | ENV | OS Level | No |

## 4. 5-D THREAT ANALYSIS (STRIDE + PASTA + LINDDUN + CWE + DREAD)

### [TM-API-003] SQL Injection via String Concatenation / Unsafe Query Construction
**STRIDE / LINDDUN:** Tampering / Non-repudiation | **CWE:** CWE-89
**DREAD Score:** Damage=10, Repro=9, Exploit=8, Users=9, Discover=8 (Avg: 8.80)

**PASTA Attack Scenario:**
- **Precondition:** Search/filter endpoints, admin panels, report generators
- **Exploitation:** Injected payloads via query params/body fields
- **Business Impact:** PII leakage, financial loss, database compromise

**Evidence Context (Actionable Trace):**
| File Path | Exact Line | Trigger (Rule/Keyword) | Severity | Source | Confidence |
|-----------|------------|------------------------|----------|--------|------------|
| `knowledge-base/kb-threats.yaml` | 103 | Keyword: `executequery` | MEDIUM | Keyword+Line | Medium |
| `knowledge-base/kb-threats.yaml` | 103 | Keyword: `statement` | MEDIUM | Keyword+Line | Medium |
| `knowledge-base/kb-keywords.yaml` | 274 | Keyword: `executequery` | MEDIUM | Keyword+Line | Medium |
| `knowledge-base/kb-keywords.yaml` | 261 | Keyword: `statement` | MEDIUM | Keyword+Line | Medium |
| `knowledge-base/kb-sast-rules.yaml` | 21 | Keyword: `statement` | MEDIUM | Keyword+Line | Medium |

**Mitigation Requirements:**
- Prepared statements everywhere
- Centralize query building; ban raw concatenation by linting
- Least-privileged DB roles

### [TM-CRYPTO-001] Broken / Weak Cryptography (MD5/SHA1/DES/ECB) for Secrets or Sensitive Data
**STRIDE / LINDDUN:** Information Disclosure / Linkability | **CWE:** CWE-327
**DREAD Score:** Damage=9, Repro=8, Exploit=7, Users=9, Discover=7 (Avg: 8.00)

**PASTA Attack Scenario:**
- **Precondition:** Password storage, token derivation, encryption at rest, backups
- **Exploitation:** Offline cracking; ciphertext pattern analysis
- **Business Impact:** Account compromise, regulatory breach, reputational damage

**Evidence Context (Actionable Trace):**
| File Path | Exact Line | Trigger (Rule/Keyword) | Severity | Source | Confidence |
|-----------|------------|------------------------|----------|--------|------------|
| `knowledge-base/kb-threats.yaml` | 346 | Keyword: `bcrypt` | MEDIUM | Keyword+Line | Medium |
| `knowledge-base/kb-threats.yaml` | 346 | Keyword: `argon2` | MEDIUM | Keyword+Line | Medium |
| `knowledge-base/kb-keywords.yaml` | 488 | Keyword: `bcrypt` | MEDIUM | Keyword+Line | Medium |
| `knowledge-base/kb-keywords.yaml` | 496 | Keyword: `argon2` | MEDIUM | Keyword+Line | Medium |

**Mitigation Requirements:**
- Ban weak algorithms by policy/lint
- Use AEAD modes (AES-GCM)
- Centralize crypto utilities and key management (KMS/HSM)

### [TM-PRIV-001] Improper Logging of PII/Secrets (Tokens, Passwords, Full User Objects)
**STRIDE / LINDDUN:** Information Disclosure / Detectability | **CWE:** CWE-532
**DREAD Score:** Damage=8, Repro=9, Exploit=7, Users=9, Discover=8 (Avg: 8.20)

**PASTA Attack Scenario:**
- **Precondition:** Application logs, APM traces, centralized log stores
- **Exploitation:** Sensitive fields emitted without redaction
- **Business Impact:** Privacy breach, regulatory fines, incident response cost

**Evidence Context (Actionable Trace):**
| File Path | Exact Line | Trigger (Rule/Keyword) | Severity | Source | Confidence |
|-----------|------------|------------------------|----------|--------|------------|
| `knowledge-base/kb-threats.yaml` | 311 | Keyword: `password` | HIGH | Keyword+Line | Medium |
| `knowledge-base/kb-threats.yaml` | 382 | Keyword: `console.log` | LOW | Keyword+Line | Medium |
| `knowledge-base/kb-keywords.yaml` | 240 | Keyword: `password` | HIGH | Keyword+Line | Medium |
| `knowledge-base/kb-keywords.yaml` | 442 | Keyword: `console.log` | LOW | Keyword+Line | Medium |
| `knowledge-base/kb-sast-rules.yaml` | 46 | Keyword: `password` | HIGH | Keyword+Line | Medium |
| `src/reporter.py` | 388 | Keyword: `password` | HIGH | Keyword+Line | Medium |

**Mitigation Requirements:**
- Structured logging + field allowlists
- Redaction middleware for HTTP headers/body
- Secrets scanning on logs and APM payloads

### [TM-BIZ-001] Client-Side Trust of Financial Fields (Price/Quantity/Risk Score Manipulation)
**STRIDE / LINDDUN:** Tampering / Unawareness | **CWE:** CWE-602
**DREAD Score:** Damage=10, Repro=7, Exploit=7, Users=8, Discover=6 (Avg: 7.60)

**PASTA Attack Scenario:**
- **Precondition:** Checkout, payout, underwriting, risk scoring APIs
- **Exploitation:** Modify client parameters, replay requests
- **Business Impact:** Financial loss, AML/KYC violations, chargebacks

**Evidence Context (Actionable Trace):**
| File Path | Exact Line | Trigger (Rule/Keyword) | Severity | Source | Confidence |
|-----------|------------|------------------------|----------|--------|------------|
| `knowledge-base/kb-threats.yaml` | 728 | Keyword: `risk_score` | HIGH | Keyword+Line | Medium |
| `knowledge-base/kb-threats.yaml` | 728 | Keyword: `maxriskscore` | HIGH | Keyword+Line | Medium |
| `knowledge-base/kb-keywords.yaml` | 36 | Keyword: `risk_score` | HIGH | Keyword+Line | Medium |
| `knowledge-base/kb-keywords.yaml` | 48 | Keyword: `maxriskscore` | HIGH | Keyword+Line | Medium |

**Mitigation Requirements:**
- Server-side recalculation of totals and risk
- Signed quotes and expiry for price offers
- Fraud monitoring for abnormal deltas

### [TM-BIZ-002] KYC/AML Gate Bypass via Parameter Tampering or Workflow Skips
**STRIDE / LINDDUN:** Tampering / Unawareness | **CWE:** CWE-285
**DREAD Score:** Damage=10, Repro=6, Exploit=6, Users=9, Discover=6 (Avg: 7.40)

**PASTA Attack Scenario:**
- **Precondition:** Payout, withdrawal, onboarding, compliance APIs
- **Exploitation:** Tampering with approval flags or calling internal endpoints
- **Business Impact:** Illicit payouts, regulatory exposure, sanctions risk

**Evidence Context (Actionable Trace):**
| File Path | Exact Line | Trigger (Rule/Keyword) | Severity | Source | Confidence |
|-----------|------------|------------------------|----------|--------|------------|
| `knowledge-base/kb-threats.yaml` | 767 | Keyword: `hold_transaction` | HIGH | Keyword+Line | Medium |
| `knowledge-base/kb-threats.yaml` | 767 | Keyword: `previous_review` | HIGH | Keyword+Line | Medium |
| `knowledge-base/kb-keywords.yaml` | 54 | Keyword: `hold_transaction` | HIGH | Keyword+Line | Medium |
| `knowledge-base/kb-keywords.yaml` | 62 | Keyword: `previous_review` | HIGH | Keyword+Line | Medium |

**Mitigation Requirements:**
- Server-side gates at payout/withdrawal
- Immutable audit trail + dual control for overrides
- Least privilege for internal compliance APIs

### [TM-AUTH-002] Credential Stuffing / Missing Rate Limiting on Auth Endpoints
**STRIDE / LINDDUN:** Denial of Service / Detectability | **CWE:** CWE-307
**DREAD Score:** Damage=8, Repro=9, Exploit=8, Users=8, Discover=8 (Avg: 8.20)

**PASTA Attack Scenario:**
- **Precondition:** Login, token refresh, password reset, OTP endpoints
- **Exploitation:** High-rate brute force and credential stuffing
- **Business Impact:** Account takeover, auth outage, infra cost spike

**Evidence Context (Actionable Trace):**
| File Path | Exact Line | Trigger (Rule/Keyword) | Severity | Source | Confidence |
|-----------|------------|------------------------|----------|--------|------------|
| `knowledge-base/kb-threats.yaml` | 25 | Keyword: `authenticate` | MEDIUM | Keyword+Line | Medium |
| `knowledge-base/kb-keywords.yaml` | 232 | Keyword: `authenticate` | MEDIUM | Keyword+Line | Medium |
| `src/inventory.py` | 86 | Keyword: `authenticate` | MEDIUM | Keyword+Line | Medium |
| `src/reporter.py` | 274 | Keyword: `authenticate` | MEDIUM | Keyword+Line | Medium |

**Mitigation Requirements:**
- IP + account throttling
- Credential stuffing detection (known breached passwords, velocity checks)
- Step-up MFA for risky logins

### [TM-CLOUD-002] Hardcoded Cloud Credentials / Service Account Keys in Source
**STRIDE / LINDDUN:** Information Disclosure / Detectability | **CWE:** CWE-798
**DREAD Score:** Damage=10, Repro=8, Exploit=8, Users=9, Discover=7 (Avg: 8.40)

**PASTA Attack Scenario:**
- **Precondition:** Git repositories, build logs, artifact stores
- **Exploitation:** Leaked secrets via commits or CI output
- **Business Impact:** Cloud account takeover, data breach, crypto-mining, service disruption

**Evidence Context (Actionable Trace):**
| File Path | Exact Line | Trigger (Rule/Keyword) | Severity | Source | Confidence |
|-----------|------------|------------------------|----------|--------|------------|
| `knowledge-base/kb-threats.yaml` | 439 | Rule: `vuln-hardcoded-credentials` | CRITICAL | SAST | High |
| `knowledge-base/kb-keywords.yaml` | 184 | Rule: `vuln-hardcoded-credentials` | CRITICAL | SAST | High |
| `knowledge-base/kb-sast-rules.yaml` | 40 | Rule: `vuln-hardcoded-credentials` | CRITICAL | SAST | High |
| `src/scanner.py` | 354 | Rule: `vuln-hardcoded-credentials` | CRITICAL | SAST | High |

**Mitigation Requirements:**
- Secret scanning in CI (gitleaks) + pre-commit hooks
- Use IAM roles / workload identity federation
- Central secret manager with rotation and auditing

## 5. PASTA ANALYSIS (Attack Trees & Paths)

```mermaid
flowchart TD
    a0["Precondition: Attacker maps attack surface"]
    a1["Initial Exploit: TM-API-003: SQL Injection via String Concatenation / Unsafe Query Construction"]
    a2["Pivot/Escalate: TM-CRYPTO-001: Broken / Weak Cryptography [MD5/SHA1/DES/ECB] for Secrets or Sensitive Data"]
    a3["Objective Reached: TM-PRIV-001: Improper Logging of PII/Secrets [Tokens, Passwords, Full User Objects]"]
    a4["Business Impact: High regulatory and financial loss"]

    a0 -.-> a1
    a1 -.-> a2
    a2 -.-> a3
    a3 -.-> a4

    classDef highRisk fill:#ffcccc,stroke:#cc0000;
    class a1 highRisk;
    class a2 highRisk;
    class a3 highRisk;
    linkStyle 0 stroke:#cc0000,stroke-width:2px,stroke-dasharray: 5 5;
    linkStyle 1 stroke:#cc0000,stroke-width:2px,stroke-dasharray: 5 5;
    linkStyle 2 stroke:#cc0000,stroke-width:2px,stroke-dasharray: 5 5;
    linkStyle 3 stroke:#cc0000,stroke-width:2px,stroke-dasharray: 5 5;
```

## 6. RISK SUMMARY & ACTION PLAN

| Threat ID | Threat Name | Risk Level | DREAD Avg | Mitigation Priority |
|-----------|-------------|------------|-----------|---------------------|
| TM-API-003 | SQL Injection via String Concatenation / Unsafe Query Construction | **Critical** | 8.80 | P0 - Immediate |
| TM-CRYPTO-001 | Broken / Weak Cryptography (MD5/SHA1/DES/ECB) for Secrets or Sensitive Data | **Critical** | 8.00 | P0 - Immediate |
| TM-PRIV-001 | Improper Logging of PII/Secrets (Tokens, Passwords, Full User Objects) | **Critical** | 8.20 | P0 - Immediate |
| TM-BIZ-001 | Client-Side Trust of Financial Fields (Price/Quantity/Risk Score Manipulation) | **High** | 7.60 | P1 - Current Sprint |
| TM-BIZ-002 | KYC/AML Gate Bypass via Parameter Tampering or Workflow Skips | **High** | 7.40 | P1 - Current Sprint |
| TM-AUTH-002 | Credential Stuffing / Missing Rate Limiting on Auth Endpoints | **Critical** | 8.20 | P0 - Immediate |
| TM-CLOUD-002 | Hardcoded Cloud Credentials / Service Account Keys in Source | **Critical** | 8.40 | P0 - Immediate |

---
*Secret Findings (gitleaks): 0*
*Total Packages (SBOM): 0*
*Report generated automatically by tm-scan v1.0.0 on 2026-03-03 06:49:22*
*End of Threat Model Report*