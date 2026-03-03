# TM-scan — Enterprise Agentic Threat Modeling Engine

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.9+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

**A zero-PAT, five-dimensional threat modeling scanner that runs locally or in CI/CD**

Generates Markdown, SARIF, and Mermaid DFDs with deterministic PR feedback — no external LLMs required.

</div>

---

## Table of Contents

- [Overview](#overview)
- [Why tm-scan](#why-tm-scan)
- [Architecture](#architecture)
- [Five-Dimensional Framework](#five-dimensional-framework)
- [Quickstart](#quickstart)
- [CI/CD Integration](#cicd-integration)
- [PR Reviewer Bot](#pr-reviewer-bot)
- [Configuration](#configuration)
- [Outputs](#outputs)
- [Knowledge Base](#knowledge-base)
- [Development](#development)

---

## Overview

**tm-scan** is an automated threat modeling scanner that combines multiple security frameworks into a single, deterministic engine. It scans code repositories for security-relevant evidence, maps findings to threat models, and generates actionable reports with inline PR feedback.

### Key Features

| Feature | Description |
|---------|-------------|
| **Zero-PAT Auth** | Uses GitHub Actions token in CI or `gh` CLI locally — no manual PAT management |
| **5-D Framework** | STRIDE + PASTA + LINDDUN + CWE + DREAD in one pass |
| **Deterministic** | Rule-based matching produces consistent, reproducible results |
| **Line-Level Precision** | SAST rules with exact line numbers for actionable findings |
| **Multi-Format Output** | Markdown reports, SARIF, Evidence JSON, optional PDF |
| **PR Guardrails** | Automatic inline comments with reviewer guidance and fix snippets |
| **Quality Gates** | DREAD-based threshold enforcement (avg ≥ 8.0 fails CI) |
| **Enterprise Ready** | Supports GitHub Enterprise Server, custom API endpoints |
| **Auto-Save Reports** | Commits threat models back to target repository |

---

## Why tm-scan

### For Security Teams
- **Scale:** Scan entire organizations with time-based and allowlist filtering
- **Consistency:** Deterministic rules ensure repeatable results
- **Evidence-Based:** All findings backed by exact code locations and threat model references
- **Coverage:** 18+ threat patterns covering API, Auth, Crypto, Privacy, Cloud, K8s, App, Web, AI, and Business Logic

### For Development Teams
- **Fast Feedback:** CI/CD integration with inline PR comments
- **Actionable:** Specific fix snippets with line numbers, not generic warnings
- **Zero Config:** Works out of the box with sensible defaults
- **Local Testing:** Run on your machine before pushing

### For Compliance
- **Audit Trail:** JSON evidence files for every scan
- **CWE Mapping:** Direct mapping to MITRE CWE standard
- **DREAD Scoring:** Quantified risk assessment
- **Privacy-Aware:** LINDDUN categories for data protection

---

## Architecture

### High-Level Flow

```mermaid
flowchart TD
    subgraph Input["Input Sources"]
        GH[GitHub API/CLI]
        Local[Local Directory]
        KB[Knowledge Base<br/>kb-threats.yaml<br/>kb-sast-rules.yaml<br/>kb-keywords.yaml]
    end

    subgraph Core["tm-scan Core Engine"]
        Inv[Inventory Module<br/>src/inventory.py]
        Sel[Selector Module<br/>src/selector.py]
        Cln[Cloner Module<br/>src/cloner.py]
        Scn[Scanner Module<br/>src/scanner.py]
        GT[Gitleaks Wrapper<br/>src/gitleaks_wrapper.py]
        ST[Syft SBOM Wrapper<br/>src/sbom_wrapper.py]
        Rep[Reporter Module<br/>src/reporter.py]
    end

    subgraph Output["Outputs"]
        MD[Markdown Report<br/>+ Mermaid DFD]
        SARIF[SARIF File]
        EJSON[Evidence JSON]
        ESM[Evidence Summary MD]
        PDF[PDF Report Optional]
    end

    subgraph CI["CI/CD Integration"]
        Workflow[tm-scan-agent.yml<br/>.github/workflows/]
        PRBot[PR Reviewer Bot<br/>scripts/local_pr_reviewer.py]
        AutoCommit[Auto-commit Report<br/>ThreatModelling_result/]
    end

    GH --> Inv
    Local --> Scn
    KB --> Scn
    KB --> Rep

    Inv --> Sel
    Sel --> Cln
    Cln --> Scn
    Scn --> GT
    Scn --> ST
    Scn --> Rep
    GT --> Rep
    ST --> Rep

    Rep --> MD
    Rep --> SARIF
    Rep --> EJSON
    Rep --> ESM
    Rep --> PDF

    EJSON --> PRBot
    MD --> AutoCommit
```

### Module Architecture

```mermaid
graph TB
    subgraph CLI["CLI Entry Point: tm-scan"]
        Parser[Argument Parser]
        Config[Config Handler<br/>Hybrid Auth Detection]
        Logger[Logging Setup]
    end

    subgraph Pipeline["Scanning Pipeline"]
        Inv[RepoInventory<br/>GitHub API/gh CLI]
        Sel[RepoSelector<br/>Priority Scoring]
        Cln[RepoCloner<br/>Git Operations]
        Scn[EvidenceScanner<br/>Keyword + SAST Rules]
    end

    subgraph Tools["External Tools"]
        GL[GitleaksWrapper<br/>Secret Scanning]
        SY[SyftWrapper<br/>SBOM Generation]
    end

    subgraph Reporting["Reporting Layer"]
        TMR[ThreatModelReporter<br/>5-D Analysis]
        PDF[PdfReportRenderer<br/>WeasyPrint]
    end

    subgraph CI["CI Components"]
        WF[tm-scan-agent.yml]
        PRB[local_pr_reviewer.py<br/>Deterministic Reviewer]
    end

    subgraph Knowledge["Knowledge Base"]
        KB_T[kb-threats.yaml<br/>18+ Patterns]
        KB_S[kb-sast-rules.yaml<br/>Line-Level Rules]
        KB_K[kb-keywords.yaml<br/>150+ Keywords]
    end

    Parser --> Config
    Config --> Logger
    Logger --> Inv
    Inv --> Sel
    Sel --> Cln
    Cln --> Scn
    Scn --> GL
    Scn --> SY
    Scn --> TMR
    GL --> TMR
    SY --> TMR
    TMR --> PDF
    KB_T --> Scn
    KB_S --> Scn
    KB_K --> Scn
    KB_T --> TMR
    KB_T --> PRB
    TMR --> WF
    WF --> PRB
```

### End-to-End Scanning Workflow

```mermaid
flowchart TD
    Start([User invokes tm-scan]) --> Parse[Parse CLI arguments]
    Parse --> Config[Load Configuration<br/>Detect hybrid auth]
    Config --> Auth{Authentication<br/>Method?}

    Auth -->|GITHUB_ACTIONS env| CI[Use CI Token]
    Auth -->|gh auth token| Local[Use CLI Token]
    Auth -->|--github-token| Arg[Use provided token]

    CI --> Mode
    Local --> Mode
    Arg --> Mode{Scan Mode?}

    Mode -->|Local Dir| LocalDir[Use local directory<br/>Skip inventory/clone]
    Mode -->|Organization| Inv[Inventory: Fetch Repos<br/>API or gh CLI]

    Inv --> Filter[Filter: Time + Allowlist<br/>Exclude archived]
    Filter --> Select[Selector: Score & Prioritize<br/>Patch-specific signals]
    Select --> DryRun{Dry Run?}
    DryRun -->|Yes| OutputDry[Output selection list<br/>Exit]
    DryRun -->|No| Clone[Cloner: Git Clone<br/>Shallow depth 1]

    LocalDir --> Scan
    Clone --> Scan[Scanner: Evidence Discovery]

    Scan --> FileScan[Walk directory tree<br/>Skip excluded dirs]
    FileScan --> Pattern[File pattern matching<br/>OpenAPI, DB, Config]
    Pattern --> Content[Content scanning<br/>150+ keywords + SAST rules]

    Content --> Evidence[Collect evidence:<br/>keyword_hits, sast_hits<br/>auth_hints, db_hints]
    Evidence --> SaveEvid[Save evidence.json<br/>evidence-summary.md]

    SaveEvid --> Gitleaks{Gitleaks<br/>enabled?}
    Gitleaks -->|Yes| SecretScan[gitleaks detect<br/>Secret scanning]
    Gitleaks -->|No| SyftCheck
    SecretScan --> SaveGL[Save gitleaks-summary.json]

    SaveGL --> SyftCheck{Syft<br/>enabled?}
    SyftCheck -->|Yes| SBOM[syft scan<br/>SBOM generation]
    SyftCheck -->|No| Match
    SBOM --> SaveSyft[Save sbom-summary.json]

    SaveSyft --> Match[Match Threats:<br/>Keywords × SAST Rules × KB]
    Match --> DREAD[Calculate DREAD scores<br/>Per threat]

    DREAD --> QualityGate{Quality Gate<br/>DREAD avg ≥ 8.0?}
    QualityGate -->|Yes| Fail[Exit non-zero<br/>Critical threshold]
    QualityGate -->|No| Generate[Generate Reports]

    Generate --> MD[Markdown Report<br/>+ Mermaid DFDs<br/>+ Line evidence]
    Generate --> SARIF[SARIF Report<br/>CWE-mapped]
    Generate --> PDF{PDF<br/>enabled?}

    PDF -->|Yes| RenderPDF[Render PDF Report<br/>WeasyPrint]
    PDF -->|No| CI_Actions
    RenderPDF --> CI_Actions([CI Actions])

    Fail --> PRBot{In CI/CD?}
    PRBot -->|Yes| RunPRBot[Run Deterministic<br/>PR Reviewer]
    PRBot -->|No| End
    RunPRBot --> End([End])
```

### Evidence Discovery Flow

```mermaid
flowchart TD
    subgraph Input["Knowledge Base Inputs"]
        KB_Keywords[kb-keywords.yaml<br/>150+ keywords<br/>Categorized]
        KB_SAST[kb-sast-rules.yaml<br/>Line-level regex<br/>AND/OR logic]
        FilePatterns[File patterns<br/>OpenAPI, DB, Config]
    end

    subgraph Scanner["EvidenceScanner Engine"]
        Walk[Walk directory tree]
        Filter[Filter excluded dirs<br/>git, node_modules<br/>vendor, build]
        Check[Check file patterns]
        Read[Read file content]
        MatchKW[Match keywords<br/>Case-insensitive]
        MatchSAST[Match SAST rules<br/>Line-by-line]
        ExtractHints[Extract hints<br/>auth, db, secrets]
    end

    subgraph Output["Evidence Collection"]
        KeywordHits[keyword_hits<br/>Category, priority, file]
        SASTHits[sast_hits<br/>Rule ID, line, severity, CWE]
        AuthHints[auth_hints<br/>Auth mechanisms found]
        DBHints[db_hints<br/>Database types]
        RiskyConfigs[risky_config_hints<br/>URLs, credentials]
    end

    KB_Keywords --> MatchKW
    KB_SAST --> MatchSAST
    FilePatterns --> Check

    Walk --> Filter
    Filter --> Check
    Check -->|Match| Read
    Read --> MatchKW
    Read --> MatchSAST

    MatchKW --> ExtractHints
    MatchSAST --> ExtractHints

    MatchKW --> KeywordHits
    MatchSAST --> SASTHits
    ExtractHints --> AuthHints
    ExtractHints --> DBHints
    ExtractHints --> RiskyConfigs
```

### Threat Matching Process

```mermaid
flowchart LR
    subgraph Evidence["Evidence from Scanner"]
        EK[keyword_hits<br/>Set of keywords]
        ES[sast_hits<br/>Set of rule IDs + CWEs]
    end

    subgraph Knowledge["Knowledge Base"]
        KT[kb-threats.yaml<br/>18+ threat definitions]
    end

    subgraph Process["Matching Engine"]
        Iter1[For each threat]
        GetKeys[Get threat keywords]
        GetRules[Get trigger rules]
        GetCWE[Get threat CWE]
        IntersectK[Intersect keywords]
        IntersectR[Intersect rule IDs]
        IntersectC[Match CWE]
        Union{Union matches}
        Score[Score by evidence count]
        Sort[Sort by relevance]
    end

    subgraph Output["Matched Threats"]
        MT[Relevant threats<br/>With evidence counts]
        Details[Keyword hits<br/>SAST hits with lines<br/>File locations]
    end

    EK --> IntersectK
    ES --> IntersectR
    ES --> IntersectC
    KT --> Iter1

    Iter1 --> GetKeys
    Iter1 --> GetRules
    Iter1 --> GetCWE
    GetKeys --> IntersectK
    GetRules --> IntersectR
    GetCWE --> IntersectC

    IntersectK --> Union
    IntersectR --> Union
    IntersectC --> Union
    Union --> Score
    Score --> Sort
    Sort --> MT
    MT --> Details
```

### Report Generation Flow

```mermaid
flowchart TD
    subgraph Inputs["Report Inputs"]
        Evidence[evidence.json<br/>+ sast_hits with lines]
        KB[kb-threats.yaml]
        Gitleaks[gitleaks-summary.json]
        SBOM[sbom-summary.json]
        Config[Scan config]
    end

    subgraph Report["ThreatModelReporter"]
        Match[Match threats to evidence<br/>Resolve exact lines]
        Exec[Generate executive summary]
        Risk[Calculate risk level<br/>Avg DREAD]
        DFD[Generate Mermaid DFD<br/>Dynamic based on files]
        FullDiagram[Generate full threat<br/>model diagram]
        Matrix[Generate data flow matrix]
        FiveD[Build 5-D analysis<br/>STRIDE+PASTA+LINDDUN<br/>+CWE+DREAD]
        PASTA[Build PASTA diagram<br/>Attack tree]
        RiskSum[Risk summary table<br/>Priority levels]
    end

    subgraph Outputs["Report Formats"]
        MD[threatmodel-report.md<br/>Full Markdown]
        SARIF[threatmodel-report.sarif<br/>SARIF v2.1.0]
        PDF[threatmodel-report.pdf<br/>Optional PDF]
    end

    Evidence --> Match
    KB --> Match
    Match --> Exec
    Evidence --> Risk
    Gitleaks --> Risk
    Risk --> Exec

    Evidence --> DFD
    KB --> DFD
    Evidence --> FullDiagram
    KB --> FullDiagram
    Evidence --> Matrix

    Match --> FiveD
    Evidence --> FiveD
    Match --> PASTA
    Match --> RiskSum

    Exec --> MD
    DFD --> MD
    FullDiagram --> MD
    Matrix --> MD
    FiveD --> MD
    PASTA --> MD
    RiskSum --> MD

    Match --> SARIF

    MD --> PDF
```

### CI/CD Workflow

```mermaid
sequenceDiagram
    participant Dev as Developer
    participant GH as GitHub
    participant WF as tm-scan Workflow
    participant Tool as tm-scan Engine
    participant Scanner as Evidence Scanner
    participant Rep as Reporter
    participant PRBot as PR Reviewer Bot
    participant Commit as Auto-Commit

    Dev->>GH: Push to PR
    GH->>WF: Trigger workflow<br/>(skip if [skip tm-scan])
    WF->>Tool: Checkout tm-scan
    WF->>Tool: Checkout target repo

    Tool->>Scanner: Run local scan<br/>--local-dir target-repo
    Scanner->>Scanner: Walk files
    Scanner->>Scanner: Match keywords + SAST
    Scanner->>Scanner: Collect evidence<br/>with line numbers

    Scanner->>Rep: Pass evidence
    Rep->>Rep: Match threats
    Rep->>Rep: Calculate DREAD
    Rep->>Rep: Generate reports

    alt DREAD >= 8.0
        Rep--xWF: Exit non-zero
        WF->>PRBot: Trigger on failure
        PRBot->>PRBot: Load evidence.json
        PRBot->>PRBot: Match threats to diff
        PRBot->>GH: Post inline PR comments
    else DREAD < 8.0
        Rep->>WF: Return success
        WF->>Commit: Commit report to<br/>ThreatModelling_result/
        Commit->>GH: Push report
    end

    WF->>GH: Upload artifacts<br/>Comment PR with summary
```

---

## Five-Dimensional Framework

tm-scan fuses five complementary security frameworks into a unified threat model:

```mermaid
graph LR
    subgraph Dimensions["5-Dimensional Framework"]
        STRIDE[STRIDE<br/>Spoofing, Tampering<br/>Repudiation, Info Disclosure<br/>DoS, Elevation of Privilege]
        PASTA[PASTA<br/>Threat Actor, Attack Surface<br/>Attack Vector, Business Impact]
        LINDDUN[LINDDUN<br/>Linkability, Identifiability<br/>Non-repudiation, Detectability<br/>Disclosure, Unawareness<br/>Non-compliance]
        CWE[CWE<br/>MITRE Weakness Enumeration]
        DREAD[DREAD<br/>Damage, Reproducibility<br/>Exploitability, Affected Users<br/>Discoverability]
    end

    Evidence[Code Evidence<br/>+ SAST Rules] --> STRIDE
    Evidence --> PASTA
    Evidence --> LINDDUN
    Evidence --> CWE
    Evidence --> DREAD

    STRIDE --> Report[Unified Report<br/>With Line Evidence]
    PASTA --> Report
    LINDDUN --> Report
    CWE --> Report
    DREAD --> Report
```

### 1. STRIDE Categories

| Category | Description | Example Indicators |
|----------|-------------|-------------------|
| **Spoofing** | Impersonation of users or systems | `jwt`, `oauth`, `auth`, `login`, `session` |
| **Tampering** | Unauthorized data modification | `sql`, `update`, `delete`, `transaction` |
| **Repudiation** | Denial of actions | Missing audit logs, non-atomic operations |
| **Information Disclosure** | Data exposure | `secret`, `password`, `api_key`, `token` |
| **Denial of Service** | Availability impact | Unbounded loops, missing rate limits |
| **Elevation of Privilege** | Unauthorized privilege gain | `admin`, `escalate`, `sudo`, `role` |

### 2. PASTA Context

| Element | Description | Example |
|---------|-------------|---------|
| **Threat Actor** | Who is attacking? | External authenticated user, insider, automated scanner |
| **Attack Surface** | Where is the entry point? | REST API, GraphQL endpoint, webhook handler |
| **Attack Vector** | How is the attack delivered? | Manipulated IDs, user-controlled URLs, input payload |
| **Business Impact** | What is the damage? | Data breach, financial loss, compliance violation |

### 3. LINDDUN Privacy

| Category | Privacy Concern | Detection |
|----------|-----------------|-----------|
| **Linkability** | Data can be linked across contexts | Shared identifiers, cross-tenant data access |
| **Identifiability** | Data can identify individuals | PII in logs, user tables without protection |
| **Non-repudiation** | Actions cannot be denied | Missing audit trails, unsigned operations |
| **Detectability** | Data disclosure can be detected | Error messages revealing internal state |
| **Disclosure of Information** | Unintended data exposure | Debug info, verbose errors |
| **Unawareness** | Subjects unaware of data use | Hidden data collection, opaque processing |
| **Non-compliance** | Regulatory violations | Missing consent, inadequate data protection |

### 4. CWE Mapping

Each threat maps to MITRE CWE identifiers for standards compliance:
- `CWE-79`: Cross-Site Scripting (XSS)
- `CWE-89`: SQL Injection
- `CWE-639`: IDOR (Broken Object Level Authorization)
- `CWE-918`: Server-Side Request Forgery
- `CWE-798`: Hardcoded Credentials
- `CWE-327`: Broken Cryptography
- `CWE-502`: Insecure Deserialization
- `CWE-611`: XXE (XML External Entity)
- `CWE-347`: Weak JWT Verification
- And 50+ more...

### 5. DREAD Scoring

| Factor | Scale | Weight |
|--------|-------|--------|
| **Damage** | 1-10 | How bad is the impact? |
| **Reproducibility** | 1-10 | How easy is it to reproduce? |
| **Exploitability** | 1-10 | How much work is required? |
| **Affected Users** | 1-10 | How many users are impacted? |
| **Discoverability** | 1-10 | How easy is it to find? |

**Quality Gate:** Average DREAD ≥ 8.0 fails CI and marks SARIF as `error`.

---

## Quickstart

### Prerequisites

```bash
# Python 3.9+
python --version

# GitHub CLI (for local scanning)
gh --version

# Optional: gitleaks and syft for enhanced scanning
gitleaks --version
syft --version
```

### Installation

```bash
# Clone repository
git clone https://github.com/yantongggg/TM_o31.git
cd TM_o31

# Install dependencies
python -m pip install -r requirements.txt

# Make executable
chmod +x tm-scan
```

### Local Scan

```bash
# Scan local directory (recommended for single repo)
./tm-scan --local-dir . --mode quick --fail-on-critical

# Scan organization repos
gh auth login
./tm-scan --org my-org --since-days 30 --max-repos 10

# Dry run (show selected repos without scanning)
./tm-scan --org my-org --since-days 30 --dry-run
```

### Output Location

All artifacts are stored under `~/tm-output/`:

```
~/tm-output/
├── reports/
│   └── <repo-name>/
│       └── 2025-01-15/
│           ├── threatmodel-report.md      # Full report with Mermaid DFD
│           ├── threatmodel-report.sarif   # GitHub Security import
│           ├── evidence.json              # Raw findings with line numbers
│           ├── evidence-summary.md        # Evidence overview
│           ├── gitleaks-summary.json      # Secret scan results
│           └── sbom-summary.json          # Dependency inventory
├── run-metadata/
│   ├── run-config.json                   # Scan configuration
│   ├── repo-inventory.json               # All discovered repos
│   ├── selected-repos.txt                # Prioritized selection
│   └── skipped-repos.txt                 # Unselected repos
└── logs/
    └── run-20250115_143022.log           # Detailed execution log
```

---

## CI/CD Integration

### Workflow File

Create `.github/workflows/tm-scan-agent.yml`:

```yaml
name: tm-scan agentic workflow

on:
  pull_request:
    branches: ["**"]
    types: [opened, synchronize, reopened, ready_for_review]
  push:
    branches: ["main"]
    paths-ignore:
      - 'ThreatModelling_result/**'
  workflow_dispatch:

permissions:
  contents: write
  pull-requests: write
  security-events: write

jobs:
  tm-scan:
    if: ${{ !contains(github.event.head_commit.message, '[skip tm-scan]') }}
    runs-on: ubuntu-latest
    steps:
      - name: Checkout PR code
        uses: actions/checkout@v4
        with:
          path: target-repo
          fetch-depth: 0

      - name: Checkout tm-scan
        uses: actions/checkout@v4
        with:
          repository: ${{ github.repository_owner }}/TM_o31
          path: tm-scan-tool
          token: ${{ secrets.GITHUB_TOKEN }}

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install tm-scan dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r tm-scan-tool/requirements.txt

      - name: Run tm-scan (local quick mode)
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITHUB_ACTIONS: "true"
          REPO_OWNER: ${{ github.repository_owner }}
          REPO_NAME: ${{ github.event.repository.name }}
        run: |
          cd tm-scan-tool
          python tm-scan --local-dir "$GITHUB_WORKSPACE/target-repo" --mode quick

      - name: Find Markdown Report
        id: find-md
        if: success() || failure()
        run: |
          MD_PATH=$(find "$HOME/tm-output" -name "threatmodel-report.md" -print -quit 2>/dev/null || true)
          if [ -n "$MD_PATH" ]; then
            echo "found=true" >> "$GITHUB_OUTPUT"
            echo "md_file=$MD_PATH" >> "$GITHUB_OUTPUT"
          else
            echo "found=false" >> "$GITHUB_OUTPUT"
          fi

      - name: Upload Threat Model Reports as Artifact
        if: (success() || failure()) && steps.find-md.outputs.found == 'true'
        uses: actions/upload-artifact@v4
        with:
          name: threat-model-reports
          path: ~/tm-output/reports/target-repo/

      - name: Run deterministic PR reviewer
        if: failure() && github.event_name == 'pull_request'
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITHUB_REPOSITORY: ${{ github.repository }}
          GITHUB_EVENT_PATH: ${{ github.event_path }}
        run: |
          python tm-scan-tool/scripts/local_pr_reviewer.py

      - name: Comment PR with Threat Model Report
        if: (success() || failure()) && github.event_name == 'pull_request' && steps.find-md.outputs.found == 'true'
        uses: marocchino/sticky-pull-request-comment@v2
        with:
          header: threat-model-report
          path: ${{ steps.find-md.outputs.md_file }}

      - name: Publish Job Summary
        if: success() || failure()
        run: |
          if [ "${{ steps.find-md.outputs.found }}" = "true" ]; then
            echo "## 🛡️ Threat Modeling Scan Results" >> $GITHUB_STEP_SUMMARY
            cat "${{ steps.find-md.outputs.md_file }}" >> $GITHUB_STEP_SUMMARY
          fi

      - name: Save Report to Repository
        if: (success() || failure()) && steps.find-md.outputs.found == 'true'
        run: |
          TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
          REPO_OWNER="${{ github.repository_owner }}"
          REPO_NAME="${{ github.event.repository.name }}"

          REPORT_DIR="$GITHUB_WORKSPACE/target-repo/ThreatModelling_result"
          mkdir -p "$REPORT_DIR"

          NEW_FILENAME="threatmodel-report_${REPO_OWNER}_${REPO_NAME}_${TIMESTAMP}.md"

          cp "${{ steps.find-md.outputs.md_file }}" "$REPORT_DIR/$NEW_FILENAME"
          echo "Report saved to $REPORT_DIR/$NEW_FILENAME"

      - name: Commit and Push Report
        if: (success() || failure()) && steps.find-md.outputs.found == 'true'
        uses: stefanzweifel/git-auto-commit-action@v5
        with:
          repository: ./target-repo
          commit_message: "docs(security): auto-save threat modeling report for ${{ github.repository }}"
          file_pattern: "ThreatModelling_result/*.md"
```

### What Happens in CI?

1. **Checkout** — Gets your PR code and tm-scan tool
2. **Scan** — Runs `tm-scan` in local mode
3. **Quality Gate** — Checks DREAD average
4. **Save Report** — Commits report to `ThreatModelling_result/`
5. **PR Comment** — Posts summary as PR comment
6. **PR Review** — On failure, posts inline comments with exact lines

---

## PR Reviewer Bot

The deterministic PR reviewer provides inline feedback without external LLMs:

### How It Works

```mermaid
flowchart LR
    Evidence[evidence.json<br/>with sast_hits] --> Match[Match Threats]
    KB[kb-threats.yaml] --> Match

    Match --> ReviewMsg[reviewer_message]
    Match --> FixSnippet[auto_fix_snippet]

    PRDiff[PR Diff] --> Locate[Find Keywords in Diff<br/>Added lines only]
    Locate --> Positions[Line Positions]

    ReviewMsg --> Comment[Inline Comment]
    FixSnippet --> Comment
    Positions --> Comment

    Comment --> API[GitHub API]
    API --> PR[Pull Request]
```

### Comment Format

Each inline comment includes:

```markdown
**TM-API-001 - Broken Object Level Authorization (IDOR)**

Verify per-object authorization on every ID-bearing endpoint. Enforce tenant scoping and ownership checks server-side.

Suggested fix:
```
# Pseudocode: enforce ownership check
def fetch_scoped_object(user, object_id):
    obj = repo.fetch(object_id)
    if not obj:
        raise NotFound()
    if obj.tenant_id != user.tenant_id:
        raise Forbidden("unauthorized object access")
    return obj
```
```

### Features

| Feature | Description |
|---------|-------------|
| **Keyword-Based** | Locates specific keywords in added lines (`+` prefix) |
| **Rule-Based** | Matches complex regex patterns for code constructs |
| **Line-Level Precision** | Uses SAST hits for exact line numbers |
| **Deduplicated** | Merges identical comments to avoid spam |
| **Context-Aware** | Only comments on relevant PR changes |

---

## Configuration

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--org` | GitHub organization name | `mbbgrp` |
| `--since-days` | Filter repos updated within N days | `30` |
| `--repos-file` | Path to allowlist file (one repo per line) | None |
| `--max-repos` | Maximum repositories to scan | `50` |
| `--depth` | Git clone depth (0 = full, 1 = shallow) | `1` |
| `--mode` | Scan mode: `quick` or `deep` | `quick` |
| `--local-dir` | Scan local directory (skip inventory/clone) | None |
| `--fail-on-critical` | Exit non-zero if avg DREAD ≥ 8.0 | `false` |
| `--no-gitleaks` | Skip gitleaks secret scanning | `false` |
| `--no-sbom` | Skip syft SBOM generation | `false` |
| `--pdf` | Generate PDF report | `false` |
| `--github-token` | Override GitHub token | Auto-detected |
| `--github-api-url` | GitHub API base URL (Enterprise) | `https://api.github.com` |
| `--workspace-dir` | Local clone location | `~/tm-workspace` |
| `--output-dir` | Report output location | `~/tm-output` |
| `--dry-run` | Show selection without scanning | `false` |

### Authentication Priority

tm-scan uses a **hybrid auth model** with fallback priority:

1. **CLI argument** `--github-token`
2. **Environment variable** `GITHUB_TOKEN` (CI)
3. **GitHub CLI** `gh auth token` (local)
4. **Unauthenticated** (public repos only)

In GitHub Actions, `GITHUB_TOKEN` is automatically available.

### GitHub Enterprise

For GitHub Enterprise Server:

```bash
# Via environment variable
export GITHUB_API_URL="https://github.example.com"
./tm-scan --org my-org

# Via CLI argument
./tm-scan --org my-org --github-api-url "https://github.example.com/api/v3"
```

---

## Outputs

### 1. Markdown Report (`threatmodel-report.md`)

Comprehensive report with:
- Repository identity (owner, name, timestamp)
- Executive summary with risk level
- **Mermaid DFD** architecture diagram (dynamic based on codebase)
- **Full threat model diagram** with visual threat mapping
- Data flow matrix with CIA triad
- **5-D threat analysis** with exact line evidence:
  - STRIDE/LINDDUN/CWE classification
  - DREAD score breakdown
  - PASTA attack scenario
  - Evidence table with file path, exact line, trigger, severity, source, confidence
  - Mitigation requirements
- **PASTA analysis** with attack tree diagram
- Risk summary table with priority levels
- Gitleaks and SBOM statistics

### 2. SARIF Report (`threatmodel-report.sarif`)

Standards-compliant format for:
- GitHub Security tab integration
- PR check annotations
- Third-party tool consumption
- Audit trail generation

```json
{
  "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "tm-scan",
        "rules": [...]
      }
    },
    "results": [...]
  }]
}
```

### 3. Evidence JSON (`evidence.json`)

Machine-readable findings for:
- Downstream automation
- Trend analysis
- Custom reporting
- Data integrations

```json
{
  "repo_name": "example-app",
  "scan_timestamp": "2025-01-15",
  "keyword_hits": [...],
  "sast_hits": [
    {
      "rule_id": "vuln-sqli-concatenation",
      "file_path": "src/db.py",
      "line": 42,
      "severity": "CRITICAL",
      "cwe": "CWE-89"
    }
  ],
  "auth_hints": [...],
  "db_hints": [...],
  "risky_config_hints": [...]
}
```

### 4. Evidence Summary (`evidence-summary.md`)

Human-readable evidence overview with:
- File counts by category
- OpenAPI/Swagger specifications
- Database migration files
- Configuration files
- High priority keyword hits
- SAST/rule hits with severities
- Authentication/authorization hints
- Database technology hints
- Risky configuration hints

### 5. PDF Report (optional)

Rendered PDF with:
- Professional formatting
- Page breaks between sections
- Mermaid diagram rendering
- Print-friendly layout

---

## Knowledge Base

The knowledge base consists of three YAML files:

### kb-threats.yaml

Threat definitions with full 5-D context (18+ patterns):

```yaml
threats:
  - id: "TM-API-001"
    name: "Broken Object Level Authorization (IDOR)"
    stride_category: "Elevation of Privilege"
    linddun_category: "Unawareness"
    keywords: ["/v1/", "id=", "findById"]
    trigger_rules: []
    compliance:
      cwe_id: "CWE-639"
      owasp_api: "API1:2023"
    pasta_context:
      threat_actor: "External authenticated user"
      attack_surface: "REST endpoints"
      attack_vector: "Manipulated IDs"
    dread_score:
      damage: 9
      reproducibility: 8
      exploitability: 8
      affected_users: 9
      discoverability: 7
    reviewer_message: "Verify per-object authorization..."
    auto_fix_snippet: |
      def fetch_scoped_object(user, object_id):
          # ...
```

**Coverage:**
- API Security: IDOR, SSRF, SQL Injection, NoSQL Injection, GraphQL Auth
- Authentication: JWT Weakness, Credential Stuffing
- Cryptography: Weak Algorithms
- Privacy: Logging PII, Client Storage
- Cloud: CORS, Hardcoded Credentials
- Kubernetes: Privileged Containers
- Application: Deserialization, XSS
- AI: Prompt Injection, Data Leakage
- Business Logic: Financial Tampering, KYC/AML Bypass, Race Conditions

### kb-sast-rules.yaml

Advanced regex-based detection rules with line-level precision:

```yaml
rules:
  - id: "vuln-sqli-concatenation"
    category: "injection"
    severity: "CRITICAL"
    cwe: "CWE-89"
    target_extensions: [".java", ".js", ".py"]
    condition: "AND"
    patterns:
      - regex: "(?i)(SELECT|UPDATE).*?(FROM|INTO)"
      - regex: "(\\+.*?|f\".*?\\{.*?\\})"
    not_patterns:
      - regex: "(?i)(prepareStatement|bindParam)"
```

**Categories:**
- Injection (SQLi, Command Injection)
- Authentication (Hardcoded Secrets, JWT None)
- Cryptography (Weak Hashing, Insecure Random)
- Tampering (Deserialization, XXE)
- Business Logic (Path Traversal, PII Logging)

### kb-keywords.yaml

Simple keyword-based indicators (150+ keywords):

```yaml
authentication:
  - keyword: "jwt"
    category: "authn"
    priority: "high"
    description: "JWT token usage"

database:
  - keyword: "postgresql"
    category: "database"
    priority: "medium"
    description: "PostgreSQL database"

secrets:
  - keyword: "api_key"
    category: "secret"
    priority: "high"
    description: "API key reference"

file_patterns:
  openapi:
    - "openapi.yaml"
    - "swagger.yml"
  config:
    - "application*.yml"
    - ".env*"
```

---

## Development

### Project Structure

```
tm-scan/
├── tm-scan                    # CLI entry point
├── requirements.txt           # Python dependencies
├── src/
│   ├── __init__.py           # Package initialization
│   ├── config.py             # Configuration handling + hybrid auth
│   ├── inventory.py          # GitHub repository inventory
│   ├── selector.py           # Repository selection/prioritization
│   ├── cloner.py             # Git clone/update operations
│   ├── scanner.py            # Evidence discovery scanner
│   ├── gitleaks_wrapper.py   # Secret scanning wrapper
│   ├── sbom_wrapper.py       # SBOM generation wrapper
│   ├── reporter.py           # Threat model report generation
│   └── report_pdf.py         # PDF report rendering
├── scripts/
│   └── local_pr_reviewer.py  # Deterministic PR reviewer
├── .github/workflows/
│   └── tm-scan-agent.yml     # CI/CD workflow
└── knowledge-base/
    ├── kb-threats.yaml       # 18+ threat definitions
    ├── kb-sast-rules.yaml    # SAST detection rules
    └── kb-keywords.yaml      # 150+ keyword indicators
```

### Running Tests

```bash
# Run all tests
python -m pytest tests/

# Run with coverage
python -m pytest --cov=src tests/
```

### Adding Custom Threats

Edit `knowledge-base/kb-threats.yaml`:

```yaml
threats:
  - id: "TM-CUSTOM-001"
    name: "Your Custom Threat"
    stride_category: "Tampering"
    keywords: ["your_keyword"]
    trigger_rules: []
    compliance:
      cwe_id: "CWE-XXX"
    dread_score:
      damage: 7
      reproducibility: 6
      exploitability: 6
      affected_users: 7
      discoverability: 5
    reviewer_message: "Your security guidance"
    auto_fix_snippet: |
      # Your fix snippet
```

### Adding Detection Rules

Edit `knowledge-base/kb-sast-rules.yaml`:

```yaml
rules:
  - id: "custom-rule-001"
    category: "your_category"
    severity: "HIGH"
    cwe: "CWE-XXX"
    target_extensions: [".js", ".ts", ".py"]
    condition: "AND"
    patterns:
      - regex: "pattern1"
      - regex: "pattern2"
    not_patterns:
      - regex: "safe_pattern"
```

---

## License

See `LICENSE` file for details.

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

---

## Acknowledgments

- **STRIDE** — Microsoft threat modeling framework
- **PASTA** — Risk-based threat modeling methodology
- **LINDDUN** — Privacy threat modeling framework
- **CWE** — MITRE Common Weakness Enumeration
- **DREAD** — Risk assessment methodology
- **Gitleaks** — Secret scanning tool
- **Syft** — SBOM generation tool

---

<div align="center">

**tm-scan** — Automated threat modeling for enterprise security

[GitHub](https://github.com/yantongggg/TM_o31) • [Issues](https://github.com/yantongggg/TM_o31/issues) • [Documentation](https://github.com/yantongggg/TM_o31/wiki)

</div>
