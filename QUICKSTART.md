# Quick Start Guide

## 5-Minute Setup

### Step 1: Get a GitHub Token (2 minutes)

1. Go to: https://github.com/settings/tokens
2. Click: "Generate new token" → "Generate new token (classic)"
3. Name it: "tm-scan"
4. Select scope: `repo` (for private repos)
5. Click "Generate token"
6. Copy the token (starts with `ghp_`)

### Step 2: Install (1 minute)

```bash
cd tm-scan
pip install -r requirements.txt
chmod +x tm-scan
```

### Step 3: Configure (choose one method)

**Method A: .env file (Recommended - easiest!)**
```bash
cp .env.example .env
nano .env  # Edit and paste your token: GITHUB_TOKEN=ghp_your_token_here
```

**Method B: Environment variable**
```bash
export GITHUB_TOKEN=ghp_your_token_here
```

**Method C: Pass directly**
```bash
./tm-scan --github-token ghp_your_token_here --org mbbgrp --since-days 30
```

### Step 4: Run Your First Scan

```bash
# Dry run first (see what will be scanned)
./tm-scan --org YOUR_ORG --since-days 30 --dry-run

# Real scan
./tm-scan --org YOUR_ORG --since-days 30 --max-repos 10
```

## Common Commands

```bash
# Scan repos updated in last 7 days
./tm-scan --org mbbgrp --since-days 7 --max-repos 20

# Scan specific repos from a file
./tm-scan --org mbbgrp --repos-file repos.txt --max-repos 5

# Deep scan with full history
./tm-scan --org mbbgrp --since-days 30 --mode deep --depth 0 --max-repos 3
```

## Where Are My Reports?

```bash
# View reports
ls ~/tm-output/reports/

# View logs
cat ~/tm-output/logs/run-*.log

# View metadata
cat ~/tm-output/run-metadata/selected-repos.txt
```

## Troubleshooting

**"Permission denied (publickey)"**
→ Add SSH key to GitHub: `ssh -T git@github.com`

**"Could not fetch repos"**
→ Check your token has `repo` scope and org name is correct

**"Tool gitleaks not found"**
→ OK to ignore, or: `brew install gitleaks`

## Quick Reference

| Option | Purpose |
|--------|---------|
| `--org NAME` | GitHub organization |
| `--since-days N` | Repos updated in last N days |
| `--repos-file FILE` | Scan only repos in file |
| `--max-repos N` | Limit to N repos |
| `--dry-run` | Preview without cloning |
| `--mode quick\|deep` | Scan depth |
| `--github-token TOKEN` | Auth token |
| `--no-gitleaks` | Skip secret scan |
| `--no-sbom` | Skip SBOM |
