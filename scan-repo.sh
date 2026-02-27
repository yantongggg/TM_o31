#!/bin/bash
# Simple wrapper script to scan a specific repo without needing --org
# Usage: ./scan-repo.sh <username/org> <repo-name>
# Example: ./scan-repo.sh MSS-DB request

if [ $# -lt 2 ]; then
    echo "Usage: $0 <username/org> <repo-name>"
    echo "Example: $0 MSS-DB request"
    exit 1
fi

USERNAME_ORG="$1"
REPO_NAME="$2"

# Create temporary repos.txt
echo "$REPO_NAME" > repos.txt

# Run tm-scan
./tm-scan --org "$USERNAME_ORG" --repos-file repos.txt --max-repos 1 --since-days 0 --no-gitleaks --no-sbom --pdf

# Clean up
rm repos.txt
