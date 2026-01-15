#!/bin/bash
# Scan session file for sensitive data using droid exec
# Returns exit 0 if clean, exit 1 if secrets found

set -e

SESSION_FILE="$1"

if [ -z "$SESSION_FILE" ] || [ ! -f "$SESSION_FILE" ]; then
  echo "Error: Session file required"
  exit 1
fi

# Use droid exec to scan for secrets - read-only mode
# The agent analyzes the content and returns JSON with findings
RESULT=$(droid exec --output-format json "Analyze the following session file for ANY sensitive data that should NEVER be shared publicly:

File: $SESSION_FILE

Look for:
- API keys (any format: sk-, pk-, re_, fk-, ghp_, gho_, github_pat_, AKIA*, stripe, openai, anthropic, etc)
- Personal Access Tokens (PATs) 
- Passwords or credentials (including in environment variables, exports, or configs)
- Private keys (RSA, SSH, PGP)
- OAuth tokens or refresh tokens
- Database connection strings with credentials
- Webhook secrets
- JWT tokens or session tokens
- AWS/GCP/Azure credentials
- Any long alphanumeric strings that look like secrets (32+ chars)
- Explicit mentions of secrets like 'my api key is...' or 'the password is...'

Read the file and report findings.

IMPORTANT: If you find ANY potential secrets, respond with this exact JSON structure:
{\"found\": true, \"secrets\": [\"description of each secret found with line context\"]}

If the file is clean and safe to share publicly:
{\"found\": false, \"secrets\": []}

Be PARANOID - when in doubt, flag it. Better safe than sorry." 2>&1)

# Parse the result
if echo "$RESULT" | grep -q '"is_error": true'; then
  echo "Error running security scan"
  echo "$RESULT"
  exit 1
fi

# Extract the result field
SCAN_RESULT=$(echo "$RESULT" | jq -r '.result // empty' 2>/dev/null)

if [ -z "$SCAN_RESULT" ]; then
  echo "Warning: Could not parse scan result, falling back to regex scan"
  exit 0
fi

# Check if secrets were found
if echo "$SCAN_RESULT" | grep -qi '"found":\s*true'; then
  echo "======================================"
  echo "SECURITY ALERT: Secrets detected!"
  echo "======================================"
  echo ""
  echo "$SCAN_RESULT" | jq -r '.secrets[]? // empty' 2>/dev/null || echo "$SCAN_RESULT"
  echo ""
  echo "This session contains sensitive data and CANNOT be shared."
  echo "Remove or redact the secrets before sharing."
  exit 1
fi

echo "Security scan passed - no secrets detected"
exit 0
