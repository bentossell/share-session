#!/bin/bash
# Scan session file for sensitive data using droid exec
# Returns exit 0 if clean, exit 1 if secrets found

set -e

SESSION_FILE="$1"

if [ -z "$SESSION_FILE" ] || [ ! -f "$SESSION_FILE" ]; then
  echo "Error: Session file required"
  exit 1
fi

fallback_scan() {
  local file="$1"

  if ! command -v rg >/dev/null 2>&1; then
    echo "Error: rg not found for fallback scan"
    return 1
  fi

  local patterns=(
    "-----BEGIN [A-Z ]+ PRIVATE KEY-----"
    "BEGIN OPENSSH PRIVATE KEY"
    "AKIA[0-9A-Z]{16}"
    "ASIA[0-9A-Z]{16}"
    "gh[pous]_[A-Za-z0-9]{36}"
    "github_pat_[A-Za-z0-9_]{22,}"
    "glpat-[A-Za-z0-9_\-]{20,}"
    "xox[baprs]-[A-Za-z0-9-]{10,}"
    "xapp-[A-Za-z0-9-]{10,}"
    "sk_(live|test)_[A-Za-z0-9]{20,}"
    "pk_(live|test)_[A-Za-z0-9]{20,}"
    "whsec_[A-Za-z0-9]{20,}"
    "SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}"
    "AIza[0-9A-Za-z_\-]{35}"
    "1//[0-9A-Za-z_\-]{20,}"
    "eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+"
    "bearer\s+[A-Za-z0-9._\-]{20,}"
    "access[_-]?token"
    "refresh[_-]?token"
    "id[_-]?token"
    "client[_-]?secret"
    "private[_-]?key"
    "aws[_-]?secret[_-]?access[_-]?key"
    "aws[_-]?session[_-]?token"
    "https?://[^\s/]+:[^\s/]+@"
    "postgres(ql)?://[^\s/]+:[^\s/]+@"
    "mongodb(\+srv)?://[^\s/]+:[^\s/]+@"
    "redis://[^\s/]+:[^\s/]+@"
    "amqp://[^\s/]+:[^\s/]+@"
    "sig=[A-Za-z0-9%/+=]{20,}"
    "https?://hooks\.slack\.com/services/"
    "https?://(discord\.com|discordapp\.com)/api/webhooks/"
  )

  local rg_args=(-n -i)
  for pattern in "${patterns[@]}"; do
    rg_args+=(-e "$pattern")
  done

  local matches
  matches=$(rg "${rg_args[@]}" "$file" 2>/dev/null || true)

  if [ -n "$matches" ]; then
    echo "======================================"
    echo "SECURITY ALERT: Secrets detected (fallback scan)!"
    echo "======================================"
    echo ""
    echo "$matches"
    echo ""
    echo "This session contains sensitive data and CANNOT be shared."
    echo "Remove or redact the secrets before sharing."
    return 1
  fi

  return 0
}

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
  echo "Warning: Could not parse scan result, running fallback scan"
  if fallback_scan "$SESSION_FILE"; then
    echo "Security scan passed - no secrets detected (fallback)"
    exit 0
  fi
  exit 1
fi

if ! echo "$SCAN_RESULT" | jq -e . >/dev/null 2>&1; then
  echo "Warning: Invalid scan result JSON, running fallback scan"
  if fallback_scan "$SESSION_FILE"; then
    echo "Security scan passed - no secrets detected (fallback)"
    exit 0
  fi
  exit 1
fi

FOUND=$(echo "$SCAN_RESULT" | jq -r '.found // empty' 2>/dev/null)

if [ -z "$FOUND" ]; then
  echo "Warning: Scan result missing 'found', running fallback scan"
  if fallback_scan "$SESSION_FILE"; then
    echo "Security scan passed - no secrets detected (fallback)"
    exit 0
  fi
  exit 1
fi

# Check if secrets were found
if [ "$FOUND" = "true" ]; then
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
