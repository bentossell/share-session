#!/bin/bash
# Share a Droid session as a GitHub gist

set -e

# Source secrets for env vars like SHARE_SESSION_PREVIEW_URL
[ -f "$HOME/.secrets" ] && source "$HOME/.secrets"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SESSIONS_DIR="${HOME}/.factory/sessions"
SESSION_ID="$1"
SESSION_TITLE="$2"  # Optional: title provided by agent
SHARE_ARGS="$3"     # Optional: custom instructions (e.g., "ignore the last 4 messages")

# Get current working directory for session matching
CURRENT_CWD="${4:-$(pwd)}"

# Check gh is available and authenticated
if ! command -v gh &> /dev/null; then
  echo "Error: GitHub CLI (gh) not installed. Install from https://cli.github.com/"
  exit 1
fi

if ! gh auth status &> /dev/null; then
  echo "Error: Not logged into GitHub CLI. Run 'gh auth login' first."
  exit 1
fi

# Default to current project's most recent session (based on cwd)
if [ -z "$SESSION_ID" ]; then
  # Convert cwd to session directory name format (slashes become dashes, leading dash)
  CWD_ENCODED=$(echo "$CURRENT_CWD" | sed 's|/|-|g')
  PROJECT_SESSION_DIR="$SESSIONS_DIR/$CWD_ENCODED"
  
  if [ -d "$PROJECT_SESSION_DIR" ]; then
    # Find most recent session for THIS project
    latest_jsonl=$(find "$PROJECT_SESSION_DIR" -name "*.jsonl" -type f -exec stat -f "%m %N" {} \; 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)
  fi
  
  # Fallback to global most recent if no project session found
  if [ -z "$latest_jsonl" ]; then
    echo "Warning: No session found for current project, using most recent global session"
    latest_jsonl=$(find "$SESSIONS_DIR" -name "*.jsonl" -type f -exec stat -f "%m %N" {} \; 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)
  fi
  
  if [ -z "$latest_jsonl" ]; then
    echo "Error: No sessions found in $SESSIONS_DIR"
    exit 1
  fi
  
  SESSION_FILE="$latest_jsonl"
  SESSION_ID=$(basename "$(dirname "$SESSION_FILE")")
  echo "Sharing current session: $SESSION_ID"
elif [ -f "$SESSION_ID" ]; then
  # Direct file path provided
  SESSION_FILE="$SESSION_ID"
  echo "Sharing session file: $SESSION_FILE"
else
  # Find session by ID if explicitly requested
  SESSION_FILE=$(find "$SESSIONS_DIR" -path "*$SESSION_ID*" -name "*.jsonl" -type f 2>/dev/null | head -1)
  
  if [ -z "$SESSION_FILE" ] || [ ! -f "$SESSION_FILE" ]; then
    echo "Error: Session not found: $SESSION_ID"
    echo "Run './scripts/list.sh' to see available sessions"
    exit 1
  fi
  echo "Sharing requested session: $SESSION_ID"
fi

echo "Session file: $SESSION_FILE"
echo ""

# Get session info
msg_count=$(wc -l < "$SESSION_FILE" | tr -d ' ')
size=$(du -h "$SESSION_FILE" | cut -f1)
echo "Messages: $msg_count | Size: $size"
echo ""

# Get base name for exports
BASE_NAME=$(basename "$SESSION_FILE" .jsonl)

# Apply filtering if SHARE_ARGS provided (e.g., "ignore the last 4 messages")
WORKING_FILE="$SESSION_FILE"
if [ -n "$SHARE_ARGS" ]; then
  echo "Processing custom instructions: $SHARE_ARGS"
  FILTERED_FILE="/tmp/${BASE_NAME}_filtered.jsonl"
  if node "$SCRIPT_DIR/filter-session.js" "$SESSION_FILE" "$FILTERED_FILE" "$SHARE_ARGS" 2>/dev/null; then
    WORKING_FILE="$FILTERED_FILE"
    msg_count=$(wc -l < "$WORKING_FILE" | tr -d ' ')
    echo "After filtering: $msg_count events"
  else
    echo "Warning: Could not apply filter, using full session"
  fi
  echo ""
fi

# Security scan with droid exec (AI-powered secret detection)
echo "Running AI security scan..."
if ! "$SCRIPT_DIR/scan-secrets.sh" "$WORKING_FILE"; then
  echo ""
  echo "BLOCKED: Session contains sensitive data."
  echo "The session will NOT be uploaded to prevent credential leakage."
  # Cleanup filtered file if exists
  [ -n "$FILTERED_FILE" ] && rm -f "$FILTERED_FILE"
  exit 1
fi
echo ""

# Export all formats
echo "Exporting formats..."
HTML_FILE="/tmp/${BASE_NAME}.html"
MD_FILE="/tmp/${BASE_NAME}.md"
JSONL_FILE="/tmp/${BASE_NAME}.jsonl"

# Scrub and copy jsonl (regex-based backup scrubber)
node "$SCRIPT_DIR/scrub-jsonl.js" "$WORKING_FILE" "$JSONL_FILE" 2>/dev/null
echo "  - JSONL (scrubbed)"

# Export HTML
node "$SCRIPT_DIR/export-html.js" "$WORKING_FILE" "$HTML_FILE" 2>/dev/null
echo "  - HTML (formatted viewer)"

# Export MD  
node "$SCRIPT_DIR/export-md.js" "$WORKING_FILE" "$MD_FILE" 2>/dev/null
echo "  - Markdown"

echo ""

# Use provided title or default
if [ -z "$SESSION_TITLE" ]; then
  SESSION_TITLE="Droid Session"
fi
echo "Title: $SESSION_TITLE"
echo ""

# Create gist with all three files
echo "Creating gist with all formats..."
GIST_URL=$(gh gist create --desc "$SESSION_TITLE" "$HTML_FILE" "$MD_FILE" "$JSONL_FILE" 2>&1 | tail -1)

if [[ "$GIST_URL" == https://gist.github.com/* ]]; then
  GIST_ID=$(echo "$GIST_URL" | rev | cut -d'/' -f1 | rev)
  USERNAME=$(gh api user --jq .login)
  
  echo ""
  echo "Success!"
  echo "========="
  echo ""
  
  # Preview URL - set SHARE_SESSION_PREVIEW_URL env var to your deployed domain
  # e.g. export SHARE_SESSION_PREVIEW_URL="https://sessions.example.com"
  if [ -n "$SHARE_SESSION_PREVIEW_URL" ]; then
    echo "Preview: ${SHARE_SESSION_PREVIEW_URL}?${GIST_ID}"
    echo ""
  fi
  
  echo "Gist: $GIST_URL"
  echo ""
  echo "Raw files:"
  echo "  HTML:  https://gist.githubusercontent.com/$USERNAME/$GIST_ID/raw/${BASE_NAME}.html"
  echo "  MD:    https://gist.githubusercontent.com/$USERNAME/$GIST_ID/raw/${BASE_NAME}.md"
  echo "  JSONL: https://gist.githubusercontent.com/$USERNAME/$GIST_ID/raw/${BASE_NAME}.jsonl"
  
  # Cleanup
  rm -f "$HTML_FILE" "$MD_FILE" "$JSONL_FILE"
  [ -n "$FILTERED_FILE" ] && rm -f "$FILTERED_FILE"
else
  echo "Error creating gist: $GIST_URL"
  rm -f "$HTML_FILE" "$MD_FILE" "$JSONL_FILE"
  [ -n "$FILTERED_FILE" ] && rm -f "$FILTERED_FILE"
  exit 1
fi
