#!/bin/bash
# Share a Droid session as a GitHub gist

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SESSIONS_DIR="${HOME}/.factory/sessions"
SESSION_ID="$1"

# Check gh is available and authenticated
if ! command -v gh &> /dev/null; then
  echo "Error: GitHub CLI (gh) not installed. Install from https://cli.github.com/"
  exit 1
fi

if ! gh auth status &> /dev/null; then
  echo "Error: Not logged into GitHub CLI. Run 'gh auth login' first."
  exit 1
fi

# If no session ID provided, try to find most recent
if [ -z "$SESSION_ID" ]; then
  # Find most recently modified session
  latest_jsonl=$(find "$SESSIONS_DIR" -name "*.jsonl" -type f -exec stat -f "%m %N" {} \; 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)
  
  if [ -z "$latest_jsonl" ]; then
    echo "Error: No sessions found in $SESSIONS_DIR"
    echo "Run './scripts/list.sh' to see available sessions"
    exit 1
  fi
  
  SESSION_FILE="$latest_jsonl"
  SESSION_ID=$(basename "$(dirname "$SESSION_FILE")")
  echo "Using most recent session: $SESSION_ID"
else
  # Find session by ID
  SESSION_FILE=$(find "$SESSIONS_DIR" -path "*$SESSION_ID*" -name "*.jsonl" -type f 2>/dev/null | head -1)
  
  if [ -z "$SESSION_FILE" ] || [ ! -f "$SESSION_FILE" ]; then
    echo "Error: Session not found: $SESSION_ID"
    echo "Run './scripts/list.sh' to see available sessions"
    exit 1
  fi
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

# Export all formats
echo "Exporting formats..."
HTML_FILE="/tmp/${BASE_NAME}.html"
MD_FILE="/tmp/${BASE_NAME}.md"
JSONL_FILE="/tmp/${BASE_NAME}.jsonl"

# Scrub and copy jsonl
node "$SCRIPT_DIR/scrub-jsonl.js" "$SESSION_FILE" "$JSONL_FILE" 2>/dev/null
echo "  - JSONL (scrubbed)"

# Export HTML
node "$SCRIPT_DIR/export-html.js" "$SESSION_FILE" "$HTML_FILE" 2>/dev/null
echo "  - HTML (formatted viewer)"

# Export MD  
node "$SCRIPT_DIR/export-md.js" "$SESSION_FILE" "$MD_FILE" 2>/dev/null
echo "  - Markdown"

echo ""

# Create gist with all three files
echo "Creating gist with all formats..."
GIST_URL=$(gh gist create --public=false "$HTML_FILE" "$MD_FILE" "$JSONL_FILE" 2>&1 | tail -1)

if [[ "$GIST_URL" == https://gist.github.com/* ]]; then
  GIST_ID=$(echo "$GIST_URL" | rev | cut -d'/' -f1 | rev)
  USERNAME=$(gh api user --jq .login)
  
  echo ""
  echo "Success!"
  echo "========="
  echo "Gist URL: $GIST_URL"
  echo ""
  echo "Direct links:"
  echo "  HTML: https://gist.githubusercontent.com/$USERNAME/$GIST_ID/raw/${BASE_NAME}.html"
  echo "  MD:   https://gist.githubusercontent.com/$USERNAME/$GIST_ID/raw/${BASE_NAME}.md"
  echo "  JSONL: https://gist.githubusercontent.com/$USERNAME/$GIST_ID/raw/${BASE_NAME}.jsonl"
  
  # Cleanup
  rm -f "$HTML_FILE" "$MD_FILE" "$JSONL_FILE"
else
  echo "Error creating gist: $GIST_URL"
  rm -f "$HTML_FILE" "$MD_FILE" "$JSONL_FILE"
  exit 1
fi
