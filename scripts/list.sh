#!/bin/bash
# List available Droid sessions

SESSIONS_DIR="${HOME}/.factory/sessions"

if [ ! -d "$SESSIONS_DIR" ]; then
  echo "No sessions directory found at $SESSIONS_DIR"
  exit 1
fi

echo "Available sessions:"
echo "==================="

for dir in "$SESSIONS_DIR"/*/; do
  [ -d "$dir" ] || continue
  session_name=$(basename "$dir")
  
  # Find the .jsonl file
  jsonl_file=$(find "$dir" -name "*.jsonl" -type f 2>/dev/null | head -1)
  
  if [ -n "$jsonl_file" ]; then
    # Get file size and message count
    size=$(du -h "$jsonl_file" | cut -f1)
    msg_count=$(wc -l < "$jsonl_file" | tr -d ' ')
    modified=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M" "$jsonl_file" 2>/dev/null || stat -c "%y" "$jsonl_file" 2>/dev/null | cut -d' ' -f1-2)
    
    echo "$session_name"
    echo "  Messages: $msg_count | Size: $size | Modified: $modified"
  fi
done
