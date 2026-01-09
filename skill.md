---
description: Share Droid sessions as GitHub gists. Use when asked to "share session", "export session to gist", or "create gist from session".
---

# Share Session Skill

Export and share Droid CLI sessions via GitHub gists.

## Usage

```bash
# List available sessions
./scripts/list.sh

# Share as HTML (default - nicely formatted viewer)
./scripts/share.sh [session-id] html

# Share as Markdown
./scripts/share.sh [session-id] md

# Share raw JSONL
./scripts/share.sh [session-id] raw

# Export locally without uploading
node ./scripts/export-html.js <session.jsonl> [output.html]
node ./scripts/export-md.js <session.jsonl> [output.md]
```

If no session-id provided, uses most recent session.

## Formats

- **html** - Self-contained HTML with syntax highlighting, collapsible tool calls, dark theme
- **md** - Clean Markdown with collapsible details blocks
- **raw** - Original JSONL file

## Requirements

- `gh` CLI installed and authenticated (`gh auth login`)
- Node.js for HTML/MD export

## Session Locations

- Global: `~/.factory/sessions/`
- Project-local: `.factory/sessions/`
