#!/usr/bin/env node
// Export Droid session to HTML

const fs = require('fs');

const sessionFile = process.argv[2];
if (!sessionFile) {
  console.error('Usage: export-html.js <session.jsonl> [output.html]');
  process.exit(1);
}

const outputFile = process.argv[3] || sessionFile.replace('.jsonl', '.html');

// Secret patterns to scrub - comprehensive list
const SECRET_PATTERNS = [
  // API keys with various prefixes
  /\b(sk-[a-zA-Z0-9]{20,})\b/g,
  /\b(pk-[a-zA-Z0-9]{20,})\b/g,
  /\b(sk-proj-[a-zA-Z0-9_\-]{20,})\b/g,
  /\b(sk-ant-[a-zA-Z0-9_\-]{20,})\b/g,
  // Generic long alphanumeric strings that look like keys (40+ chars)
  /\b([a-zA-Z0-9_\-]{40,})\b/g,
  // API key assignments in various formats
  /\b(api[_-]?key[s]?[\s'":\=]*)([\w\-]{16,})/gi,
  /\b(api[_-]?secret[\s'":\=]*)([\w\-]{16,})/gi,
  // Bearer tokens
  /(bearer\s+)([a-zA-Z0-9_\-\.]{20,})/gi,
  // AWS keys
  /\b(AKIA[0-9A-Z]{16})\b/g,
  /\b(aws[_-]?secret[_-]?access[_-]?key[\s'":\=]*)([\w/+=]{30,})/gi,
  // GitHub tokens
  /\b(ghp_[a-zA-Z0-9]{36})\b/g,
  /\b(gho_[a-zA-Z0-9]{36})\b/g,
  /\b(github_pat_[a-zA-Z0-9_]{22,})\b/g,
  // Stripe keys
  /\b(sk_live_[a-zA-Z0-9]{20,})\b/g,
  /\b(sk_test_[a-zA-Z0-9]{20,})\b/g,
  /\b(pk_live_[a-zA-Z0-9]{20,})\b/g,
  /\b(pk_test_[a-zA-Z0-9]{20,})\b/g,
  /\b(whsec_[a-zA-Z0-9]{20,})\b/g,
  // Generic key/secret/token/password in context
  /\b(password[\s'":\=]+)([^\s'"]{8,})/gi,
  /\b(secret[\s'":\=]+)([\w\-]{12,})/gi,
  /\b(token[\s'":\=]+)([\w\-\.]{16,})/gi,
  /\b(key[\s'":\=]+)([\w\-]{20,})/gi,
  // "my API key" or "the API key" followed by something
  /(my|the|your|this)\s+(api[_\s-]?key|secret|token|password)[\s:]+(\S{12,})/gi,
  // "add...key...to" patterns with the key
  /(add|set|use|put|enter|paste|copy)\s+[^.]*?(key|secret|token|password)[^.]*?[\s:'"]+([a-zA-Z0-9_\-]{16,})/gi,
  // Private keys
  /(-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----)/g,
  // Hex strings that look like secrets (32+ hex chars)
  /\b([a-f0-9]{32,})\b/gi,
  // Base64 encoded strings that are long (likely secrets)
  /\b([A-Za-z0-9+/]{40,}={0,2})\b/g,
];

function scrubSecrets(text) {
  if (!text) return text;
  let scrubbed = text;
  
  SECRET_PATTERNS.forEach((pattern) => {
    scrubbed = scrubbed.replace(pattern, (match, ...groups) => {
      // For patterns with capture groups, replace just the secret part
      const captureGroups = groups.filter(g => typeof g === 'string');
      if (captureGroups.length >= 2) {
        const prefix = captureGroups[0];
        const secret = captureGroups[captureGroups.length - 1];
        if (secret && secret.length >= 12) {
          return prefix + '[REDACTED]';
        }
      }
      // For simple patterns, replace the whole match if it looks like a secret
      if (match.length >= 16 && /^[\w\-+/=]+$/.test(match)) {
        return '[REDACTED]';
      }
      return match;
    });
  });
  
  return scrubbed;
}

// Read and parse session
const content = fs.readFileSync(sessionFile, 'utf-8');
const lines = content.trim().split('\n').filter(Boolean);
const events = lines.map(line => JSON.parse(line));

// Extract session info and messages
const sessionStart = events.find(e => e.type === 'session_start');
const messages = events.filter(e => e.type === 'message');

// Build a map of tool_use_id -> tool results for pairing
const toolResults = new Map();
messages.forEach(event => {
  const msg = event.message;
  if (msg.role === 'user' && Array.isArray(msg.content)) {
    msg.content.forEach(block => {
      if (block.type === 'tool_result') {
        const resultContent = typeof block.content === 'string' 
          ? block.content 
          : JSON.stringify(block.content, null, 2);
        toolResults.set(block.tool_use_id, scrubSecrets(resultContent));
      }
    });
  }
});

// Helper to escape HTML
const escapeHtml = (str) => {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
};

// Helper to extract text from content blocks
const extractText = (content) => {
  if (typeof content === 'string') return scrubSecrets(content);
  if (!Array.isArray(content)) return '';
  
  return content.map(block => {
    if (block.type === 'text') return scrubSecrets(block.text);
    if (block.type === 'thinking') return '<thinking>\n' + scrubSecrets(block.thinking) + '\n</thinking>';
    if (block.type === 'tool_use') {
      const input = scrubSecrets(JSON.stringify(block.input, null, 2));
      const result = toolResults.get(block.id) || '';
      return '<tool_use name="' + block.name + '" id="' + block.id + '">\n' + input + '\n</tool_use>' +
        (result ? '\n<tool_result>\n' + result + '\n</tool_result>' : '');
    }
    if (block.type === 'tool_result') return ''; // Handled with tool_use
    if (block.type === 'image') return '[Image]';
    return '';
  }).filter(Boolean).join('\n\n');
};

// Check if message is purely tool results (not a real user message)
function isToolResultMessage(content) {
  if (!Array.isArray(content)) return false;
  return content.length > 0 && content.every(block => block.type === 'tool_result');
}

// Clean system reminders from user messages
function cleanUserMessage(text) {
  if (text.includes('<system-reminder>')) {
    const parts = text.split('</system-reminder>');
    return parts[parts.length - 1].trim();
  }
  return text;
}

// Consolidate consecutive assistant messages into turns
function consolidateMessages(messages) {
  const turns = [];
  let currentTurn = null;
  
  messages.forEach((event) => {
    const msg = event.message;
    const role = msg.role;
    
    // Skip tool result messages
    if (role === 'user' && isToolResultMessage(msg.content)) {
      return;
    }
    
    if (role === 'user') {
      // New user turn - save any pending assistant turn first
      if (currentTurn && currentTurn.role === 'assistant') {
        turns.push(currentTurn);
      }
      
      let text = extractText(msg.content);
      text = cleanUserMessage(text);
      
      if (text) {
        turns.push({
          role: 'user',
          timestamp: event.timestamp,
          content: text
        });
      }
      currentTurn = null;
    } else if (role === 'assistant') {
      const text = extractText(msg.content);
      
      if (!currentTurn || currentTurn.role !== 'assistant') {
        // Start new assistant turn
        if (currentTurn) {
          turns.push(currentTurn);
        }
        currentTurn = {
          role: 'assistant',
          timestamp: event.timestamp,
          content: text
        };
      } else {
        // Append to existing assistant turn
        currentTurn.content += '\n\n' + text;
      }
    }
  });
  
  // Don't forget the last turn
  if (currentTurn) {
    turns.push(currentTurn);
  }
  
  return turns;
}

// Consolidate messages into turns
const turns = consolidateMessages(messages);

// Build message HTML
function buildMessageHtml(turn) {
  const timestamp = turn.timestamp ? new Date(turn.timestamp).toLocaleString() : '';
  const icon = turn.role === 'user' ? '👤 User' : '🤖 Assistant';
  
  return '<div class="message ' + turn.role + '">' +
    '<div class="message-header">' +
    '<span>' + icon + '</span>' +
    '<span class="timestamp">' + timestamp + '</span>' +
    '</div>' +
    '<div class="message-content" data-raw="' + escapeHtml(turn.content) + '"></div>' +
    '</div>';
}

const messagesHtml = turns.map(buildMessageHtml).join('\n');

const css = `
:root {
  --bg: #0d1117;
  --bg-secondary: #161b22;
  --bg-tertiary: #21262d;
  --text: #c9d1d9;
  --text-muted: #8b949e;
  --border: #30363d;
  --accent: #58a6ff;
  --user-bg: #1f2937;
  --assistant-bg: #161b22;
  --tool-bg: #1c2128;
  --thinking-bg: #1a1f25;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.6;
}
.header {
  background: var(--bg-secondary);
  border-bottom: 1px solid var(--border);
  padding: 20px;
  position: sticky;
  top: 0;
  z-index: 100;
}
.header h1 { font-size: 1.25rem; font-weight: 600; margin-bottom: 4px; }
.header .meta { font-size: 0.875rem; color: var(--text-muted); }
.container { max-width: 900px; margin: 0 auto; padding: 20px; }
.message { margin-bottom: 24px; border-radius: 8px; overflow: hidden; }
.message-header {
  padding: 12px 16px;
  font-weight: 600;
  font-size: 0.875rem;
  display: flex;
  align-items: center;
  gap: 8px;
}
.message.user { background: var(--user-bg); }
.message.user .message-header { background: rgba(88, 166, 255, 0.1); color: var(--accent); }
.message.assistant { background: var(--assistant-bg); border: 1px solid var(--border); }
.message.assistant .message-header { background: var(--bg-tertiary); color: #7ee787; }
.message-content { padding: 16px; }
.message-content p { margin-bottom: 1em; }
.message-content p:last-child { margin-bottom: 0; }
.message-content pre {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 12px;
  overflow-x: auto;
  margin: 1em 0;
}
.message-content code { font-family: "SF Mono", "Fira Code", Consolas, monospace; font-size: 0.875em; }
.message-content :not(pre) > code { background: var(--bg-tertiary); padding: 2px 6px; border-radius: 4px; }
.thinking, .tool-result-block {
  background: var(--thinking-bg);
  border-left: 3px solid #8b5cf6;
  padding: 12px 16px;
  margin: 12px 0;
  border-radius: 0 6px 6px 0;
  cursor: pointer;
}
.tool-result-block { border-left-color: #3fb950; }
.collapsible-header { font-size: 0.75rem; font-weight: 600; text-transform: uppercase; margin-bottom: 8px; }
.thinking .collapsible-header { color: #a78bfa; }
.tool-result-block .collapsible-header { color: #3fb950; }
.collapsible-content { color: var(--text-muted); font-size: 0.875rem; white-space: pre-wrap; display: none; max-height: 500px; overflow-y: auto; }
.expanded .collapsible-content { display: block; }
.tool-call { background: var(--tool-bg); border: 1px solid var(--border); border-radius: 6px; margin: 12px 0; overflow: hidden; }
.tool-header { background: var(--bg-tertiary); padding: 8px 12px; font-size: 0.8rem; color: #f0883e; font-weight: 600; cursor: pointer; }
.tool-content { padding: 12px; font-family: monospace; font-size: 0.8rem; white-space: pre-wrap; word-break: break-all; display: none; max-height: 400px; overflow-y: auto; }
.tool-call.expanded .tool-content { display: block; }
.timestamp { font-size: 0.75rem; color: var(--text-muted); margin-left: auto; }
.message-content h1, .message-content h2, .message-content h3 { margin-top: 1.5em; margin-bottom: 0.5em; font-weight: 600; }
.message-content ul, .message-content ol { margin: 1em 0; padding-left: 2em; }
.message-content li { margin: 0.25em 0; }
.message-content a { color: var(--accent); text-decoration: none; }
.message-content a:hover { text-decoration: underline; }
.message-content table { border-collapse: collapse; width: 100%; margin: 1em 0; }
.message-content th, .message-content td { border: 1px solid var(--border); padding: 8px 12px; text-align: left; }
.message-content th { background: var(--bg-tertiary); }
`;

const js = `
document.querySelectorAll(".message-content").forEach(el => {
  const raw = el.dataset.raw || "";
  let html = raw
    .replace(/<thinking>([\\s\\S]*?)<\\/thinking>/g, (_, content) => 
      '<div class="thinking" onclick="this.classList.toggle(\\'expanded\\')"><div class="collapsible-header">💭 Thinking (click to expand)</div><div class="collapsible-content">' + content + '</div></div>')
    .replace(/<tool_use name="([^"]+)" id="([^"]+)">([\\s\\S]*?)<\\/tool_use>/g, (_, name, id, content) =>
      '<div class="tool-call" onclick="this.classList.toggle(\\'expanded\\')"><div class="tool-header">🔧 ' + name + '</div><div class="tool-content">' + content + '</div></div>')
    .replace(/<tool_result>([\\s\\S]*?)<\\/tool_result>/g, (_, content) => {
      const truncated = content.length > 3000 ? content.slice(0, 3000) + "\\n... (truncated)" : content;
      return '<div class="tool-result-block" onclick="this.classList.toggle(\\'expanded\\')"><div class="collapsible-header">📤 Result (click to expand)</div><div class="collapsible-content">' + truncated + '</div></div>';
    });
  try {
    if (!html.includes('<div class="')) {
      html = marked.parse(html);
    }
  } catch (e) { console.error("Markdown error:", e); }
  el.innerHTML = html;
});
document.querySelectorAll("pre code").forEach(block => hljs.highlightElement(block));
`;

const title = escapeHtml(scrubSecrets(sessionStart?.title || 'Droid Session'));
const sessionId = escapeHtml(sessionStart?.id || 'unknown');
const cwd = sessionStart?.cwd ? ' · 📁 ' + escapeHtml(scrubSecrets(sessionStart.cwd)) : '';

const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title}</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css">
  <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
  <style>${css}</style>
</head>
<body>
  <div class="header">
    <h1>${title}</h1>
    <div class="meta">Session: ${sessionId} · ${turns.length} turns${cwd}</div>
  </div>
  <div class="container">
${messagesHtml}
  </div>
  <script>${js}</script>
</body>
</html>`;

fs.writeFileSync(outputFile, html);
console.log('Exported to: ' + outputFile);
console.log('Note: Secrets have been scrubbed (API keys, tokens, passwords, etc.)');
