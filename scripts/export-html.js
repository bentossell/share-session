#!/usr/bin/env node
// Export Droid session to HTML - pi-mono style

const fs = require('fs');

const sessionFile = process.argv[2];
if (!sessionFile) {
  console.error('Usage: export-html.js <session.jsonl> [output.html]');
  process.exit(1);
}

const outputFile = process.argv[3] || sessionFile.replace('.jsonl', '.html');

// Secret patterns to scrub
const SECRET_PATTERNS = [
  /\b(sk-[a-zA-Z0-9]{20,})\b/g,
  /\b(pk-[a-zA-Z0-9]{20,})\b/g,
  /\b(sk-proj-[a-zA-Z0-9_\-]{20,})\b/g,
  /\b(sk-ant-[a-zA-Z0-9_\-]{20,})\b/g,
  /\b([a-zA-Z0-9_\-]{40,})\b/g,
  /\b(api[_-]?key[s]?[\s'":\=]*)([\w\-]{16,})/gi,
  /(bearer\s+)([a-zA-Z0-9_\-\.]{20,})/gi,
  /\b(AKIA[0-9A-Z]{16})\b/g,
  /\b(ghp_[a-zA-Z0-9]{36})\b/g,
  /\b(gho_[a-zA-Z0-9]{36})\b/g,
  /\b(github_pat_[a-zA-Z0-9_]{22,})\b/g,
  /\b(sk_live_[a-zA-Z0-9]{20,})\b/g,
  /\b(sk_test_[a-zA-Z0-9]{20,})\b/g,
  /\b(password[\s'":\=]+)([^\s'"]{8,})/gi,
  /\b(secret[\s'":\=]+)([\w\-]{12,})/gi,
  /\b(token[\s'":\=]+)([\w\-\.]{16,})/gi,
  /(-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----)/g,
];

function scrubSecrets(text) {
  if (!text) return text;
  let scrubbed = text;
  SECRET_PATTERNS.forEach((pattern) => {
    scrubbed = scrubbed.replace(pattern, (match, ...groups) => {
      const captureGroups = groups.filter(g => typeof g === 'string');
      if (captureGroups.length >= 2) {
        const prefix = captureGroups[0];
        const secret = captureGroups[captureGroups.length - 1];
        if (secret && secret.length >= 12) {
          return prefix + '[REDACTED]';
        }
      }
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

const sessionStart = events.find(e => e.type === 'session_start');
const messages = events.filter(e => e.type === 'message');

// Build tool results map
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

const escapeHtml = (str) => {
  if (typeof str !== 'string') return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
};

function isToolResultMessage(content) {
  if (!Array.isArray(content)) return false;
  return content.length > 0 && content.every(block => block.type === 'tool_result');
}

function cleanUserMessage(text) {
  if (text.includes('<system-reminder>')) {
    const parts = text.split('</system-reminder>');
    return parts[parts.length - 1].trim();
  }
  return text;
}

// Process messages into structured turns
function processMessages(messages) {
  const turns = [];
  let turnIndex = 0;
  
  messages.forEach((event, idx) => {
    const msg = event.message;
    const role = msg.role;
    
    if (role === 'user' && isToolResultMessage(msg.content)) return;
    
    if (role === 'user') {
      let text = '';
      if (typeof msg.content === 'string') {
        text = msg.content;
      } else if (Array.isArray(msg.content)) {
        text = msg.content.filter(b => b.type === 'text').map(b => b.text).join('\n');
      }
      text = cleanUserMessage(scrubSecrets(text));
      if (text) {
        turns.push({
          id: 'msg-' + turnIndex++,
          role: 'user',
          timestamp: event.timestamp,
          text: text,
          hasTools: false
        });
      }
    } else if (role === 'assistant') {
      const turn = {
        id: 'msg-' + turnIndex++,
        role: 'assistant',
        timestamp: event.timestamp,
        thinking: null,
        text: '',
        tools: [],
        hasTools: false
      };
      
      if (Array.isArray(msg.content)) {
        msg.content.forEach(block => {
          if (block.type === 'thinking') {
            turn.thinking = scrubSecrets(block.thinking);
          } else if (block.type === 'text') {
            turn.text += (turn.text ? '\n\n' : '') + scrubSecrets(block.text);
          } else if (block.type === 'tool_use') {
            // Special handling for ExitSpecMode - extract spec content
            if (block.name === 'ExitSpecMode' && block.input && block.input.plan) {
              turn.spec = {
                title: block.input.title || 'Spec',
                plan: scrubSecrets(block.input.plan),
                options: block.input.optionNames || []
              };
            } else {
              turn.hasTools = true;
              turn.tools.push({
                id: block.id,
                name: block.name,
                input: scrubSecrets(JSON.stringify(block.input, null, 2)),
                result: toolResults.get(block.id) || ''
              });
            }
          }
        });
      } else if (typeof msg.content === 'string') {
        turn.text = scrubSecrets(msg.content);
      }
      
      turns.push(turn);
    }
  });
  
  return turns;
}

const turns = processMessages(messages);

// Format tool call for sidebar display (like pi-mono)
function formatToolCall(name, input) {
  const shortenPath = (p) => {
    const parts = p.split('/');
    return parts.length > 2 ? '.../' + parts.slice(-2).join('/') : p;
  };
  
  try {
    const args = typeof input === 'string' ? JSON.parse(input) : input;
    switch (name.toLowerCase()) {
      case 'read':
        const readPath = shortenPath(String(args.file_path || args.path || ''));
        if (args.offset || args.limit) {
          return `[read: ${readPath}:${args.offset || 0}-${(args.offset || 0) + (args.limit || 100)}]`;
        }
        return `[read: ${readPath}]`;
      case 'create':
        return `[create: ${shortenPath(String(args.file_path || ''))}]`;
      case 'edit':
      case 'multiedit':
        return `[edit: ${shortenPath(String(args.file_path || ''))}]`;
      case 'execute':
        const cmd = String(args.command || '').replace(/[\n\t]/g, ' ').trim().slice(0, 40);
        return `[bash]: ${cmd}${cmd.length >= 40 ? '...' : ''}`;
      case 'grep':
        return `[grep: ${args.pattern || ''}]`;
      case 'glob':
        const patterns = args.patterns || [];
        return `[glob: ${patterns.slice(0, 2).join(', ')}]`;
      case 'ls':
        return `[ls: ${shortenPath(String(args.directory_path || '.'))}]`;
      case 'fetchurl':
        const url = String(args.url || '');
        const domain = url.match(/https?:\/\/([^\/]+)/)?.[1] || url.slice(0, 30);
        return `[fetch: ${domain}]`;
      case 'websearch':
        return `[search: ${(args.query || '').slice(0, 30)}]`;
      default:
        return `[${name.toLowerCase()}]`;
    }
  } catch {
    return `[${name.toLowerCase()}]`;
  }
}

// Build sidebar tree HTML
function buildTreeHtml(turns) {
  const nodes = [];
  
  turns.forEach((turn, idx) => {
    if (turn.role === 'user') {
      const preview = (turn.text || '').substring(0, 40).replace(/\n/g, ' ').trim();
      const truncated = (turn.text || '').length > 40 ? '...' : '';
      nodes.push(`<div class="tree-node" data-target="${turn.id}" data-role="user"><span class="tree-role-user">user:</span> <span class="tree-content">${escapeHtml(preview)}${truncated}</span></div>`);
    } else {
      // Assistant message - show text if present
      if (turn.text) {
        const preview = turn.text.substring(0, 40).replace(/\n/g, ' ').trim();
        const truncated = turn.text.length > 40 ? '...' : '';
        const hasTools = turn.hasTools ? ' data-has-tools="true"' : '';
        nodes.push(`<div class="tree-node" data-target="${turn.id}" data-role="assistant"${hasTools}><span class="tree-role-assistant">assistant:</span> <span class="tree-content">${escapeHtml(preview)}${truncated}</span></div>`);
      }
      
      // Show spec if present
      if (turn.spec) {
        nodes.push(`<div class="tree-node" data-target="${turn.id}" data-role="spec"><span class="tree-role-spec">📋 ${escapeHtml(turn.spec.title)}</span></div>`);
      }
      
      // Show each tool call as separate entry
      if (turn.tools && turn.tools.length > 0) {
        turn.tools.forEach((tool, toolIdx) => {
          const toolDisplay = formatToolCall(tool.name, tool.input);
          nodes.push(`<div class="tree-node tree-tool-node" data-target="${turn.id}" data-role="tool"><span class="tree-role-tool">${escapeHtml(toolDisplay)}</span></div>`);
        });
      }
      
      // If no text, no tools, and no spec, show placeholder
      if (!turn.text && (!turn.tools || turn.tools.length === 0) && !turn.spec) {
        nodes.push(`<div class="tree-node" data-target="${turn.id}" data-role="assistant"><span class="tree-role-assistant">assistant:</span> <span class="tree-muted">(no text)</span></div>`);
      }
    }
  });
  
  return nodes.join('\n');
}

// Copy link button SVG
const copyLinkSvg = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>`;

// Build messages HTML
function buildMessagesHtml(turns) {
  return turns.map(turn => {
    const time = turn.timestamp ? new Date(turn.timestamp).toLocaleTimeString() : '';
    const copyBtn = `<button class="copy-link-btn" data-id="${turn.id}" title="Copy link">${copyLinkSvg}</button>`;
    
    if (turn.role === 'user') {
      return `<div class="user-message" id="${turn.id}">
  ${copyBtn}
  <div class="message-timestamp">${time}</div>
  <div class="markdown-content">${escapeHtml(turn.text)}</div>
</div>`;
    }
    
    // Assistant message
    let html = `<div class="assistant-message" id="${turn.id}">
  ${copyBtn}
  <div class="message-timestamp">${time}</div>`;
    
    if (turn.thinking) {
      html += `
  <div class="thinking-block">
    <div class="thinking-collapsed">Thinking... (click to expand)</div>
    <div class="thinking-text">${escapeHtml(turn.thinking)}</div>
  </div>`;
    }
    
    if (turn.text) {
      html += `
  <div class="assistant-text"><div class="markdown-content">${escapeHtml(turn.text)}</div></div>`;
    }
    
    // Render spec block if present
    if (turn.spec) {
      const optionsHtml = turn.spec.options.length > 0 
        ? `<div class="spec-options"><span class="spec-options-label">Options:</span> ${turn.spec.options.map(o => `<span class="spec-option">${escapeHtml(o)}</span>`).join(' ')}</div>`
        : '';
      html += `
  <div class="spec-block">
    <div class="spec-header">
      <span class="spec-icon">📋</span>
      <span class="spec-title">${escapeHtml(turn.spec.title)}</span>
    </div>
    ${optionsHtml}
    <div class="spec-content markdown-content">${escapeHtml(turn.spec.plan)}</div>
  </div>`;
    }
    
    turn.tools.forEach(tool => {
      const status = tool.result ? 'success' : 'pending';
      const preview = tool.result ? tool.result.substring(0, 200) : '';
      const hasMore = tool.result && tool.result.length > 200;
      
      html += `
  <div class="tool-execution ${status}">
    <div class="tool-header"><span class="tool-name">${escapeHtml(tool.name)}</span></div>
    <div class="tool-input"><pre>${escapeHtml(tool.input)}</pre></div>
    ${tool.result ? `<div class="tool-output expandable">
      <div class="output-preview"><pre>${escapeHtml(preview)}${hasMore ? '\n... (click to expand)' : ''}</pre></div>
      <div class="output-full"><pre>${escapeHtml(tool.result)}</pre></div>
    </div>` : ''}
  </div>`;
    });
    
    html += '\n</div>';
    return html;
  }).join('\n');
}

const title = escapeHtml(scrubSecrets(sessionStart?.title || 'Session Export'));
const sessionId = sessionStart?.id || 'unknown';
const cwd = sessionStart?.cwd ? escapeHtml(scrubSecrets(sessionStart.cwd)) : '';

const css = `
:root {
  /* Factory Design System - Tungsten Dark Theme */
  --primary: #d56a26;
  --primary-light: #ffa469;
  --accent: #d56a26;
  --border: #342f2d;
  --border-light: #a89895;
  --success: #5b8e63;
  --error: #d9363e;
  --warning: #e3992a;
  --muted: #80756f;
  --dim: #59514d;
  --text: #f2f0f0;
  --text-secondary: #b3a9a4;
  --thinkingText: #80756f;
  --selectedBg: #282523;
  --userMessageBg: #1d1b1a;
  --toolPendingBg: #1d1b1a;
  --toolSuccessBg: #1e3a2a;
  --toolErrorBg: #3a1e1e;
  --body-bg: #282C34;
  --container-bg: #21252B;
  --surface-3: #282523;
  --surface-4: #342f2d;
  --line-height: 18px;
  
  /* Diff colors */
  --diff-added-bg: #1e3a2a;
  --diff-added-text: #b5f0b5;
  --diff-removed-bg: #3a1e1e;
  --diff-removed-text: #ffb0b0;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: ui-monospace, 'Cascadia Code', 'Source Code Pro', Menlo, Consolas, monospace;
  font-size: 12px;
  line-height: var(--line-height);
  color: var(--text);
  background: var(--body-bg);
}
#app { display: flex; min-height: 100vh; }

/* Sidebar */
#sidebar {
  width: 350px;
  background: var(--container-bg);
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  position: sticky;
  top: 0;
  height: 100vh;
  border-right: 1px solid var(--dim);
}
.sidebar-header { padding: 8px 12px; border-bottom: 1px solid var(--border); }
.sidebar-header h1 { font-size: 12px; color: var(--primary); margin-bottom: 2px; }
.sidebar-meta { font-size: 10px; color: var(--muted); }
.sidebar-controls { padding: 8px 8px 4px 8px; }
.sidebar-search {
  width: 100%;
  padding: 4px 8px;
  font-size: 11px;
  font-family: inherit;
  background: var(--body-bg);
  color: var(--text);
  border: 1px solid var(--dim);
  border-radius: 3px;
}
.sidebar-search:focus { outline: none; border-color: var(--primary); }
.sidebar-filters {
  display: flex;
  padding: 4px 8px 8px 8px;
  gap: 4px;
  flex-wrap: wrap;
}
.filter-btn {
  padding: 3px 8px;
  font-size: 10px;
  font-family: inherit;
  background: transparent;
  color: var(--muted);
  border: 1px solid var(--dim);
  border-radius: 3px;
  cursor: pointer;
}
.filter-btn:hover { color: var(--text); border-color: var(--border-light); }
.filter-btn.active { background: var(--primary); color: var(--body-bg); border-color: var(--primary); }
.tree-container { flex: 1; overflow: auto; padding: 4px 0; }
.tree-node {
  padding: 2px 8px;
  cursor: pointer;
  display: flex;
  align-items: baseline;
  font-size: 11px;
  line-height: 13px;
  white-space: nowrap;
  overflow: hidden;
}
.tree-node:hover { background: var(--selectedBg); }
.tree-node.active { background: var(--selectedBg); }
.tree-node.active .tree-content { font-weight: bold; }
.tree-marker { flex-shrink: 0; margin-right: 4px; }
.tree-role-user { color: var(--primary-light); }
.tree-role-assistant { color: var(--success); }
.tree-role-tool { color: var(--muted); }
.tree-role-spec { color: #b5b1fc; font-weight: bold; }
.tree-muted { color: var(--dim); font-style: italic; }
.tree-tool-node { padding-left: 16px; }
.tree-content { color: var(--text); overflow: hidden; text-overflow: ellipsis; }
.tree-status { padding: 4px 12px; font-size: 10px; color: var(--muted); }
.help-bar { font-size: 11px; color: var(--text-secondary); margin-bottom: var(--line-height); }

/* Content */
#content {
  flex: 1;
  overflow-y: auto;
  padding: var(--line-height) calc(var(--line-height) * 2);
  display: flex;
  flex-direction: column;
  align-items: center;
}
#content > * { width: 100%; max-width: 800px; }
#messages { display: flex; flex-direction: column; gap: var(--line-height); }

.message-timestamp { font-size: 10px; color: var(--dim); opacity: 0.8; }
.user-message {
  background: var(--userMessageBg);
  padding: var(--line-height);
  border-radius: 4px;
  position: relative;
}
.assistant-message { padding: 0; position: relative; }

/* Copy link button */
.copy-link-btn {
  position: absolute;
  top: 8px;
  right: 8px;
  width: 28px;
  height: 28px;
  padding: 6px;
  background: var(--container-bg);
  border: 1px solid var(--dim);
  border-radius: 4px;
  color: var(--muted);
  cursor: pointer;
  opacity: 0;
  transition: opacity 0.15s, background 0.15s;
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 10;
}
.user-message:hover .copy-link-btn,
.assistant-message:hover .copy-link-btn { opacity: 1; }
.copy-link-btn:hover { background: var(--primary); color: var(--body-bg); border-color: var(--primary); }
.copy-link-btn.copied { background: var(--success); color: var(--body-bg); border-color: var(--success); }

/* Highlight for deep-linked messages */
.user-message.highlight,
.assistant-message.highlight { animation: highlight-pulse 2s ease-out; }
@keyframes highlight-pulse {
  0% { box-shadow: 0 0 0 3px var(--primary); }
  100% { box-shadow: 0 0 0 0 transparent; }
}
.assistant-message > .message-timestamp { padding-left: var(--line-height); }
.assistant-text { padding: var(--line-height); padding-top: 0; }
.message-timestamp + .assistant-text,
.message-timestamp + .thinking-block { padding-top: 0; }
.thinking-block + .assistant-text { padding-top: 0; }

/* Thinking */
.thinking-block { padding: var(--line-height); }
.thinking-collapsed {
  display: none;
  color: var(--thinkingText);
  font-style: italic;
  cursor: pointer;
}
.thinking-collapsed:hover { color: var(--primary); }
.thinking-text {
  color: var(--thinkingText);
  font-style: italic;
  white-space: pre-wrap;
}

/* Tools */
.tool-execution {
  padding: var(--line-height);
  border-radius: 4px;
}
.tool-execution + .tool-execution { margin-top: var(--line-height); }
.assistant-text + .tool-execution { margin-top: var(--line-height); }
.tool-execution.pending { background: var(--toolPendingBg); }
.tool-execution.success { background: var(--toolSuccessBg); }
.tool-execution.error { background: var(--toolErrorBg); }
.tool-header { font-weight: bold; }
.tool-name { color: var(--text); }
.tool-input pre, .tool-output pre {
  margin: 0;
  font-family: inherit;
  white-space: pre-wrap;
  word-break: break-word;
  color: var(--muted);
}
.tool-output { margin-top: var(--line-height); color: var(--muted); }
.tool-output.expandable { cursor: pointer; }
.tool-output.expandable:hover { opacity: 0.9; }
.tool-output.expandable .output-full { display: none; }
.tool-output.expandable.expanded .output-preview { display: none; }
.tool-output.expandable.expanded .output-full { display: block; }

/* Markdown */
.markdown-content { white-space: pre-wrap; word-wrap: break-word; }
.markdown-content h1, .markdown-content h2, .markdown-content h3 {
  color: var(--primary-light);
  margin: var(--line-height) 0 0 0;
  font-weight: bold;
  font-size: 1em;
}
.markdown-content code {
  background: var(--surface-3);
  color: var(--primary-light);
  padding: 0 4px;
  border-radius: 3px;
}
.markdown-content pre {
  background: var(--surface-3);
  margin: var(--line-height) 0;
  overflow-x: auto;
  padding: var(--line-height);
  border-radius: 4px;
}
.markdown-content pre code { display: block; background: none; color: var(--text); padding: 0; }
.markdown-content a { color: #50acf2; text-decoration: underline; }
.markdown-content ul, .markdown-content ol { padding-left: 1.2em; margin: 0; margin-left: 0; }
.markdown-content li { margin: 0; padding-left: 0.3em; list-style-position: outside; line-height: var(--line-height); }
.markdown-content ul ul, .markdown-content ol ol, .markdown-content ul ol, .markdown-content ol ul { margin: 0; margin-left: 1em; }
.markdown-content blockquote {
  border-left: 3px solid var(--primary);
  padding-left: var(--line-height);
  margin: var(--line-height) 0;
  color: var(--text-secondary);
  font-style: italic;
}

/* Spec blocks */
.spec-block {
  background: linear-gradient(135deg, rgba(181, 177, 252, 0.1) 0%, rgba(213, 106, 38, 0.05) 100%);
  border: 1px solid #b5b1fc;
  border-radius: 8px;
  padding: var(--line-height);
  margin: var(--line-height) 0;
}
.spec-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: var(--line-height);
  padding-bottom: 8px;
  border-bottom: 1px solid rgba(181, 177, 252, 0.3);
}
.spec-icon { font-size: 16px; }
.spec-title {
  font-weight: bold;
  font-size: 14px;
  color: #b5b1fc;
}
.spec-options {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-bottom: var(--line-height);
  flex-wrap: wrap;
}
.spec-options-label {
  color: var(--text-secondary);
  font-size: 11px;
}
.spec-option {
  background: rgba(181, 177, 252, 0.2);
  color: #b5b1fc;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
}
.spec-content {
  color: var(--text);
}
.spec-content h1, .spec-content h2, .spec-content h3 {
  color: #b5b1fc;
}

/* Mobile */
@media (max-width: 768px) {
  #sidebar { display: none; }
  #content { padding: 12px; }
}
`;

const js = `
(function() {
  let filterMode = 'default';
  let thinkingExpanded = true;
  let toolOutputsExpanded = false;

  // Tree navigation
  document.querySelectorAll('.tree-node').forEach(node => {
    node.addEventListener('click', () => {
      const targetId = node.dataset.target;
      const target = document.getElementById(targetId);
      if (target) {
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        document.querySelectorAll('.tree-node').forEach(n => n.classList.remove('active'));
        node.classList.add('active');
      }
    });
  });

  // Search
  const searchInput = document.getElementById('search');
  searchInput.addEventListener('input', (e) => {
    applyFilters();
  });

  // Filter buttons
  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      filterMode = btn.dataset.filter;
      applyFilters();
    });
  });

  function applyFilters() {
    const query = searchInput.value.toLowerCase();
    document.querySelectorAll('.tree-node').forEach(node => {
      const text = node.textContent.toLowerCase();
      const role = node.dataset.role;
      
      let visible = text.includes(query);
      
      if (visible && filterMode === 'user-only') {
        visible = role === 'user';
      } else if (visible && filterMode === 'no-tools') {
        // Hide tool entries, keep user and assistant messages
        visible = role !== 'tool';
      }
      
      node.style.display = visible ? '' : 'none';
    });
    updateStatus();
  }

  function updateStatus() {
    const visible = document.querySelectorAll('.tree-node:not([style*="display: none"])').length;
    const total = document.querySelectorAll('.tree-node').length;
    document.getElementById('tree-status').textContent = visible + ' / ' + total + ' messages';
  }

  // Toggle thinking blocks
  const toggleThinking = () => {
    thinkingExpanded = !thinkingExpanded;
    document.querySelectorAll('.thinking-text').forEach(el => {
      el.style.display = thinkingExpanded ? '' : 'none';
    });
    document.querySelectorAll('.thinking-collapsed').forEach(el => {
      el.style.display = thinkingExpanded ? 'none' : 'block';
    });
  };

  // Toggle tool outputs
  const toggleToolOutputs = () => {
    toolOutputsExpanded = !toolOutputsExpanded;
    document.querySelectorAll('.tool-output.expandable').forEach(el => {
      el.classList.toggle('expanded', toolOutputsExpanded);
    });
  };

  // Click handlers for thinking blocks
  document.querySelectorAll('.thinking-collapsed').forEach(el => {
    el.addEventListener('click', () => {
      el.parentElement.querySelector('.thinking-text').style.display = '';
      el.style.display = 'none';
    });
  });

  // Click handlers for tool outputs
  document.querySelectorAll('.tool-output.expandable').forEach(el => {
    el.addEventListener('click', () => {
      el.classList.toggle('expanded');
    });
  });

  // Keyboard shortcuts
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      searchInput.value = '';
      filterMode = 'default';
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      document.querySelector('.filter-btn[data-filter="default"]').classList.add('active');
      applyFilters();
    }
    if (e.ctrlKey && e.key === 't') {
      e.preventDefault();
      toggleThinking();
    }
    if (e.ctrlKey && e.key === 'o') {
      e.preventDefault();
      toggleToolOutputs();
    }
  });

  // Render markdown
  document.querySelectorAll('.markdown-content').forEach(el => {
    let text = el.textContent;
    text = text
      .replace(/^### (.+)$/gm, '<h3>$1</h3>')
      .replace(/^## (.+)$/gm, '<h2>$1</h2>')
      .replace(/^# (.+)$/gm, '<h1>$1</h1>')
      .replace(/\`\`\`(\\w*)\\n([\\s\\S]*?)\`\`\`/g, '<pre><code>$2</code></pre>')
      .replace(/\`([^\`]+)\`/g, '<code>$1</code>')
      .replace(/\\*\\*([^*]+)\\*\\*/g, '<strong>$1</strong>')
      .replace(/\\*([^*]+)\\*/g, '<em>$1</em>')
      .replace(/^- (.+)$/gm, '<li>$1</li>')
      .replace(/((<li>.*<\\/li>\\s*)+)/gm, function(match) { return '<ul>' + match + '</ul>'; })
      .replace(/^> (.+)$/gm, '<blockquote>$1</blockquote>')
      .replace(/\\[([^\\]]+)\\]\\(([^)]+)\\)/g, '<a href="$2" target="_blank">$1</a>');
    el.innerHTML = text;
  });

  // Copy link buttons
  document.querySelectorAll('.copy-link-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const id = btn.dataset.id;
      const baseUrl = window.location.href.split('#')[0].split('?')[0];
      const url = baseUrl + '?target=' + id;
      
      navigator.clipboard.writeText(url).then(() => {
        btn.classList.add('copied');
        setTimeout(() => btn.classList.remove('copied'), 1500);
      });
    });
  });

  // Handle deep link on load
  const params = new URLSearchParams(window.location.search);
  const targetId = params.get('target');
  if (targetId) {
    const target = document.getElementById(targetId);
    if (target) {
      setTimeout(() => {
        target.scrollIntoView({ behavior: 'smooth', block: 'center' });
        target.classList.add('highlight');
        // Activate corresponding tree node
        const treeNode = document.querySelector('.tree-node[data-target="' + targetId + '"]');
        if (treeNode) {
          document.querySelectorAll('.tree-node').forEach(n => n.classList.remove('active'));
          treeNode.classList.add('active');
        }
      }, 100);
    }
  }

  // Initial status
  updateStatus();
})();
`;

const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title}</title>
  <style>${css}</style>
</head>
<body>
  <div id="app">
    <aside id="sidebar">
      <div class="sidebar-header">
        <h1>Session Export</h1>
        <div class="sidebar-meta">${turns.length} messages${cwd ? ' · ' + cwd : ''}</div>
      </div>
      <div class="sidebar-controls">
        <input type="text" id="search" class="sidebar-search" placeholder="Search...">
      </div>
      <div class="sidebar-filters">
        <button class="filter-btn active" data-filter="default" title="All messages">Default</button>
        <button class="filter-btn" data-filter="no-tools" title="Hide tool results">No-tools</button>
        <button class="filter-btn" data-filter="user-only" title="Only user messages">User</button>
      </div>
      <div class="tree-container">
${buildTreeHtml(turns)}
      </div>
      <div class="tree-status" id="tree-status"></div>
    </aside>
    <main id="content">
      <div class="help-bar">Ctrl+T toggle thinking · Ctrl+O toggle tool outputs · Esc reset</div>
      <div id="messages">
${buildMessagesHtml(turns)}
      </div>
    </main>
  </div>
  <script>${js}</script>
</body>
</html>`;

fs.writeFileSync(outputFile, html);
console.log('Exported to: ' + outputFile);
console.log('Note: Secrets have been scrubbed (API keys, tokens, passwords, etc.)');
