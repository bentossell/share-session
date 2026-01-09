#!/usr/bin/env node
// Export Droid session to Markdown

const fs = require('fs');

const sessionFile = process.argv[2];
if (!sessionFile) {
  console.error('Usage: export-md.js <session.jsonl> [output.md]');
  process.exit(1);
}

const outputFile = process.argv[3] || sessionFile.replace('.jsonl', '.md');

// Secret patterns to scrub - comprehensive list
const SECRET_PATTERNS = [
  // Environment variable assignments: VAR_NAME=value (catches RESEND_API_KEY=xxx, etc)
  /\b([A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)[A-Z0-9_]*)\s*=\s*['"]?([^\s'"&|;]+)/gi,
  /\b([A-Z][A-Z0-9_]*(?:API|AUTH)[A-Z0-9_]*)\s*=\s*['"]?([^\s'"&|;]+)/gi,
  // export VAR=value
  /(export\s+[A-Z][A-Z0-9_]*)\s*=\s*['"]?([^\s'"&|;]{8,})/gi,
  // Resend keys specifically
  /\b(re_[a-zA-Z0-9]{20,})\b/g,
  // Loops keys
  /\b(loops_[a-zA-Z0-9]{20,})\b/gi,
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

// Check if message is purely tool results
function isToolResultMessage(content) {
  if (!Array.isArray(content)) return false;
  return content.length > 0 && content.every(block => block.type === 'tool_result');
}

// Helper to extract text from content blocks
const extractText = (content) => {
  if (typeof content === 'string') return scrubSecrets(content);
  if (!Array.isArray(content)) return '';
  
  return content.map(block => {
    if (block.type === 'text') return scrubSecrets(block.text);
    if (block.type === 'thinking') {
      return `<details>\n<summary>💭 Thinking</summary>\n\n${scrubSecrets(block.thinking)}\n\n</details>`;
    }
    if (block.type === 'tool_use') {
      const input = scrubSecrets(JSON.stringify(block.input, null, 2));
      const result = toolResults.get(block.id) || '';
      let md = `<details>\n<summary>🔧 Tool: ${block.name}</summary>\n\n\`\`\`json\n${input}\n\`\`\`\n\n</details>`;
      if (result) {
        const truncated = result.length > 2000 ? result.slice(0, 2000) + '\n... (truncated)' : result;
        md += `\n\n<details>\n<summary>📤 Result</summary>\n\n\`\`\`\n${truncated}\n\`\`\`\n\n</details>`;
      }
      return md;
    }
    if (block.type === 'tool_result') return ''; // Handled with tool_use
    if (block.type === 'image') return '*[Image attached]*';
    return '';
  }).filter(Boolean).join('\n\n');
};

// Strip system reminders from user messages
const cleanUserMessage = (text) => {
  if (text.includes('<system-reminder>')) {
    const parts = text.split('</system-reminder>');
    return parts[parts.length - 1].trim();
  }
  return text;
};

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

// Consolidate messages
const turns = consolidateMessages(messages);

// Generate Markdown
let md = `# ${scrubSecrets(sessionStart?.title || 'Droid Session')}

> **Session ID:** ${sessionStart?.id || 'unknown'}  
> **Directory:** ${scrubSecrets(sessionStart?.cwd || 'N/A')}  
> **Messages:** ${turns.length} turns

---

`;

turns.forEach((turn) => {
  const timestamp = turn.timestamp ? new Date(turn.timestamp).toLocaleString() : '';
  const icon = turn.role === 'user' ? '👤' : '🤖';
  const label = turn.role === 'user' ? 'User' : 'Assistant';
  
  md += `## ${icon} ${label}\n`;
  if (timestamp) md += `*${timestamp}*\n\n`;
  md += `${turn.content}\n\n`;
  md += `---\n\n`;
});

fs.writeFileSync(outputFile, md);
console.log(`Exported to: ${outputFile}`);
console.log('Note: Secrets have been scrubbed (API keys, tokens, passwords, etc.)');
