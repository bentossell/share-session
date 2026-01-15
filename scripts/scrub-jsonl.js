#!/usr/bin/env node
// Scrub secrets from JSONL session file

const fs = require('fs');

const inputFile = process.argv[2];
const outputFile = process.argv[3];

if (!inputFile || !outputFile) {
  console.error('Usage: scrub-jsonl.js <input.jsonl> <output.jsonl>');
  process.exit(1);
}

// Secret patterns to scrub - comprehensive list
const PRIVATE_KEY_PATTERN = /(-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----)/g;
const BASIC_AUTH_URL_PATTERN = /\b([a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\/\s:@]+:)([^@\s]+)(@)/g;

const SECRET_PATTERNS = [
  // Environment variable assignments: VAR_NAME=value (catches RESEND_API_KEY=xxx, etc)
  /\b([A-Za-z][A-Za-z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)[A-Za-z0-9_]*)\s*=\s*['"]?([^\s'"&|;]+)/gi,
  /\b([A-Za-z][A-Za-z0-9_]*(?:API|AUTH)[A-Za-z0-9_]*)\s*=\s*['"]?([^\s'"&|;]+)/gi,
  // export VAR=value
  /(export\s+[A-Za-z][A-Za-z0-9_]*)\s*=\s*['"]?([^\s'"&|;]{8,})/gi,
  // Common token fields in configs/JSON
  /\b((?:access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|private[_-]?key|private[_-]?key_id|session[_-]?token|oauth[_-]?token|auth[_-]?token|_?authToken)[\s'":=]+)([^\s'"]{8,})/gi,
  // Resend keys specifically
  /\b(re_[a-zA-Z0-9]{20,})\b/g,
  // Loops keys
  /\b(loops_[a-zA-Z0-9]{20,})\b/gi,
  // API keys with various prefixes
  /\b(sk-[a-zA-Z0-9]{20,})\b/g,
  /\b(pk-[a-zA-Z0-9]{20,})\b/g,
  /\b(sk-proj-[a-zA-Z0-9_\-]{20,})\b/g,
  /\b(sk-ant-[a-zA-Z0-9_\-]{20,})\b/g,
  // Bearer tokens
  /(bearer\s+)([a-zA-Z0-9_\-\.]{20,})/gi,
  // JWT tokens
  /\b(eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,})\b/g,
  // AWS keys
  /\b(AKIA[0-9A-Z]{16})\b/g,
  /\b(ASIA[0-9A-Z]{16})\b/g,
  /\b(aws[_-]?secret[_-]?access[_-]?key[\s'":\=]*)([\w/+=]{30,})/gi,
  /\b(aws[_-]?session[_-]?token[\s'":\=]*)([\w/+=]{16,})/gi,
  // GitHub tokens
  /\b(ghp_[a-zA-Z0-9]{36})\b/g,
  /\b(gho_[a-zA-Z0-9]{36})\b/g,
  /\b(ghs_[a-zA-Z0-9]{36})\b/g,
  /\b(ghc_[a-zA-Z0-9]{36})\b/g,
  /\b(ghu_[a-zA-Z0-9]{36})\b/g,
  /\b(github_pat_[a-zA-Z0-9_]{22,})\b/g,
  // GitLab tokens
  /\b(glpat-[a-zA-Z0-9_\-]{20,})\b/g,
  // Stripe keys
  /\b(sk_live_[a-zA-Z0-9]{20,})\b/g,
  /\b(sk_test_[a-zA-Z0-9]{20,})\b/g,
  /\b(pk_live_[a-zA-Z0-9]{20,})\b/g,
  /\b(pk_test_[a-zA-Z0-9]{20,})\b/g,
  /\b(whsec_[a-zA-Z0-9]{20,})\b/g,
  // Slack tokens
  /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/g,
  /\b(xapp-[A-Za-z0-9-]{10,})\b/g,
  // Webhooks
  /\bhttps?:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9\/]{10,}\b/g,
  /\bhttps?:\/\/(?:discord\.com|discordapp\.com)\/api\/webhooks\/\d+\/[A-Za-z0-9_\-]+\b/gi,
  // SendGrid
  /\b(SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})\b/g,
  // Mailgun
  /\b(key-[a-z0-9]{32})\b/gi,
  // Twilio
  /\b(SK[a-zA-Z0-9]{32})\b/g,
  // NPM
  /\b(npm_[A-Za-z0-9]{36})\b/g,
  // GCP keys
  /\b(AIza[0-9A-Za-z_\-]{35})\b/g,
  /\b(1\/\/[0-9A-Za-z_\-]{20,})\b/g,
  // Azure SAS and storage connection strings
  /\b(sig=)([A-Za-z0-9%/+=]{20,})/gi,
  /\b(DefaultEndpointsProtocol=[^;]+;AccountName=[^;]+;AccountKey=)([^;]+)\b/gi,
  // API key assignments in various formats
  /\b(api[_-]?key[s]?[\s'":\=]*)([\w\-]{16,})/gi,
  /\b(api[_-]?secret[\s'":\=]*)([\w\-]{16,})/gi,
  // Generic key/secret/token/password in context
  /\b(password[\s'":\=]+)([^\s'"]{8,})/gi,
  /\b(secret[\s'":\=]+)([\w\-]{12,})/gi,
  /\b(token[\s'":\=]+)([\w\-\.]{16,})/gi,
  /\b(key[\s'":\=]+)([\w\-]{20,})/gi,
  // "my API key" or "the API key" followed by something
  /(my|the|your|this)\s+(api[_\s-]?key|secret|token|password)[\s:]+(\S{12,})/gi,
  // "add...key...to" patterns with the key
  /(add|set|use|put|enter|paste|copy)\s+[^.]*?(key|secret|token|password)[^.]*?[\s:'"]+([a-zA-Z0-9_\-]{16,})/gi,
  // Generic long alphanumeric strings that look like keys (40+ chars)
  /\b([a-zA-Z0-9_\-]{40,})\b/g,
  // Hex strings that look like secrets (32+ hex chars)
  /\b([a-f0-9]{32,})\b/gi,
  // Base64 encoded strings that are long (likely secrets)
  /\b([A-Za-z0-9+/]{40,}={0,2})\b/g,
];

function scrubSecrets(text) {
  if (!text || typeof text !== 'string') return text;
  let scrubbed = text;

  scrubbed = scrubbed.replace(PRIVATE_KEY_PATTERN, '[REDACTED_PRIVATE_KEY]');
  scrubbed = scrubbed.replace(BASIC_AUTH_URL_PATTERN, (match, prefix, secret, at) => {
    if (secret && secret.length >= 1) {
      return `${prefix}[REDACTED]${at}`;
    }
    return match;
  });

  SECRET_PATTERNS.forEach((pattern) => {
    scrubbed = scrubbed.replace(pattern, (match, ...groups) => {
      const captureGroups = groups.filter(g => typeof g === 'string');
      if (captureGroups.length >= 2) {
        const prefix = captureGroups[0];
        const secret = captureGroups[captureGroups.length - 1];
        if (secret && secret.length >= 8) {
          if (/[=:]\s*$/.test(prefix)) return prefix + '[REDACTED]';
          if (/\s$/.test(prefix)) return prefix + '[REDACTED]';
          return prefix + '=[REDACTED]';
        }
      }
      if (match.length >= 16 && /^[\w\-+/=.]+$/.test(match)) {
        return '[REDACTED]';
      }
      return match;
    });
  });
  
  return scrubbed;
}

function scrubObject(obj) {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === 'string') return scrubSecrets(obj);
  if (Array.isArray(obj)) return obj.map(scrubObject);
  if (typeof obj === 'object') {
    const result = {};
    for (const [key, value] of Object.entries(obj)) {
      result[key] = scrubObject(value);
    }
    return result;
  }
  return obj;
}

// Read and process each line
const content = fs.readFileSync(inputFile, 'utf-8');
const lines = content.trim().split('\n').filter(Boolean);

const scrubbedLines = lines.map(line => {
  try {
    const event = JSON.parse(line);
    const scrubbed = scrubObject(event);
    return JSON.stringify(scrubbed);
  } catch (e) {
    return scrubSecrets(line);
  }
});

fs.writeFileSync(outputFile, scrubbedLines.join('\n') + '\n');
console.log(`Scrubbed ${lines.length} lines to: ${outputFile}`);
