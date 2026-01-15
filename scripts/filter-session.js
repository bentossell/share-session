#!/usr/bin/env node
// Filter session JSONL based on instructions
// Usage: filter-session.js <input.jsonl> <output.jsonl> <instruction>
// Example: filter-session.js session.jsonl filtered.jsonl "ignore the last 4 user and assistant messages"

const fs = require('fs');

const inputFile = process.argv[2];
const outputFile = process.argv[3];
const instruction = process.argv.slice(4).join(' ');

if (!inputFile || !outputFile) {
  console.error('Usage: filter-session.js <input.jsonl> <output.jsonl> [instruction]');
  process.exit(1);
}

const content = fs.readFileSync(inputFile, 'utf-8');
const lines = content.trim().split('\n').filter(Boolean);

let events = lines.map((line, idx) => {
  try {
    return { idx, event: JSON.parse(line), raw: line };
  } catch (e) {
    return { idx, event: null, raw: line };
  }
});

// Parse instruction to filter messages
if (instruction) {
  const lowerInst = instruction.toLowerCase();
  
  // Match "ignore the last N user and assistant messages" or "ignore last N messages"
  const lastNMatch = lowerInst.match(/(?:ignore|remove|skip|drop|exclude)\s+(?:the\s+)?last\s+(\d+)\s+(?:user\s+and\s+assistant\s+)?messages?/i);
  
  if (lastNMatch) {
    const n = parseInt(lastNMatch[1], 10);
    
    // Find indices of user and assistant messages
    const messageIndices = [];
    events.forEach((e, idx) => {
      if (e.event && (e.event.role === 'user' || e.event.role === 'assistant')) {
        messageIndices.push(idx);
      }
    });
    
    // Remove the last N message indices
    const indicesToRemove = new Set(messageIndices.slice(-n));
    events = events.filter((_, idx) => !indicesToRemove.has(idx));
    
    console.log(`Removed last ${n} user/assistant messages (${indicesToRemove.size} events)`);
  }
  
  // Match "only include first N messages" or "first N messages only"
  const firstNMatch = lowerInst.match(/(?:only\s+)?(?:include\s+)?first\s+(\d+)\s+messages?/i);
  
  if (firstNMatch) {
    const n = parseInt(firstNMatch[1], 10);
    let count = 0;
    const keepIndices = new Set();
    
    events.forEach((e, idx) => {
      if (e.event && (e.event.role === 'user' || e.event.role === 'assistant')) {
        if (count < n) {
          keepIndices.add(idx);
          count++;
        }
      } else {
        // Keep system events, tool calls etc that come before the cutoff
        if (count <= n) keepIndices.add(idx);
      }
    });
    
    events = events.filter((_, idx) => keepIndices.has(idx));
    console.log(`Kept first ${n} messages`);
  }
}

// Write filtered events
const output = events.map(e => e.raw).join('\n') + '\n';
fs.writeFileSync(outputFile, output);
console.log(`Wrote ${events.length} events to: ${outputFile}`);
