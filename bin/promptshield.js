#!/usr/bin/env node
'use strict';

const { analyzePrompt } = require('../lib/promptShield');

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', chunk => { data += chunk; });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}

function printHelp() {
  console.log(`promptshield — detect prompt injection / jailbreak patterns

Usage:
  promptshield "some text to check"
  echo "some text" | promptshield
  promptshield --json "some text"
  promptshield --threshold 6 "some text"

Options:
  --json          Output raw JSON instead of a human-readable report
  --threshold N   Risk score threshold for "safe" (default: 12)
  -h, --help      Show this help message
`);
}

async function main() {
  const args = process.argv.slice(2);

  if (args.includes('-h') || args.includes('--help')) {
    printHelp();
    process.exit(0);
  }

  const jsonOutput = args.includes('--json');
  let threshold = 12;
  const thresholdIdx = args.indexOf('--threshold');
  if (thresholdIdx !== -1 && args[thresholdIdx + 1]) {
    threshold = Number(args[thresholdIdx + 1]);
  }

  const positional = args.filter((a, i) =>
    !a.startsWith('--') &&
    a !== '-h' &&
    !(thresholdIdx !== -1 && i === thresholdIdx + 1)
  );

  let text = positional.join(' ');
  if (!text) {
    text = await readStdin();
  }

  if (!text || !text.trim()) {
    console.error('Error: no input text provided. Use --help for usage.');
    process.exit(2);
  }

  const result = analyzePrompt(text, { threshold });

  if (jsonOutput) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(`Risk level: ${result.riskLevel.toUpperCase()} (score: ${result.score})`);
    console.log(`Safe: ${result.safe}`);
    if (result.findings.length) {
      console.log('\nFindings:');
      for (const f of result.findings) {
        console.log(`  - [${f.category}] ${f.id} (weight ${f.weight})`);
        console.log(`    ${f.description}`);
        console.log(`    matched: "${f.matchedText}"`);
      }
    } else {
      console.log('\nNo suspicious patterns found.');
    }
  }

  process.exit(result.safe ? 0 : 1);
}

main().catch(err => {
  console.error('promptshield failed:', err.message);
  process.exit(2);
});
