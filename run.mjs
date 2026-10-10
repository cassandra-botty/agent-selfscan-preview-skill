#!/usr/bin/env node
// run.mjs — runx runner for agent-selfscan-preview (wake 184, 2026-10-10).
//
// Runs the SAME prober shipped as the free store download (selfscan/selfscan.js,
// byte-identical to tools/selfscan/selfscan.js) as a child process, then checks
// its verdict against the fixture's known defect (or known honesty).
// Self-failing by construction: the leaky fixture MUST be flagged and the
// private-target refusal MUST happen — if the prober ever goes blind, this
// runner exits 1 and the harness reports it. Exit 0 = prober behaved correctly.
import { execFileSync, execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';
import http from 'node:http';

const MODE = process.env.RUNX_INPUT_MODE || '';
const TARGET = process.env.RUNX_INPUT_TARGET || '';
const IMPL = path.join(path.dirname(fileURLToPath(import.meta.url)), 'selfscan', 'selfscan.js');

const TERMS = JSON.stringify({
  error: 'payment_required',
  accepts: [{ scheme: 'exact', network: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',
    asset: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', amount: '5000000',
    payTo: '1111111111111111111111111111111111111111111111', decimals: 6 }],
});

function startServer(mode) {
  return new Promise((resolve, reject) => {
    const srv = http.createServer((req, res) => {
      if (mode === 'happy') {
        if (req.url.includes('__selfscan_probe_nonexistent__')) {
          res.writeHead(404, { 'content-type': 'text/plain' });
          return res.end('not found');
        }
        res.writeHead(402, { 'content-type': 'application/json', 'payment-required': Buffer.from(TERMS).toString('base64') });
        return res.end(TERMS);
      }
      if (mode === 'leaky') {
        if (req.url.includes('__selfscan_probe_nonexistent__')) {
          res.writeHead(500, { 'content-type': 'text/plain' });
          // FAKE internal address example — the defect the leak checker must catch.
          return res.end('Error: connect ECONNREFUSED 10.20.30.40:5432\n    at db.query (/app/db.js:41)\n    at handler (/app/routes.js:12)');
        }
        res.writeHead(200, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ answer: 'paid answer with no payment', data: 'x'.repeat(60) }));
      }
      if (mode === 'throttle') {
        res.writeHead(429, { 'content-type': 'application/json', 'retry-after': '600' });
        return res.end(JSON.stringify({ error: 'rate_limited', retry_after_seconds: 600 }));
      }
      res.writeHead(404); res.end('');
    });
    srv.listen(0, '127.0.0.1', () => resolve(srv));
    srv.on('error', reject);
  });
}

// Expectation oracle: given the prober's stdout + exit code, did it behave
// CORRECTLY for this mode? Returns null when correct, a reason when not.
function oracle(mode, exitCode, text) {
  const flags = (text.match(/FLAG/g) || []).length;
  switch (mode) {
    case 'happy':
      if (exitCode !== 0) return 'expected exit 0 on honest fixture, got ' + exitCode;
      if (flags !== 0) return 'honest fixture produced ' + flags + ' FLAG lines (false positives)';
      if (!/gate shape/.test(text)) return 'honest 402 fixture produced no gate-shape observation';
      return null;
    case 'leaky':
      if (exitCode !== 1) return 'leaky fixture must be flagged (exit 1), got exit ' + exitCode;
      if (flags < 3) return 'leaky fixture produced only ' + flags + ' FLAG lines; expected gate-open + 5xx + private-address (>= 3)';
      if (!/5xx on junk/.test(text)) return 'missed junk-path 5xx';
      if (!/10\.20\.30\.40/.test(text)) return 'missed private-address literal in error body';
      if (!/gate-open/.test(text)) return 'missed open paid path (200 with data)';
      return null;
    case 'throttle':
      if (exitCode !== 0) return 'expected exit 0 on throttled fixture, got ' + exitCode;
      if (flags !== 0) return 'throttled fixture produced ' + flags + ' FLAG lines (429 must be inconclusive)';
      if (!/INCONCLUSIVE|inconclusive|limiter fired/.test(text)) return 'throttle probe gave no inconclusive observation';
      return null;
    case 'reject':
      if (exitCode !== 2) return 'expected exit 2 (refused private target), got ' + exitCode;
      if (!/refused/i.test(text)) return 'refusal did not name itself as refused';
      if (/FLAG/.test(text)) return 'refusal mode should not reach flagging';
      return null;
    case 'selfuse':
      // live target, no verdict about the target — only that the prober ran
      // honestly: it must not claim a clean bill without observations.
      if (exitCode === 2) {
        if (/COULD NOT RUN/.test(text)) return null;
        return 'exit 2 without COULD NOT RUN honesty line';
      }
      if (exitCode === 0 && /COULD NOT RUN/.test(text)) return 'claimed could-not-run but exited 0';
      return null;
    default:
      return 'unknown mode: ' + JSON.stringify(mode);
  }
}

async function main() {
  if (!MODE) { process.stdout.write('SELFSCAN-RUNNER: no mode input\n'); process.exit(1); }
  if (!fs.existsSync(IMPL)) { process.stdout.write('SELFSCAN-RUNNER: prober file missing at ' + IMPL + '\n'); process.exit(1); }

  let srv = null;
  let target = TARGET;
  if (MODE === 'reject') target = 'http://127.0.0.1:1/api/ask';
  if (MODE !== 'reject' && MODE !== 'selfuse') {
    if (!['happy', 'leaky', 'throttle'].includes(MODE)) {
      process.stdout.write('SELFSCAN-RUNNER: unknown mode ' + JSON.stringify(MODE) + '\n'); process.exit(1);
    }
    srv = await startServer(MODE);
    target = 'http://127.0.0.1:' + srv.address().port + '/api/ask';
  }
  if (MODE === 'selfuse' && !target) {
    process.stdout.write('SELFSCAN-RUNNER: selfuse mode needs a target input\n'); process.exit(1);
  }

  const argv = [IMPL, '--target', target, '--pace', '150'];
  if (MODE !== 'reject') argv.push('--allow-private'); // fixture/self-target only

  let res;
  try {
    // ASYNC on purpose: the fixture server lives in THIS event loop; a
    // synchronous spawn would block it and starve the child's requests.
    const { stdout, code } = await new Promise((ok, err) => {
      execFile('node', argv, { timeout: 30000 }, (e, so, se) => {
        if (e && typeof e.code !== 'number') return err(e); // real spawn failure
        ok({ stdout: (so || '') + (se || ''), code: e ? e.code : 0 });
      });
    });
    res = { code, text: stdout };
  } catch (e) {
    if (srv) srv.close();
    process.stdout.write('SELFSCAN-RUNNER: could not run prober: ' + e.message + '\n');
    process.exit(1);
  }
  if (srv) srv.close();

  const why = oracle(MODE, res.code, res.text);
  if (why) {
    process.stdout.write('SELFSCAN-RUNNER: PROBE MISHANDLED CASE — ' + why + '\n');
    process.stdout.write(res.text.slice(-2000) + '\n');
    process.exit(1);
  }
  process.stdout.write('SELFSCAN-RUNNER: prober behaved correctly for mode=' + MODE +
                       ' (probe exit ' + res.code + ')\n');
  process.exit(0);
}

main().catch(e => { process.stdout.write('SELFSCAN-RUNNER: unexpected: ' + (e && e.message) + '\n'); process.exit(1); });
