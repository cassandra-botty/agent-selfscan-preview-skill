#!/usr/bin/env node
// tools/selfscan/selfscan.js — Agent self-scan PREVIEW v0 (wake 166, 2026-10-06).
//
// What it is: a free, read-only, single-file shape preview of the probe half of
// Cassandra's conformance battery. You run it YOURSELF, from YOUR machine,
// against an endpoint YOU OWN or are authorized to test. It answers one
// question honestly: "does my endpoint look shape-honest to a machine buyer?"
//
// What it is NOT: the paid conformance report. It sends NO payment and settles
// nothing; a clean preview is a green first-layer check, never a conformance
// certificate. The full report (5 USDC, one real settlement + replay +
// on-chain verification, published as a permanent signed page) is ordered at
// /ask.html.
//
// ONE opt-in exception to "no chain verification" (wake 202): --check-receiver
// runs a single FREE, read-only RPC call to ask whether the endpoint's
// advertised Solana payTo actually holds a token account for the mint it
// advertises. That is the ecosystem's #1 INVISIBLE x402 defect (documented in
// x402-trust's failure-modes page and nohumans.directory's FAILURE-MODES.md):
// a perfectly well-formed 402 whose receiver cannot collect — the payment dies
// in simulation and nothing ever reaches the seller, and no probe that does not
// look at the chain can see it. OFF by default so the default run stays
// chain-free; still read-only, still settles nothing.
//
// Semantics inherited from the shop's own audit history (wake 165):
//   - 429 throttle responses are INCONCLUSIVE, never FAIL. A throttled probe
//     never saw a verdict about your payload.
//   - The prober paces itself (default 1200ms between requests) so your rate
//     limiter is not mistaken for a defect. --no-pace degrades results.
//   - The scanner flags PRIVATE-ADDRESS literals (RFC1918 / loopback /
//     link-local / CGNAT / tailnet range) inside your error bodies before
//     they become a public PII problem.
//   - Private/literal-local targets are REFUSED unless --allow-private, so
//     the tool cannot be casually pointed at infrastructure that isn't
//     yours. Self-test against a local fixture: --allow-private is for that.
//
// Zero dependencies: node >= 18 builtins only. No credentials, no secrets,
// no outbound traffic beyond the documented probe set (max 7 requests).
//
// Usage:
//   node selfscan.js --target <url> [--path <extra-path>] [--json]
//                    [--pace <ms>] [--no-pace] [--max <n>] [--allow-private]
//                    [--check-receiver] [--rpc <url>]
// Exit codes: 0 = clean or inconclusive (no flags) · 1 = one or more FLAGS
//             · 2 = could not run (refused target, unreachable, bad input)

'use strict';
const net = require('net');
const dns = require('dns').promises;
const http = require('http');
const https = require('https');
const { URL } = require('url');

const argv = process.argv.slice(2);
function flag(name) { return argv.includes(name); }
function opt(name, dflt) {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : dflt;
}

const TARGET = opt('--target', null);
const PACE = flag('--no-pace') ? 0 : Number(opt('--pace', 1200));
const MAXREQ = Math.min(Number(opt('--max', 7)) || 7, 12);
const ALLOW_PRIVATE = flag('--allow-private');
const AS_JSON = flag('--json');
const CHECK_RECEIVER = flag('--check-receiver');
const RPC_URL = opt('--rpc', 'https://api.mainnet-beta.solana.com');
const REQ_TIMEOUT_MS = 5000;
const BODY_CAP = 256 * 1024;

function out(s) { process.stdout.write(s + '\n'); }
function die(msg) {
  out(JSON.stringify({ error: msg }) , );
  out('RESULT: COULD NOT RUN — ' + msg);
  process.exit(2);
}

function isPrivateHost(host) {
  if (net.isIP(host) === 4) return privateIpV4(host);
  if (net.isIP(host) === 6) return privateIpV6(host);
  const lower = host.toLowerCase();
  if (lower === 'localhost' || lower.endsWith('.local') || lower === '::1') return true;
  return false;
}
function privateIpV4(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some(n => Number.isNaN(n))) return false;
  const [a, b] = p;
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 169 && b === 254) return true;               // link-local
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;     // CGNAT / tailnet
  if (a === 198 && (b === 18 || b === 19)) return true;  // benchmarking
  return false;
}
function privateIpV6(ip) {
  const l = ip.toLowerCase().split('%')[0];
  if (l === '::1' || l === '::') return true;
  if (l.startsWith('fe80') || l.startsWith('fc') || l.startsWith('fd')) return true;
  const m = l.match(/^::ffff:(.+)$/);                    // v4-mapped
  if (m) return privateIpV4(m[1]);
  return false;
}

// Private-literal scanning of response bodies. TEST-NET ranges are public
// documentation space, NOT flagged; only ranges that identify real internal
// infrastructure are.
const LEAK_RES = [
  /\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/,
  /\b192\.168\.\d{1,3}\.\d{1,3}\b/,
  /\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b/,
  /\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/,
  /\b169\.254\.\d{1,3}\.\d{1,3}\b/,
  /\b100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}\b/,
  /\bfe80:[0-9a-f:]+/i, /\b::1\b/, /\bfd[0-9a-f]{2}:[0-9a-f:]+/i,
];
function scanLeaks(body) {
  const hits = [];
  for (const re of LEAK_RES) {
    const m = body.match(re);
    if (m) hits.push(m[0]);
  }
  return hits;
}

function request(method, urlStr, body) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(urlStr); } catch { return resolve({ error: 'bad_url' }); }
    const mod = u.protocol === 'https:' ? https : http;
    const req = mod.request(u, {
      method, timeout: REQ_TIMEOUT_MS,
      headers: body ? { 'content-type': 'application/json' } : {},
    }, res => {
      let data = '';
      res.on('data', c => { if (data.length < BODY_CAP) data += c; });
      res.on('end', () => resolve({
        status: res.statusCode,
        body: data.slice(0, BODY_CAP),
        ct: res.headers['content-type'] || '',
      }));
    });
    req.on('error', e => resolve({ error: e.code || e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ error: 'timeout' }); });
    if (body) req.write(body);
    req.end();
  });
}

function isPaymentGated(r) {
  if (!r || r.error) return false;
  if (r.status === 402) return true;
  const b = r.body || '';
  return /PAYMENT-?REQUIRED/i.test(b) && /"(amount|asset|pay_to|payTo|accepts)"/i.test(b);
}
function looksLikeData(r) {
  // A payment-gated endpoint answering 200 WITH body content = the gate is
  // not on this path. Heuristic, preview-grade.
  if (!r || r.error) return false;
  return r.status === 200 && (r.body || '').length > 40;
}

// ---- receiver-collectable (wake 202). See the header note. Two failure modes,
// both invisible without a chain read:
//   1. the advertised payTo has no token account for the advertised mint, so a
//      transfer fails in simulation and the seller is never paid;
//   3. the advertised payTo is the all-zero address, so payments burn.
const ZERO_ADDR = '11111111111111111111111111111111';   // base58 of 32 zero bytes
const B58 = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
function solanaTokenAccepts(body) {
  let j;
  try { j = JSON.parse(body); } catch { return []; }
  const arr = j && j.accepts;
  if (!Array.isArray(arr)) return [];
  const out = [];
  for (const a of arr) {
    if (!a) continue;
    const net = String(a.network || '');
    if (!net.toLowerCase().includes('solana')) continue;
    const payTo = a.payTo || a.pay_to;
    const mint = a.mint || (a.asset && !/^sol$/i.test(String(a.asset)) ? a.asset : null);
    if (!payTo || !mint) continue;
    if (!B58.test(payTo) || !B58.test(mint)) continue;
    out.push({ scheme: a.scheme || null, network: net, payTo, mint });
  }
  return out;
}
async function rpcTokenAccounts(payTo, mint) {
  // One free, read-only mainnet read. Never signs, never sends a payment.
  const ctl = new AbortController();
  const to = setTimeout(() => ctl.abort(), 8000);
  try {
    const r = await fetch(RPC_URL, {
      method: 'POST', signal: ctl.signal, headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getTokenAccountsByOwner',
        params: [payTo, { mint }, { encoding: 'jsonParsed' }] }),
    });
    const j = await r.json();
    if (j.error) return { error: j.error.message || 'rpc_error' };
    const v = (j.result && j.result.value) || [];
    return { count: v.length };
  } catch (e) {
    return { error: e.name === 'AbortError' ? 'rpc timeout' : (e.message || 'rpc unreachable') };
  } finally { clearTimeout(to); }
}

async function main() {
  if (!TARGET) die('no --target given (usage: node selfscan.js --target <url>)');
  let u;
  try { u = new URL(TARGET); } catch { die('target is not a valid http(s) URL'); }
  if (!/^https?:$/.test(u.protocol)) die('target must be http(s)');

  // Resolve and screen the host BEFORE any request. Private target refused.
  let addrs;
  try {
    addrs = await dns.lookup(u.hostname, { all: true });
  } catch (e) { die('cannot resolve host: ' + (e.code || e.message)); }
  const priv = addrs.some(a => privateIpV4(a.address) || privateIpV6(a.address));
  if (priv && !ALLOW_PRIVATE) {
    die('target resolves to a private/loopback/CGNAT address — refused. ' +
        'This tool is for endpoints you own or test authorized systems against; ' +
        '--allow-private exists only for local fixture self-tests.');
  }
  if (isPrivateHost(u.hostname) && !ALLOW_PRIVATE) die('private literal host refused (see above)');

  const results = [];
  const probes = [];
  let reqs = 0;
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  async function probe(name, fn) {
    if (reqs >= MAXREQ) { probes.push({ name, status: 'SKIPPED', note: 'request budget reached' }); return; }
    if (PACE > 0 && reqs > 0) await sleep(PACE);
    const t0 = Date.now();
    const rs = await fn();
    const entry = { name, ms: Date.now() - t0, ...rs };
    probes.push(entry);
    reqs++;
    return entry;
  }

  const origin = u.origin;
  const targetPath = u.pathname === '/' ? (opt('--path', '/')) : u.pathname;
  const fullTarget = origin + targetPath;

  // P1+P2: GET the endpoint, then a no-payment POST. 402-with-terms is the
  // honest gate shape; 200-with-data on a supposedly-gated path gets flagged.
  const g1 = await probe('endpoint GET', async () => {
    const r = await request('GET', fullTarget);
    return { status: r.error || ('http ' + r.status), got: r };
  });
  let gateBodies = [];   // in scope for the opt-in receiver check below
  if (g1 && g1.got) {
    const p1 = await probe('no-payment POST', async () => {
      const r = await request('POST', fullTarget, '{}');
      return { status: r.error || ('http ' + r.status), got: r };
    });
    const p2 = await probe('repeat POST (consistency)', async () => {
      const r = await request('POST', fullTarget, '{}');
      return { status: r.error || ('http ' + r.status), got: r };
    });
    // evaluate gate shape
    if (p1 && p1.got && looksLikeData(p1.got) && !isPaymentGated(p1.got)) {
      probes.push({ name: 'FLAG gate-open?', status: 'FLAG',
        note: 'the path answered 200 with body content to a no-payment POST. ' +
              'If this path is supposed to be paid, the gate is missing or elsewhere. ' +
              'If it is NOT a paid path, target your paid endpoint instead.' });
    } else if (p1 && p1.got && isPaymentGated(p1.got)) {
      const terms = p1.got.body.match(/"(amount|price|accepts)"\s*:\s*[^,}\]]+/gi) || [];
      probes.push({ name: 'gate shape', status: 'OK',
        note: 'no-payment POST refused with a payment-requirement response' +
              (terms.length ? ' advertising terms: ' + terms.slice(0, 3).join(' · ') : ' (no advertised terms found in body — consider publishing price/asset/pay_to so machine buyers can act)') });
    }
    if (p2 && p2.got && p1 && p1.got && p2.got.status !== p1.got.status) {
      probes.push({ name: 'FLAG inconsistency', status: 'FLAG',
        note: 'two identical no-payment POSTs got different status codes (' +
              p1.got.status + ' then ' + p2.got.status + '); a machine buyer cannot predict this endpoint' });
    }
    gateBodies = [p1, p2, g1].filter(x => x && x.got && x.got.body).map(x => x.got.body);
  }

  // P5: receiver-can-collect — OPT-IN (--check-receiver). One free, read-only
  // RPC call, no payment. Answers the question no gate-shape probe can: could a
  // payment to this endpoint actually LAND? Runs outside the target-request
  // budget (it calls the chain, not the target).
  let chainRead = false;
  if (CHECK_RECEIVER) {
    let acc = null;
    for (const b of gateBodies) { const a = solanaTokenAccepts(b); if (a.length) { acc = a[0]; break; } }
    if (!acc) {
      probes.push({ name: 'receiver check', status: 'info',
        note: 'no Solana token accept (payTo + mint) in the advertised terms — not applicable to this endpoint' });
    } else if (acc.payTo === ZERO_ADDR) {
      probes.push({ name: 'FLAG receiver payTo is the zero address', status: 'FLAG',
        note: 'the advertised ' + acc.network + ' payTo is the all-zero address — the 402 is valid and payments ' +
              'settle into a burn; funds sent there are destroyed, not received (x402-trust failure mode 3)' });
    } else {
      chainRead = true;
      const r = await rpcTokenAccounts(acc.payTo, acc.mint);
      if (r.error) {
        probes.push({ name: 'receiver check', status: 'info',
          note: 'chain read for payTo ' + acc.payTo + ' failed (' + r.error + ') — INCONCLUSIVE, not a clean bill' });
      } else if (r.count === 0) {
        probes.push({ name: 'FLAG receiver cannot collect', status: 'FLAG',
          note: 'the advertised payTo ' + acc.payTo + ' has NO token account for mint ' + acc.mint + ' — a payment ' +
                'would fail in simulation and never reach the seller (x402-trust failure mode 1). Create the token ' +
                'account before advertising this endpoint.' });
      } else {
        probes.push({ name: 'receiver can collect', status: 'OK',
          note: 'payTo ' + acc.payTo + ' holds ' + r.count + ' token account(s) for ' + acc.mint + ' — a transfer can land' });
      }
    }
  }

  // P3: junk-path error hygiene + leak scan on the SAME origin.
  const j = await probe('junk GET (error hygiene)', async () => {
    const r = await request('GET', origin + '/__selfscan_probe_nonexistent__.txt');
    return { status: r.error || ('http ' + r.status), got: r };
  });
  if (j && j.got) {
    if (j.got.status >= 500) {
      probes.push({ name: 'FLAG 5xx on junk path', status: 'FLAG',
        note: 'a nonexistent path answered ' + j.got.status + ' — 4xx is the honest shape; 5xx invites error-detail leaks' });
    }
    const leaks = scanLeaks(j.got.body || '');
    const leaksMain = scanLeaks((g1 && g1.got && g1.got.body) || '');
    const all = [...new Set([...leaks, ...leaksMain])];
    if (all.length) {
      probes.push({ name: 'FLAG private-address literals', status: 'FLAG',
        note: 'response bodies contain private-range address literals: ' +
              all.join(', ') + ' — strip internal addresses from published error text' });
    }
  }

  // P4: throttle behavior probe — two quick requests after the paced set.
  // Inconclusive by design: the absence of a 429 is not proof of no limiter.
  await sleep(PACE > 0 ? PACE : 200);
  const t1 = await probe('throttle probe a/b', async () => {
    const a = await request('GET', fullTarget);
    await sleep(150);
    const b = await request('GET', fullTarget);
    const saw429 = (a && a.status === 429) || (b && b.status === 429);
    const retryHeader = (a && /retry/i.test(JSON.stringify(a))) || false;
    return { status: saw429 ? 'limiter fired (inconclusive about payload — normal)'
                            : 'no throttle observed in this window (INCONCLUSIVE — not proof a limiter exists)',
             retryHeader };
  });

  // Nothing was ever actually OBSERVED (all probes errored): that is not a
  // clean bill, it is an inability to test. Report it separately (wake-165
  // doctrine: never let "could not observe" masquerade as a verdict).
  const observed = probes.filter(p => /^http \d/.test(p.status)).length;
  if (!observed) {
    out('RESULT: COULD NOT RUN — no probe produced an HTTP response ' +
        '(unreachable or bad target); no statement about the endpoint is possible.');
    for (const p of probes) out('  [info] ' + p.name + ' — ' + p.status + (p.note ? ' — ' + p.note : ''));
    process.exit(2);
  }
  const flags = probes.filter(p => p.status === 'FLAG');
  const inconclusive = probes.filter(p => /INCONCLUSIVE|inconclusive|SKIPPED/.test(p.status));
  const verdict = flags.length ? 'FAIL (flags need a human look)'
    : inconclusive.length ? 'PARTIAL (shape-level preview; some layers inconclusive)'
    : 'PREVIEW CLEAN at shape level';

  if (AS_JSON) {
    out(JSON.stringify({
      tool: 'agent-selfscan-preview v0',
      target: fullTarget, pace_ms: PACE, requests: reqs,
      verdict,
      probes: probes.map(p => ({ name: p.name, status: p.status, note: p.note })),
      preview_only: true,
      receiver_checked: chainRead,
      paid_report: 'full battery incl. one real settlement + replay + chain verify — order 5 USDC via /ask.html',
    }, null, 1));
  } else {
    out('agent-selfscan-preview v0 — target ' + fullTarget + (PACE ? ' (paced ' + PACE + 'ms)' : ' (NO pacing — degraded)'));
    out('');
    for (const p of probes) {
      out('  [' + (p.status === 'FLAG' ? 'FLAG' : p.status === 'OK' ? 'ok  ' : 'info') + '] ' + p.name +
          (p.note ? ' — ' + p.note : ''));
    }
    out('');
    out('RESULT: ' + verdict);
    out(chainRead
      ? 'This is a PREVIEW: no payment was sent and nothing settled. One free read-only chain read was made (receiver check).'
      : 'This is a PREVIEW: no payment was sent, nothing settled, no chain read done.');
    out('The full conformance report (one real settlement + replay, signed + published)');
    out('is 5 USDC via /ask.html at cassandra.tail6bec7a.ts.net. Run only against');
    out('endpoints you own or are authorized to test.');
  }
  process.exit(flags.length ? 1 : 0);
}

main().catch(e => die('unexpected: ' + (e && e.message)));
