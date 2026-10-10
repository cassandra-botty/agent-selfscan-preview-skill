// tools/selfscan/fixtures.js — throwaway mock endpoints for the selfscan
// battery (wake 166). Local-only, no secrets, no real services. Starts three
// servers and waits for kill; the battery reads ports from its own defaults.
//   18901 happy  — x402-honest shape: 402 + advertised terms on the gated
//                  path, clean 404 on junk, no leak.
//   18902 leaky  — a payment-gated path answering 200 WITH data (open gate),
//                  junk path answering 500 with a stack trace that contains a
//                  private-range address literal (10.20.30.40 — a FAKE
//                  example, not any live machine).
//   18903 429all — every request 429 (with retry_after): the throttle-equals-
//                  inconclusive oracle, matching tools/conformance/mock429.js.
'use strict';
const http = require('http');

const TERMS = JSON.stringify({
  error: 'payment_required',
  accepts: [{ scheme: 'exact', network: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',
    asset: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', amount: '5000000',
    payTo: '11111111111111111111111111111111', decimals: 6 }],
});

http.createServer((req, res) => {
  res.writeHead(402, { 'content-type': 'application/json', 'payment-required': Buffer.from(TERMS).toString('base64') });
  res.end(TERMS);
}).listen(18901, '127.0.0.1');

http.createServer((req, res) => {
  if (req.url.includes('__selfscan_probe_nonexistent__')) {
    res.writeHead(500, { 'content-type': 'text/plain' });
    return res.end('Error: connect ECONNREFUSED 10.20.30.40:5432\n    at db.query (/app/db.js:41)\n    at handler (/app/routes.js:12)');
  }
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ answer: 'here is the paid answer with no payment', data: 'x'.repeat(60) }));
}).listen(18902, '127.0.0.1');

http.createServer((req, res) => {
  res.writeHead(429, { 'content-type': 'application/json', 'retry-after': '600' });
  res.end(JSON.stringify({ error: 'rate_limited', retry_after_seconds: 600 }));
}).listen(18903, '127.0.0.1', () => console.log('selfscan fixtures up: 18901 happy / 18902 leaky / 18903 429all'));