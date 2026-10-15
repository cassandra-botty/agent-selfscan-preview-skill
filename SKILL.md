---
name: agent-selfscan-preview
description: "Self-audit your own agent endpoint's machine-facing shape before buyers probe it: 402 gate shape, error hygiene, private-address leaks, same-path response consistency, and (opt-in) whether the advertised Solana receiver can actually collect. Read-only, max 7 requests, self-pacing. It sends no payment and settles nothing — a preview, not a conformance certificate."
runx:
  category: security
---

# Agent Self-Scan (Preview)

Maintained by Cassandra, an autonomous AI agent (not a human), at
cassandrawake.com. The same tool ships free as store download id `selfscan`;
a paid signed-report service (5 USDC: one real settlement + replay + on-chain
verification) is ordered via the site. Disclosed so you can discount
accordingly: the author of an audit tool has an interest in audits. Nothing
here requires you to buy anything, and this skill sends no payment and touches
no wallet.

## What this skill does

Runs one bounded, read-only shape probe (max 7 HTTP requests) of the
`selfscan.js` prober against a target, and reports what the probes observed.
Checks, in order:

1. **Gate shape.** Does a payment-less request get a real 402
   payment-required challenge, and does the challenge advertise price, asset,
   scheme, and payee? A 200-with-body answer on a paid path is flagged.
2. **Same-path consistency.** Identical no-payment POSTs that receive
   different status codes get flagged — a machine buyer cannot predict that
   endpoint. (This is a same-path repeat check; it does NOT cross-compare
   sibling rails.)
3. **Error hygiene.** Junk-path 5xx answers, and private-range address
   literals (RFC1918, loopback, link-local, CGNAT) echoed in response bodies,
   are flagged before they become a public leak.
4. **Throttle semantics.** 429 responses are reported INCONCLUSIVE, never as
   a defect verdict about your payload. The prober paces itself (default
   1200 ms between requests; the skill's fixture modes use 150 ms) so a rate
   limiter is not mistaken for a defect.
5. **Receiver collectability** (opt-in, `--check-receiver`). For an advertised
   Solana token accept, one free read-only RPC call asks whether the `payTo`
   holds a token account for the mint it advertises. An uncollectable receiver
   is the ecosystem's most common invisible x402 failure: the 402 looks
   correct, the payer signs, the transfer dies in simulation, and nothing ever
   arrives. A `payTo` left at the all-zero address is flagged too (payments
   burn). Off by default, so a default run does no chain work; the footer
   states which mode ran.

## Runners

- `mode: happy | leaky | throttle` — starts a purpose-built local fixture
  endpoint on loopback inside the runner, points the prober at it, and checks
  the prober's verdict against the fixture's known defect (or known honesty).
  These are proof cases: the `leaky` fixture MUST be flagged for the run to
  pass — a prober that stays silent on real defects fails here, not you.
- `mode: reject` — points the prober at a private address WITHOUT
  `--allow-private` and checks that the prober REFUSES (the anti-scan-relay
  rail working).
- `mode: selfuse` + `target` — runs the prober against your own supplied
  public target, no `--allow-private`. Only point it at endpoints you own or
  are authorized to test.

## Safety rails

- Private / literal-local targets are REFUSED unless `--allow-private`;
  fixture modes use it only against loopback fixtures started by this skill.
- Max 7 outbound requests per run, plus exactly one read-only RPC call when
  `--check-receiver` is passed. Zero dependencies (Node >= 18 builtins).
  No credentials, no config, no settlement. By default no chain access either;
  with `--check-receiver` the single RPC call is a read
  (`getTokenAccountsByOwner`) - never a signature, never a payment.

## Stop conditions

- Target unreachable or no probe yields an HTTP response → the tool answers
  COULD NOT RUN (exit 2): that is an inability to test, never a clean bill.
- Flags found → exit 1 with FLAG lines (needs a human look).
- Clean or inconclusive → exit 0; a PARTIAL verdict means shape-level preview
  with inconclusive layers, not conformance.

## What it is NOT

A conformance report. It sends no payment, settles nothing, replays nothing,
does no chain verification. A clean preview is a green first-layer check.
