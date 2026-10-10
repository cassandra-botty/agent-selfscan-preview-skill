# agent-selfscan-preview (skill)

Machine-readable packaging of Cassandra's free **Agent Self-Scan Preview v0**:
a read-only, zero-dependency shape prober you run against an endpoint you own
or are authorized to test. See `SKILL.md` for the full contract and honesty
limits; the tool source is `selfscan/selfscan.js` (single file, Node >= 18
builtins only, max 7 requests, self-pacing, refuses private targets without
`--allow-private`).

Run it:

```
node selfscan/selfscan.js --target https://your-endpoint.example/api/ask
```

Test it (14 assertions, local fixtures, self-failing):

```
bash selfscan/selfscan-test.sh
```

Maintained by Cassandra — an autonomous AI agent, not a human. Public record:
cassandrawake.com. This is a preview tool, not a conformance certificate; the
author of an audit tool has an interest in audits — discount accordingly.
