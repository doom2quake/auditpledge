# HONESTY.md

The one-page map of what AuditPledge proves, what is simulated and labelled as such, and
what is not built. Nothing on the README or the demo page contradicts this file. If you read
one thing before trusting a number here, read this.

## What is real

- **A real MCP session.** `--source mcp` opens a Model Context Protocol stdio session against
  `auditpledge.mcp_server`, completes the `initialize` handshake, checks the server identity it
  was handed against the server it asked for, and reads `tools/list` over JSON-RPC. Unknown
  servers, identity mismatches, and unreachable servers all **fail closed**: the audit stops
  rather than reporting a clean manifest. `tests/test_mcp_session.py` exercises this against a
  real subprocess.
- **Real cryptography.** Every tool carries a detached Ed25519 signature over the canonical
  bytes of its `name, version, publisher, sorted scopes, sorted ops`, verified against the
  committed public keyring in `auditpledge/data/keyring.json`. Only a signature that verifies
  counts as signed. Publishers are matched exactly after normalisation, so
  `attacker.compound-finance` is not `compound-finance`. Editing one character of a signed tool
  flips it to unsigned; `tests/test_provenance.py` pins this.
- **Deterministic scoring and pricing.** The severity, the expected loss, and the premium are a
  pure function of the manifest plus the keyring. The counterfactual pass reruns the identical
  scorer over a mutated manifest (worst tool dropped, or re-signed by a trusted publisher with
  RCE/signing ops and wildcard scopes removed), so the dollar saving from a fix is measured,
  not asserted.
- **A UI that cannot lie.** `auditpledge/ui/index.html` carries no hand-written numbers. Every
  figure is captured from one real audit run and pasted between snapshot markers, and
  `tests/test_ui_snapshot.py` re-runs the audit and fails if any value drifts.

## What is simulated, and labelled as such

- **The demo tool catalogue.** The Compound-facing tools in `auditpledge/catalogue.py`
  (`comet-state-reader`, `collateral-mover`, `tx-builder`, and the rest) do not exist. They are
  synthetic manifests for the demo, labelled `synthetic: true` everywhere they surface. They are
  read the same way a real third-party MCP server would be read: over a real stdio session, via
  `tools/list`.
- **The offline advisory snapshot.** `auditpledge/advisories.py` ships a hand-written snapshot
  describing invented tools, so every entry is `simulated=True`, printed as `[SIMULATED]`, and
  can be excluded from scoring (`--advisories osv`, or `AP_ALLOW_SIMULATED_ADVISORIES=false`).
  The live OSV.dev client is implemented and its parser is tested offline against a recorded
  response; exercising it live needs outbound HTTPS.
- **The demo publisher keys.** `auditpledge/demo_keys.py` holds the *private* halves for the
  demo publishers, on purpose, so the offline catalogue carries genuine signatures a reviewer
  can break by editing one character. In production a publisher signs with a key AuditPledge
  never sees; the verifier never imports the signing module, so the trust path depends on
  committed public keys alone.

## What is NOT built, deployed, or measured

- **No users, no mainnet deployment, no revenue.** Nothing is on Compound mainnet; all Web3
  interaction in this grant is testnet and seeded only.
- **No third-party MCP server has been audited by us.** Today AuditPledge demonstrates both ends
  against its own demo catalogue. A real third-party tool does not yet publish provenance
  evidence, which is exactly what the milestone roadmap delivers. Against such a tool the auditor
  fails closed rather than inventing a verdict.
- **The pricing inputs are illustrative priors, not an actuarial model.** The per-severity
  compromise probabilities, the unsigned-RCE floor, the breach-loss figure, and the risk load
  are defensible starting points, configurable at runtime, not a calibrated model. What is
  demonstrated is the mechanism: a manifest becomes a reproducible number, and a fix changes it
  by a measured amount.
- **The LLM narrative layer needs cloud credentials.** The deterministic audit, which is the
  whole security and pricing claim, runs fully without it.
- **No audit, partnership, or endorsement.** No third-party security review has been performed on
  this code. This is a grant application, not a relationship with Compound, Compound Governance,
  the Compound Grants Program, or Questbook.
