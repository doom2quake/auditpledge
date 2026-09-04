# AuditPledge: provenance and priced risk for the MCP tools that Compound-facing agents call

**Grant program:** Compound Grants Program (CGP), Security Tooling domain
**Applicant:** doom2quake (builder collective)
**Requested track:** Security Tools (milestone-funded, non-dilutive)
**Applied through:** Questbook (`compoundgrants.questbook.app`)
**New project repo:** `github.com/doom2quake/auditpledge`
**Lead author (papers/citations):** Dipankar Sarkar
**Status of this document:** draft grant application, testnet and seeded scope, no mainnet deployment

---

## 0. Grant verification (read this first)

Two items require an operator decision and human action before applying:

1. **Verify the current application window is open.** Governance proposal 326 (CGP Renewal)
   executed in September 2024 for a 12-month program with a named Security Tooling allocation,
   and the public Questbook portal (`compoundgrants.questbook.app`) lists prior seasons. We
   could not confirm on an official page that a fresh intake is open right now; one source
   indicated a cycle closed new proposals on 31 May. **An operator must confirm the live RFP
   and deadline on the official portal before submitting.** This is the single gating check.
2. **KYC and a payout wallet.** Milestone disbursement is on-chain via multisig, which will
   require an operator-controlled wallet address and likely KYC to the domain allocator. A
   human must complete this; the agent cannot.

We claim no audits, partnerships, or endorsements from Compound, Compound Governance, the
Compound Grants Program, or Questbook. This is a grant application, not a relationship we are
asserting.

## 1. The problem

DeFi is being wired up to AI agents. A growing number of Compound-facing tools, position
managers, liquidation bots, rebalancers, treasury assistants, now run as agents that call
external tools over the Model Context Protocol (MCP). An MCP agent that manages a Compound
position is only as trustworthy as the weakest tool in its toolbelt. One unsigned,
remote-code-capable, over-scoped tool in that toolbelt can read a signing key, rewrite a
transaction before it is broadcast, or exfiltrate a seed phrase, and the agent's operator has
no standard way to see it coming.

The concrete failure is this: today an operator wiring an agent to Compound has no way to
answer "which of the tools my agent can call are dangerous, and how dangerous, in money." They
read a list of tool names, trust the publisher on faith, and find out something was wrong after
funds move. There is no provenance check on the tool supply chain, no severity ranking, and no
dollar figure a risk owner or an insurer could act on. Software supply-chain attacks
(typosquatted packages, compromised maintainers, lookalike publishers) are already the dominant
way real systems get breached; the MCP tool layer imports every one of those failure modes and
adds a live wire to a wallet. The people who suffer are the protocol's users, whose deposits
are at risk, and the builders, who ship agent tooling with no way to prove it is safe.

## 2. Why Compound, why now

Compound's Grants Program names **Security Tooling** as a funded domain with a dedicated
allocation, and the program is run milestone-by-milestone through domain-specific RFPs. That is
exactly the shape of this work: a security tool is not a one-shot deliverable, it is an artifact
the ecosystem keeps using, which is what milestone funding is built to support.

The timing is specific to the moment. Agentic tooling for DeFi is arriving now, and MCP has
become the default way agents acquire tools, ahead of any security convention for it. There is a
narrow window to set the norm that a tool a Compound agent calls should carry verifiable
provenance, before an incident sets it the hard way. Compound is a natural home for that norm: it
is a mature lending protocol with real value at stake and an active, security-minded governance
process that already funds analysis and risk tooling. A provenance-and-pricing standard proven
against Compound-facing agents is a public good the whole ecosystem inherits.

This is not a chain-agnostic tool with a Compound label. The deliverable is tuned to the agent
patterns that touch Compound: tools that read Comet market and account state, tools that build
and sign COMP-related transactions, tools that move collateral. The risk model weights capability
against what a Compound position actually exposes, and the reference "known-good" keyring is
seeded from publishers the Compound community can vet.

## 3. Evidence we ship

**Milestone 1 is already built and green.** Most applicants to a grants program arrive with a
plan and no artifact. We arrive with a working, tested engine. The repo exists at
`projects/compound-grants/app` (the standalone repo is `github.com/doom2quake/auditpledge`) and adapts our existing lead build, **ChainProof**
(`github.com/doom2quake/chainproof`), which already does the core of this end to end:

- **A real MCP session, not a mock.** AuditPledge opens a Model Context Protocol stdio session,
  completes the `initialize` handshake, checks the server identity it was handed against the
  server it asked for, reads `tools/list` over JSON-RPC, and refuses to score any tool that will
  not present its provenance. Unknown servers, identity mismatches, and tools without evidence
  **fail closed**: the audit stops rather than reporting a clean manifest.
- **Real cryptography.** Each tool carries a detached Ed25519 signature over the canonical bytes
  of its `name, version, publisher, sorted scopes, sorted ops`, verified against a committed
  public keyring. Only a signature that verifies counts as signed; publishers are matched exactly
  after normalisation, so `attacker.compound-finance` is not `compound-finance`; editing one
  character of a signed tool flips it to unsigned.
- **Risk turned into a number, and a fix into a measured saving.** The scorer produces a per-tool
  severity from provenance, capability (RCE-class ops, network access), scope (wildcards, env
  access), Compound position exposure (tools that build or sign transactions or move collateral),
  and advisory hits. A pricing pass turns that into an expected loss and a suggested premium, and
  a **counterfactual** pass reruns the identical scorer over a mutated manifest (the worst tool
  dropped, or re-signed with a trusted key and its RCE ops and wildcard scopes removed) so the
  saving is measured, not asserted.
- **A UI that cannot lie.** The static offline UI carries no hand-written numbers; every figure is
  captured from a real audit run, and a snapshot test fails if the page ever shows a number the
  auditor did not produce.

**Test evidence, reproduced on this checkout.** The deterministic core, provenance, scoring,
pricing, counterfactual repricing, advisory handling, the real MCP stdio session, and the agent
pipeline ordering, runs with no network and no cloud credentials. `PYTHONPATH=. pytest -q`
reports **75 Python tests passing** (Python 3.10+, the audit store forced in-memory by
`tests/conftest.py`), including a real MCP stdio subprocess test (handshake, `tools/list`,
identity mismatch, missing evidence) and the UI snapshot test. The repo ships a
`docs/HONESTY.md` that draws the line between what is real (the MCP session, the cryptography,
the scoring and pricing, the UI numbers) and what is synthetic and labelled as such (the demo
catalogue, the offline advisory snapshot, the demo publisher keys).

The independent review pass: before submission we run our code-review and security-review
harness over the diff and record the findings and their resolution in the repo, so a reviewer can
see the tool was itself audited.

## 4. Milestone roadmap

All Web3 interaction is **testnet and seeded only** for the grant period. Every milestone names a
deliverable, how a reviewer verifies it, and what it unlocks.

**Milestone 1, fork and Compound-tune the engine (weeks 1-4). BUILT.**
Deliverable: this repo, ChainProof re-themed and re-scoped for Compound-facing agents, with a
Compound-oriented demo catalogue (state-reader, transaction-builder, collateral-mover tools)
served over a real MCP session, and a risk model weighted for Compound position exposure.
Verify: clone the repo, run the test suite offline and see **75 tests pass**; run
`auditpledge audit --source mcp --no-llm` and see a Compound-tuned audit with provenance checks,
severities, and a priced report. **Status: complete and green.**
Unlocks: a concrete, runnable baseline the domain allocator can inspect before funding further work.

**Milestone 2, provenance evidence spec and a signing kit for Compound tool publishers (weeks 5-9).**
Deliverable: a documented, versioned schema for publishing Ed25519 provenance evidence in an MCP
tool's `_meta` field, plus a small open-source CLI that a tool author uses to sign their manifest,
and a public reference keyring format the Compound community can populate.
Verify: sign a sample third-party tool with the kit, point AuditPledge at it, and watch it move
from "fails closed, refusing to score as clean" to a verified, scored result; tests pin the
signing-and-verifying round trip.
Unlocks: the piece that lets AuditPledge audit real tools, not only our own demo catalogue. This
is the durable standard the ecosystem keeps.

**Milestone 3, live advisory feed and a testnet reference deployment (weeks 10-14).**
Deliverable: the OSV.dev advisory client exercised live (implemented today, not yet run in CI),
plus a hosted, offline-capable report viewer and a documented run against a Compound-facing agent
wired to a **testnet** deployment, no mainnet, no real funds.
Verify: run `auditpledge audit --advisories osv` and see live advisory lookups with source and
retrieval time; open the published report and confirm every number traces to a run.
Unlocks: a tool that reflects real, current vulnerability data rather than a bundled snapshot.

**Milestone 4, documentation, hand-off, and adoption (weeks 15-18).**
Deliverable: a builder's guide for Compound agent developers, the paper and demo walkthrough
updated, and outreach to Compound tool authors to publish provenance evidence.
Verify: the guide is in the repo; a developer can follow it to sign a tool and audit an agent
unaided.
Unlocks: adoption beyond us.

**After the grant.** The signing kit, the evidence schema, and the auditor are MIT-licensed and
self-maintaining; the code runs offline with no service to keep alive. We intend to keep the
advisory client and MCP version pins current, and to propose the provenance-evidence schema to the
wider MCP tooling community so it outlives any single grant.

## 5. Ecosystem impact

Everything is open-sourced under MIT, owned by doom2quake. Reusable outputs:

- **A provenance-evidence schema for MCP tools**, documented and versioned, that any project (not
  only Compound) can adopt so agent tools carry verifiable origin.
- **A publisher signing kit**, a small CLI other builders use to sign their own tool manifests,
  lowering the cost of doing the right thing.
- **The auditor and pricer themselves**, so any Compound builder can point them at their agent's
  toolbelt and get a provenance report and a risk number offline.
- **The honesty-and-review discipline**: a `docs/HONESTY.md` that states what is real versus
  synthetic, and a recorded independent review pass, which other grantees can copy as a template
  for credible security claims.

## 6. Sustainability and honest limits

**What keeps it alive:** the deliverables are static, offline-capable, MIT code with no server or
subscription to fund. The maintenance surface is small: the advisory client endpoint and the MCP
version pin. The standard survives on adoption, not on our continued spending, which is why
Milestones 2 and 4 are about a schema and a signing kit other people can run.

**What is NOT built, deployed, or measured, stated plainly:**

- **We have no users, no mainnet deployment, and no revenue.** Nothing is on Compound mainnet; all
  Web3 interaction in this grant is testnet and seeded only.
- **No third-party MCP server has been audited by us.** Today AuditPledge demonstrates both ends
  against our own demo catalogue; a real third-party tool does not yet publish provenance
  evidence, which is precisely what Milestone 2 delivers. Against such a tool the auditor fails
  closed rather than inventing a verdict.
- **The pricing inputs are illustrative priors, not an actuarial model.** The per-severity
  compromise probabilities, the unsigned-RCE floor, the breach-loss figure, and the risk load are
  defensible starting points, configurable at runtime, not a calibrated model. What we demonstrate
  is the mechanism: a manifest becomes a reproducible number and a fix changes it by a measured
  amount.
- **The advisory feed is a bundled simulated snapshot in the demo.** The live OSV.dev client is
  implemented and tested offline against a recorded response; exercising it live is Milestone 3.
- **The LLM narrative layer needs cloud credentials.** The deterministic audit, which is the whole
  security and pricing claim, runs fully without it.
- **We claim no audits, partnerships, or endorsements** from Compound or anyone else. This is a
  grant application, not a relationship we are asserting.

## 7. Funding terms

CGP is a **non-dilutive grant**: we keep the IP and the MIT licence, and there is no equity or
token/SAFE component in the program as we understand it. Grants are milestone-funded and disbursed
through a multisig against domain RFPs. The two operator gates (confirm the live window; complete
KYC and a payout wallet) are recorded in Section 0.

---

## Cite

```bibtex
@software{sarkar_auditpledge_2026,
  title   = {AuditPledge: Provenance and Priced Risk for the MCP Tools a Compound Agent Calls},
  author  = {Dipankar Sarkar},
  year    = {2026},
  url     = {https://github.com/doom2quake/auditpledge},
  license = {MIT}
}
```
