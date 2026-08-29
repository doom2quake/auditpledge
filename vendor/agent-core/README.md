# agent-core

The shared control plane for agent products built on
[Google ADK](https://google.github.io/adk-docs/): named skills, a supervisor
assembler, guardrails, a domain-aware action router, durable run state, and MCP
helpers. Every agent app in this monorepo vendors it, so a defect here is a
defect everywhere and it is held to that standard.

```
skills      capabilities as named units; assemble a supervisor from them
guardrails  read-only-SQL screen, content-safety screen, action rate limiter
config      env-driven settings base (subclass per app)
sinks       guarded outbound actions (Slack alert, GitHub / endpoint ticket)
router      domain-aware "send the outcome to the right place" router
state       durable run memory (Firestore + in-memory) with recurrence detection
runner      run an ADK agent graph and collect per-stage output
mcp         serve / consume tools over the Model Context Protocol
demo        `python -m agent_core.demo`, one end-to-end run of all of the above
```

## Why

The gap between a demo agent and something you would let touch production is
almost entirely guardrails, memory, routing, and an honest report of what it did.
That is the part every build re-implements, so it lives here once, tested.

## Run the demo

```bash
pip install -e packages/agent-core
python -m agent_core.demo                 # add --json run.json to keep the run document
```

It opens a run, pushes four SQL statements and two blocks of model text through
the guardrails, routes two incidents, and prints the run document that the run
actually wrote. Every line states its delivery mode. With no sink configured it
prints `SYNTHETIC` and no artifact URL, because nothing was delivered. Configure
a sink and the identical code path prints `LIVE` with the id the destination
returned.

## Wire it up

```python
from agent_core import (
    BaseSettings, Skill, build_supervisor,
    ActionLimiter, ActionPolicy, Notifier,
    Router, AlertHandler, TicketHandler,
    StateStore, run_agent,
)

settings = BaseSettings(env_prefix="MYAPP")
limiter  = ActionLimiter(ActionPolicy.from_env("MYAPP"))
store    = StateStore.create(settings)
notifier = Notifier(settings, limiter,
                    recorder=lambda n, o, d: store.record_guardrail(rid, n, o, d))
router   = Router([AlertHandler(notifier), TicketHandler(notifier)], env_prefix="MYAPP")

watch = Skill(name="watch", summary="Detect anomalies.", model=settings.model_fast,
              instruction="You are the Watcher...", tools=[detect_anomaly],
              output_key="watch_report")
root = build_supervisor(name="myapp_supervisor",
                        description="Coordinates the workflow.",
                        instruction="Delegate in order: watch -> act.",
                        skills=[watch, ...])

result  = await run_agent(root, "Run today's cycle.", app_name="myapp")
routing = router.route({"summary": result.final_text, "title": "Incident"})
```

## What the guardrails do, exactly

- **Action bounds.** `ActionLimiter` caps actions per cycle and per hour,
  process-wide; `AGENT_DRY_RUN=on` suppresses every outbound action. Per-cycle
  counters expire after an hour and the table is hard-capped, so a long-lived
  process that mints a run id per cycle does not leak memory.
- **No blind execution of model output.** `screen_content` blocks prompt-
  injection and escalation patterns before the caller acts on the text.
- **Read-only SQL screen.** `assert_read_only` accepts one comment-free
  SELECT/WITH statement within a byte cap, and rejects write/DDL tokens,
  `INTO`, file export (`OUTFILE`/`DUMPFILE`), filesystem functions
  (`pg_read_file`, `load_file`), session/admin functions
  (`pg_terminate_backend`, `xp_cmdshell`), remote fetches (`dblink`,
  `EXTERNAL_QUERY`), sleeps and row locks. Comments are stripped before the
  token scan so `-- ` and `/* */` cannot smuggle a keyword past it, and a MySQL
  `/*! ... */` versioned comment is an outright rejection because it executes.
- **A full audit trail.** Every guardrail decision, action, and routing outcome
  is appended to the run document in state.

## Honest limitations

These are the places where the code is deliberately narrower than the words
around it usually are. Read them before you rely on it.

- **`assert_read_only` is a text screen, not a SQL parser.** It is a deny list
  over the statement text. A dialect it does not know, or a function name it has
  not been told about, can get past it. It is defence in depth and it is not the
  only line of defence: run generated SQL under a credential that holds SELECT
  only, against an allow-listed dataset, with a server-side byte and cost cap.
  What this layer buys you is a cheap, fail-closed pre-check with a recorded
  decision.
- **A sink with no backend configured delivers nothing, and says so.** The stub
  path returns `status="logged"`, `synthetic=True`, `url=None` and a reason
  naming the env vars that would make it real. It does not invent a ticket URL.
  The router refuses to put anything into `artifacts` unless a real destination
  returned it, and reports `delivery_mode: "synthetic"` for the whole route. The
  Slack, GitHub and generic-endpoint paths are real HTTP calls. The
  generic-endpoint path is tested against a loopback server (including the
  "backend returned no id" and "backend returned 500" cases); the Slack and
  GitHub paths need real credentials and have not been executed in CI.
- **State durability is checked, not assumed.** `StateStore.create` performs a
  real bounded Firestore read before claiming the backend. If it fails, the store
  falls back to process memory and marks itself `degraded` with the reason;
  `readiness()` exposes that, and `AGENT_REQUIRE_DURABLE_STATE=1` turns the
  fallback into a startup failure instead. In-memory is only silent when the app
  asked for it with `AGENT_IN_MEMORY_STATE=1`.
- **Concurrent writes.** `update`, `set_data` and `append` are atomic: a
  Firestore transaction on the Firestore backend, one lock spanning the whole
  read-modify-write on the in-memory backend. A backend injected from outside
  that does not implement `mutate` is serialised in-process only, which is safe
  within one process and not across several.
- **MCP schema.** `tool_input_schema` reads `parameters_json_schema` (current
  ADK, verified on google-adk 2.7.1) or the legacy genai `parameters` schema, so
  a parameterised tool served over MCP advertises its arguments. The stdio server
  itself is exercised by hand, not in CI.
- **`runner.run_agent` calls a live model** and is therefore not unit-tested
  here; the layers it composes are.

## Testing

```bash
pytest packages/agent-core/tests -q
```

51 tests pass on google-adk 2.7.1 / Python 3.10. They cover the guardrail
screens (including the side-effecting-SELECT and comment-smuggling cases), the
classifier and router (including "a no-op must not look like a delivery" and a
classify-only classifier plugged in by an app), state concurrency with a
deterministic lost-update probe, backend-durability reporting, the skill to ADK
agent mapping, the MCP schema bridge against both ADK declaration shapes, the
ticket-endpoint HTTP path against a loopback server, and the demo itself. No
test reaches an external service; the only socket used is `127.0.0.1`.

Because every app repo vendors this library, five sibling suites that import it
unvendored were run against this version as well: PatentPincer 38 passed,
InterruptBox 29 passed, MemoryMesh 37 passed, QuantForge 36 passed, BoxOffice 35
passed and 4 skipped. BoxOffice is the heaviest `assert_read_only` consumer, so
it is also the check that the tightened SQL screen did not start rejecting real
analytic queries.

The Firestore path was additionally exercised by hand against a live project on
2026-08-23: `python -m agent_core.demo` reported `durable: True`, wrote ten
guardrail decisions through the transactional mutate path, and detected the
recurrence signature across two runs. Reproducing that needs ADC plus
`GOOGLE_CLOUD_PROJECT`; without them the same command reports the degraded
in-memory fallback and the reason.

## Provenance

Extracted from the Atlas build in this monorepo (`projects/devpost-30845`, ADK +
Vertex AI Gemini + BigQuery + Firestore + Cloud Run). App-specific pieces stay in
the app; what is reusable lives here.
