# Sentinel

> **Status: pre-alpha scaffold. Sentinel does not implement any security functionality yet, and it does not protect tool calls.** Do not rely on it for security.

Sentinel is planned as a runtime security library for AI agent systems. It is meant to sit between agents and the tools they invoke, and to decide, for each tool call, whether that call may execute. A tool call that Sentinel denies, or that requires approval, must never execute, and every decision is to be recorded in an audit log.

At this stage the repository holds only the package scaffold, development tooling and the design documents.

## Current status

| Component | Status |
|---|---|
| Package scaffold, tests, lint, CI (increment C-01) | implemented |
| Core models and contracts | implemented (internal, not exported): action record and digest (C-03a), models and exceptions (C-03) |
| Request validation (gateway) | not started |
| Identity and capability grants | not started |
| Filesystem path authorization | path guard implemented (internal, not exported; C-04): canonicalisation, containment, prefix registration, re-verification. Not yet used by any gateway, policy or proxy, so it enforces nothing yet |
| Policy engine | not started |
| Tool registry and execution proxy | not started |
| Audit log | not started |
| Pipeline and public client API | not started |
| Threat detection (heuristic) | not started |
| Output filtering | not started |
| Framework integrations (LangGraph, LangChain) | not started; feasibility experiments done (C-02, C-02b), adapter design approved (D-12) |

The only public attribute today is `sentinel.__version__`.

## Planned design (not implemented)

The planned v1 is an in-process pipeline (synchronous core, plus a narrow async entry for async-native tools):

**request validation → agent identity and grants → heuristic detection → deterministic policy decision → controlled tool execution → output filtering**

Each step is audited. The contracts, their limits, and the decisions behind them are in [`docs/aidlc/01-inception/decision_record.md`](docs/aidlc/01-inception/decision_record.md), the canonical decision register. The construction sequence is in [`docs/aidlc/01-inception/implementation_plan.md`](docs/aidlc/01-inception/implementation_plan.md).

## Known limitations (of the planned design)

Even when implemented, Sentinel will be an in-process Python library. In particular:

- It can only constrain tool calls that are routed through it. Code in the same process can bypass it.
- Prompt-injection and sensitive-data detection will be heuristic. They reduce risk; they do not prevent prompt injection.
- Path checks will authorize path arguments. They are not filesystem isolation or a sandbox: a symlink swapped after the final check, and hard links, are not detected.
- Path-constrained tools are supported on Linux and macOS only; registering one on Windows is refused.

The full list is in the decision register.

## Requirements

- Python 3.11 or newer. CI is configured to test 3.11, 3.12 and 3.13 on Linux (`ubuntu-latest`) and macOS (`macos-latest`); it has not yet run on GitHub.

## Local development setup

Create a project-local virtual environment and install the package in editable mode with the development tools (pytest, Ruff):

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]" -c constraints-dev.txt
```

`constraints-dev.txt` pins the exact development-tool versions used to verify the scaffold, so local and CI runs use the same versions.

## Running tests and linting

```bash
pytest                     # tests
ruff check .               # lint
ruff format --check .      # formatting check (use `ruff format .` to apply)
```

The same commands are configured to run in GitHub Actions (`.github/workflows/ci.yml`) on every push to `main` and on every pull request. The workflow has not yet run remotely, so it is unverified.

## Package name

The distribution name `sentinel-ai` and import name `sentinel` are **provisional** (decision D-02). Their availability on PyPI has not been checked. The package carries the `Private :: Do Not Upload` classifier to prevent accidental publication.

## License

No license has been chosen yet.
