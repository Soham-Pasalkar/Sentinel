# C-02b spike: LangChain `create_agent`, async-native tools, `Command` tools

**Throwaway experiment code. Not part of the Sentinel package, not product code, and implements no real security.** The "gate" and "proxy" are toy stand-ins. See `docs/aidlc/02-construction/spike_langchain_compatibility.md` for the report.

## Contents

| File | Purpose |
|---|---|
| `standin_c.py` | Test tools (sync, async-native, `Command`), proxy state machine (plus a deliberately racy control), the Design B adapter prototype, fake chat model, coverage inspection |
| `run_c02b.py` | Experiments A (create_agent), B (async-native), C (`Command`), D (invariants and retries) |
| `requirements-freeze.txt` | Exact versions the results were produced with |
| `results/` | `results_c02b.json` (structured, includes the retry matrix) and `transcript_c02b.txt` (raw console output) |

`standin_c.py` imports the C-02 stand-ins from the sibling directory `spikes/langgraph_interception/`, which must be present.

## Reproduce

The virtual environment was disposable and has been removed. Recreate it (from the repository root):

```bash
/opt/homebrew/bin/python3.11 -m venv spikes/langchain_compatibility/.venv   # any Python >= 3.11
spikes/langchain_compatibility/.venv/bin/python -m pip install -r spikes/langchain_compatibility/requirements-freeze.txt
cd spikes/langchain_compatibility
.venv/bin/python run_c02b.py
```

The runner prints PASS/FAIL per check and exits 1 if a required check fails. No network access, API keys or LLM are needed at run time (only for `pip install`). Do not install this environment into the project's `.venv`.

`spikes/` is excluded from the project's routine linting through `extend-exclude` in `pyproject.toml` (decision D-28, approved 2026-10-28). The earlier file-wide `# ruff: noqa` headers were removed; nothing else in the code changed.
