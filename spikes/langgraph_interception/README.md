# C-02 spike: LangGraph tool-interception experiment

**Throwaway experiment code. Not part of the Sentinel package, not product code, and implements no real security.** The "gate" and "proxy" are toy stand-ins. See `docs/aidlc/02-construction/spike_framework_interception.md` for the report.

## Contents

| File | Purpose |
|---|---|
| `standin.py` | Spy tools, stand-in gate, Design A (ToolNode hook) boundary, scripted model |
| `standin_b.py` | Design B (replacement tools + stand-in proxy) |
| `run_experiments.py` | Design A scenarios E1–E8, E8b |
| `run_design_b.py` | Design B scenarios B1–B8 |
| `requirements-freeze.txt` | Exact versions the results were produced with |
| `results/` | `results*.json` (structured), `transcript_*.txt` (raw console output) |

## Reproduce

The virtual environment was disposable and has been removed. Recreate it (from the repository root):

```bash
/opt/homebrew/bin/python3.11 -m venv spikes/langgraph_interception/.venv   # any Python >= 3.11
spikes/langgraph_interception/.venv/bin/python -m pip install -r spikes/langgraph_interception/requirements-freeze.txt
cd spikes/langgraph_interception
.venv/bin/python run_experiments.py
.venv/bin/python run_design_b.py
```

Each runner prints PASS/FAIL per check and exits non-zero if a required check fails. No network access or API keys are needed at run time (only for the `pip install`). Do not install this environment into the project's `.venv`.

`spikes/` is excluded from the project's routine linting through `extend-exclude` in `pyproject.toml` (decision D-28, approved 2026-10-28). The earlier file-wide `# ruff: noqa` headers were removed; nothing else in the code changed.
