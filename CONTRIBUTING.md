# Contributing to Runmantle

Thank you for helping improve Runmantle. The project is an early developer
preview, so small, well-tested changes and explicit interface discussions are
especially useful.

## Project boundaries

Contributions must keep Runmantle:

- MIT-licensed and independently deployable;
- separate from proprietary CortexOps Control Plane code;
- provider-neutral in its core execution and verification layers;
- explicit about task contracts, evidence, verification, and capabilities;
- safe by default: agent suggestions never authorize recovery;
- honest about evidence limitations and unimplemented integrations.

Do not add undocumented CortexOps APIs, credentials, endpoints, or package
assumptions. Do not copy implementation code from other agent frameworks.

## Development setup

Use Python 3.11 or newer:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

On Windows, activate the environment with `.venv\Scripts\activate`.

## Quality checks

Run all checks before opening a pull request:

```bash
python -m pytest -m "not cortexops_integration"
ruff check src tests examples
ruff format --check src tests examples
mypy
python -m build
```

That is the standalone-checkout suite. Real CortexOps tests are explicitly
marked and require its actual sibling repository:

```bash
CORTEXOPS_REPOSITORY=../CortexOps python -m pytest -m cortexops_integration
RUNMANTLE_CORTEXOPS_PROCESS_TEST=1 CORTEXOPS_REPOSITORY=../CortexOps \
  python -m pytest tests/test_cortexops_process_integration.py
```

CI uses a separate combined-workspace job to check out and install CortexOps.
Its absence never prevents collection of the standalone suite.

Run the packaged demo after installation:

```bash
runmantle demo --json
```

The GitHub Actions workflow builds a wheel, installs it into a clean virtual
environment outside the source tree, imports the package, and runs the CLI.

## Change guidelines

- Preserve `agent_reported_complete != verified` in models, runtime behavior,
  telemetry, examples, and documentation.
- Add deterministic tests for new behavior. Tests must not depend on LLMs,
  shells, deployments, files outside temporary directories, or external APIs.
- Prefer small protocols, immutable models, modern typing, and dependency
  injection.
- Keep optional integrations behind structural interfaces and optional
  dependencies.
- Update `README.md`, `docs/api.md`, and `CHANGELOG.md` when public behavior
  changes.

## Pull requests

Describe the problem, the contract or invariant affected, tests added, and any
compatibility implications. Keep unrelated changes separate. A passing test
suite demonstrates the covered behavior; it does not by itself establish broad
production readiness.
