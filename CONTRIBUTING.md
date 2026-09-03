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

The development extra includes the supported OpenAI Agents SDK range and
Uvicorn because strict type checking covers the optional adapter and the real
CortexOps process fixture. They remain outside the core runtime dependencies.

## Quality checks

Run all checks before opening a pull request:

```bash
python -m pytest -m "not cortexops_integration and not cortexops_process_integration"
ruff check src tests examples
ruff format --check src tests examples
mypy
python -m build
```

That is the standalone-checkout suite. The full local suite expects a real
CortexOps checkout at the lowercase sibling path `../cortexops`. Only
`CORTEXOPS_REPOSITORY` can override that path. The compatibility, process, and
Hermes E2E tests fail with a checkout diagnostic if it is absent or invalid:

```bash
CORTEXOPS_REPOSITORY=../cortexops pytest -q
```

CI uses a separate combined-workspace job to check out and install CortexOps.
Its absence never prevents collection of the standalone suite. The private
cross-repository checkout uses the `CORTEXOPS_REPOSITORY_TOKEN` repository
secret, whose token must have read-only Contents access to
`getcortexops/CortexOps`.

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
