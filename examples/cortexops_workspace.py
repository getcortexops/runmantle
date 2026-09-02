"""Locate the real sibling CortexOps workspace for compatibility checks."""

from __future__ import annotations

import os
import sys
from pathlib import Path

RUNMANTLE_REPOSITORY = Path(__file__).resolve().parents[1]
DEFAULT_CORTEXOPS_REPOSITORY = RUNMANTLE_REPOSITORY.parent / "cortexops"


def configure_cortexops_workspace() -> Path:
    """Add the checked-out CortexOps SDK and parser packages to ``sys.path``."""

    configured = os.environ.get("CORTEXOPS_REPOSITORY")
    root = (
        Path(configured).expanduser().resolve()
        if configured
        else DEFAULT_CORTEXOPS_REPOSITORY.resolve()
    )
    sdk = root / "packages" / "python-sdk"
    parser = root / "cortexops" / "adapters" / "cortexops_sdk" / "parser.py"
    if not root.is_dir():
        detail = "directory does not exist"
    elif not (root / ".git").exists():
        detail = "missing .git checkout metadata"
    elif not sdk.is_dir() or not parser.is_file():
        detail = "missing packages/python-sdk or the CortexOps SDK parser"
    else:
        for entry in (root, sdk):
            value = str(entry)
            if value not in sys.path:
                sys.path.insert(0, value)
        return root
    source = "CORTEXOPS_REPOSITORY" if configured else "default sibling ../cortexops"
    raise RuntimeError(
        f"invalid CortexOps checkout from {source}: {root} ({detail}); "
        "set CORTEXOPS_REPOSITORY to a valid CortexOps repository root"
    )


__all__ = ["DEFAULT_CORTEXOPS_REPOSITORY", "configure_cortexops_workspace"]
