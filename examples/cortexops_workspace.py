"""Locate the real sibling CortexOps workspace for compatibility checks."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def configure_cortexops_workspace() -> Path:
    """Add the checked-out CortexOps SDK and parser packages to ``sys.path``."""

    configured = os.environ.get("CORTEXOPS_REPOSITORY")
    candidates = [Path(configured)] if configured else []
    for ancestor in Path(__file__).resolve().parents:
        candidates.extend((ancestor / "cortexops", ancestor / "CortexOps"))
    for candidate in candidates:
        root = candidate.resolve()
        sdk = root / "packages" / "python-sdk"
        parser = root / "cortexops" / "adapters" / "cortexops_sdk" / "parser.py"
        if sdk.is_dir() and parser.is_file():
            for entry in (root, sdk):
                value = str(entry)
                if value not in sys.path:
                    sys.path.insert(0, value)
            return root
    raise RuntimeError(
        "the sibling CortexOps repository was not found; set "
        "CORTEXOPS_REPOSITORY to its root"
    )


def cortexops_workspace_available() -> bool:
    """Return whether the real SDK/parser checkout can be configured locally."""

    try:
        configure_cortexops_workspace()
    except RuntimeError:
        return False
    return True


__all__ = ["configure_cortexops_workspace", "cortexops_workspace_available"]
