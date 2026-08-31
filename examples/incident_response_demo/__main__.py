"""Command-line entry point for the incident-response demo."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from .sdk_validation import validate_cortexops_jsonl
from .workflow import DEFAULT_EVENT_PATH, run_incident_response_demo


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=Path, default=DEFAULT_EVENT_PATH)
    args = parser.parse_args()

    result = asyncio.run(run_incident_response_demo(args.events))
    validation = validate_cortexops_jsonl(result.event_path)
    print(
        f"initial={result.initial_diagnosis.status.value} "
        f"blocked={result.blocked_recovery.status.value} "
        f"recovery={result.confirmed_recovery.status.value} "
        f"final={result.final_diagnosis.status.value} "
        f"events={validation.adapter_parsed} path={result.event_path}"
    )


if __name__ == "__main__":
    main()
