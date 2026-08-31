from __future__ import annotations

import argparse
from pathlib import Path

import uvicorn
from cortexops.openclaw_plugin import (  # type: ignore[import-not-found]
    create_openclaw_plugin_router,
)
from cortexops.openclaw_plugin.repository import (  # type: ignore[import-not-found]
    OpenClawPluginRepository,
)
from cortexops.runmantle_control import (  # type: ignore[import-not-found]
    create_runmantle_control_router,
)
from fastapi import FastAPI


def approval_policy() -> dict[str, object]:
    return {
        "defaults": {"tools": "allow", "models": "deny"},
        "tool_rules": [
            {
                "id": "approve-write-file",
                "effect": "approval",
                "reason": "process integration requires operator approval",
                "match": {"tool_name": "write-file"},
            }
        ],
        "model_allowlist": [],
        "budgets": {
            "run": {"max_tokens": None, "max_cost_usd": None},
            "session": {"max_tokens": None, "max_cost_usd": None},
            "agent_daily_utc": {"max_tokens": None, "max_cost_usd": None},
        },
    }


def create_app(database: Path) -> FastAPI:
    OpenClawPluginRepository(database).save_policy(approval_policy())
    app = FastAPI()
    app.include_router(create_openclaw_plugin_router(database))
    app.include_router(create_runmantle_control_router(database))
    return app


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    uvicorn.run(
        create_app(args.database),
        host="127.0.0.1",
        port=args.port,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
