"""QRadar MCP tool server (W0.41): read-only offense lookups."""

import sys
from pathlib import Path

# Spawned as ``python3 core/integrations/qradar/tool.py`` with a narrowed env:
# put the repo root on sys.path so the ``core.*`` imports resolve.
_REPO_ROOT = str(Path(__file__).resolve().parents[3])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import asyncio
import json
import logging

import mcp.server.stdio
import mcp.types as types
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions

from core.integrations._base.tool_result import run_tool
from core.integrations.qradar.client import QRadarError
from core.integrations.qradar.ingestion import (
    build_client,
    qradar_config,
    transform_offense,
)

logger = logging.getLogger(__name__)

MAX_RESULTS = 200


def result(data):
    return [
        types.TextContent(type="text", text=json.dumps(data, indent=2, default=str))
    ]


async def handle_list_tools():
    return [
        types.Tool(
            name="qradar_list_offenses",
            description="List the newest QRadar offenses (optionally filtered, e.g. status = 'OPEN')",
            inputSchema={
                "type": "object",
                "properties": {
                    "max_results": {"type": "integer", "default": 25},
                    "filter": {
                        "type": "string",
                        "description": "QRadar offense filter, e.g. \"status = 'OPEN' and magnitude > 5\"",
                    },
                },
            },
        ),
        types.Tool(
            name="qradar_get_offense",
            description="Get one QRadar offense by id",
            inputSchema={
                "type": "object",
                "properties": {"offense_id": {"type": "integer"}},
                "required": ["offense_id"],
            },
        ),
    ]


async def handle_call_tool(name: str, arguments: dict | None):
    args = arguments or {}
    client = build_client(qradar_config())
    if client is None:
        return result({"error": "QRadar is not configured"})
    try:
        if name == "qradar_list_offenses":
            limit = max(1, min(int(args.get("max_results") or 25), MAX_RESULTS))
            offenses = await client.recent_offenses(limit, args.get("filter"))
            return result(
                {
                    "offenses": [transform_offense(o) for o in offenses],
                    "count": len(offenses),
                }
            )
        if name == "qradar_get_offense":
            offense = await client.offense(int(args["offense_id"]))
            return result({"offense": transform_offense(offense)})
        return result({"error": f"unknown tool {name}"})
    except (QRadarError, ValueError, KeyError) as e:
        return result({"error": str(e)})
    finally:
        await client.close()


async def _on_list_tools(_ctx, _params):
    return types.ListToolsResult(tools=await handle_list_tools())


async def _on_call_tool(_ctx, params):
    return await run_tool(handle_call_tool, params)


server = Server("qradar", on_list_tools=_on_list_tools, on_call_tool=_on_call_tool)


async def main():
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(
            read,
            write,
            InitializationOptions(
                server_name="qradar",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())
