"""
MEDSOC — Splunk MCP Client
Implements the Splunk MCP Server protocol (GA Feb 4, 2026).
Connects MEDSOC agents to Splunk indexes via Model Context Protocol.

Splunk MCP Server docs:
  https://splunk.github.io/splunk-mcp/
  Tool: splunk-mcp (npm package)
"""

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Optional
from datetime import datetime, timedelta

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False

logger = logging.getLogger("medsoc.mcp_client")


@dataclass
class SplunkConfig:
    """Splunk Enterprise / Cloud connection config."""
    host: str = os.getenv("SPLUNK_HOST", "localhost")
    port: int = int(os.getenv("SPLUNK_PORT", "8089"))
    token: str = os.getenv("SPLUNK_TOKEN", "")
    scheme: str = "https"
    verify_ssl: bool = False
    # Clinical IT indexes (FTH Gombe)
    indexes: list[str] = field(default_factory=lambda: [
        "ehr_access",       # Epic EHR access events
        "iomt_devices",     # Medical device network telemetry
        "endpoint",         # Clinical workstation EDR
        "auth_events",      # Active Directory / LDAP
        "network",          # Palo Alto NGFW / DICOM traffic
        "vulnerability",    # Nessus / vulnerability scanner
    ])


@dataclass
class MCPQueryResult:
    """Normalized result from Splunk MCP tool call."""
    success: bool
    events: list[dict]
    total_count: int
    query: str
    execution_time_ms: float
    index: str
    error: Optional[str] = None


class SplunkMCPClient:
    """
    Wraps the Splunk MCP Server for MEDSOC agent use.

    The Splunk MCP Server exposes these tools:
      - search          : run a SPL query, returns events
      - search_job      : async long-running SPL search
      - get_index_info  : describe index fields and volume
      - list_indexes    : enumerate available indexes
      - create_alert    : write a Splunk alert
      - get_alert       : read alert state
      - saved_search    : run a saved search by name

    In production: configure SPLUNK_HOST + SPLUNK_TOKEN env vars.
    In demo mode: calls are intercepted by SimLayer.
    """

    def __init__(self, config: SplunkConfig, sim_mode: bool = False):
        self.config = config
        self.sim_mode = sim_mode
        self._session: Optional[Any] = None
        self._query_count = 0
        logger.info("SplunkMCPClient init | sim_mode=%s | host=%s", sim_mode, config.host)

    # ── Connection lifecycle ───────────────────────────────────────────────

    async def connect(self) -> bool:
        """Establish MCP session with Splunk MCP Server."""
        if self.sim_mode:
            logger.info("Sim mode: MCP connection simulated.")
            return True

        if not MCP_AVAILABLE:
            raise ImportError(
                "mcp package not installed. Run: pip install mcp --break-system-packages"
            )

        server_params = StdioServerParameters(
            command="npx",
            args=[
                "-y", "splunk-mcp",
                "--splunk-url", f"{self.config.scheme}://{self.config.host}:{self.config.port}",
                "--splunk-token", self.config.token,
            ],
            env=None,
        )
        try:
            self._stdio_ctx = stdio_client(server_params)
            read, write = await self._stdio_ctx.__aenter__()
            self._session = ClientSession(read, write)
            await self._session.__aenter__()
            await self._session.initialize()
            tools = await self._session.list_tools()
            logger.info("Splunk MCP connected. Tools: %s", [t.name for t in tools.tools])
            return True
        except Exception as exc:
            logger.error("MCP connection failed: %s", exc)
            raise

    async def disconnect(self):
        if self._session:
            await self._session.__aexit__(None, None, None)
        if hasattr(self, "_stdio_ctx"):
            await self._stdio_ctx.__aexit__(None, None, None)

    # ── Core query interface ───────────────────────────────────────────────

    async def search(
        self,
        spl: str,
        earliest: str = "-15m",
        latest: str = "now",
        max_results: int = 500,
    ) -> MCPQueryResult:
        """
        Execute SPL via Splunk MCP Server search tool.

        Args:
            spl:         SPL query string
            earliest:    Splunk time modifier, e.g. "-1h", "-24h@d"
            latest:      Splunk time modifier, default "now"
            max_results: Cap on returned events
        """
        self._query_count += 1
        t0 = asyncio.get_event_loop().time()

        if self.sim_mode:
            from medsoc.sim.clinical_events import SimLayer
            result = await SimLayer.execute_spl(spl, earliest, max_results)
            result.execution_time_ms = (asyncio.get_event_loop().time() - t0) * 1000
            return result

        try:
            response = await self._session.call_tool(
                "search",
                arguments={
                    "query": spl,
                    "earliest_time": earliest,
                    "latest_time": latest,
                    "count": max_results,
                    "output_mode": "json",
                },
            )
            content = json.loads(response.content[0].text)
            elapsed = (asyncio.get_event_loop().time() - t0) * 1000
            return MCPQueryResult(
                success=True,
                events=content.get("results", []),
                total_count=content.get("total", 0),
                query=spl,
                execution_time_ms=elapsed,
                index=self._extract_index(spl),
            )
        except Exception as exc:
            logger.error("SPL query failed: %s | query: %s", exc, spl)
            return MCPQueryResult(
                success=False, events=[], total_count=0,
                query=spl, execution_time_ms=0.0,
                index="unknown", error=str(exc),
            )

    async def get_index_info(self, index_name: str) -> dict:
        """Describe a Splunk index — field summary, event count, earliest/latest."""
        if self.sim_mode:
            return {
                "index": index_name,
                "event_count": 1_250_000,
                "earliest": (datetime.utcnow() - timedelta(days=90)).isoformat(),
                "latest": datetime.utcnow().isoformat(),
                "fields": ["_time", "host", "source", "sourcetype", "user", "action"],
            }
        response = await self._session.call_tool(
            "get_index_info", arguments={"index": index_name}
        )
        return json.loads(response.content[0].text)

    async def list_indexes(self) -> list[str]:
        """Return all Splunk indexes visible to this token."""
        if self.sim_mode:
            return self.config.indexes
        response = await self._session.call_tool("list_indexes", arguments={})
        return json.loads(response.content[0].text).get("indexes", [])

    async def create_alert(self, name: str, spl: str, cron: str, actions: list[str]) -> bool:
        """Persist a Splunk saved alert (called by Response Agent)."""
        if self.sim_mode:
            logger.info("Sim: alert created → %s", name)
            return True
        response = await self._session.call_tool(
            "create_alert",
            arguments={"name": name, "search": spl, "cron_schedule": cron, "actions": actions},
        )
        return json.loads(response.content[0].text).get("success", False)

    # ── Convenience SPL builders ────────────────────────────────────────────

    @staticmethod
    def spl_ehr_unauthorized_access(time_window: str = "-2h") -> str:
        return (
            f"index=ehr_access earliest={time_window} "
            "| where outside_care_team=true "
            "| stats count dc(patient_id) as patients by user, ward "
            "| where count>5 OR patients>10 "
            "| sort -count"
        )

    @staticmethod
    def spl_iomt_threat_intel(subnet: str = "10.10.0.0/16") -> str:
        return (
            f"index=iomt_devices src_ip={subnet} earliest=-1h "
            "| lookup threat_intel_ips ip AS dst_ip OUTPUT threat_score country "
            "| where isnotnull(threat_score) "
            "| table _time, src_ip, device_type, dst_ip, country, threat_score, bytes_out "
            "| sort -threat_score"
        )

    @staticmethod
    def spl_ransomware_indicator() -> str:
        return (
            "index=endpoint type=WRITE_ENCRYPT earliest=-5m "
            "| bin _time span=1m "
            "| stats count values(extension) as exts by host, _time "
            "| where count>100 "
            "| join host [search index=endpoint | stats values(process) as procs by host]"
        )

    @staticmethod
    def spl_credential_stuffing(window: str = "-5m") -> str:
        return (
            f"index=auth_events type=FAILED_LOGIN earliest={window} "
            "| bin _time span=3m "
            "| stats count dc(user) as unique_targets by src_ip, _time "
            "| where count>15 AND unique_targets>3 "
            "| lookup geo_ip ip AS src_ip OUTPUT country, asn "
            "| sort -count"
        )

    @staticmethod
    def spl_pacs_exfil(server_ip: str = "10.30.1.5") -> str:
        return (
            f"index=network src_ip={server_ip} earliest=-6h "
            "| timechart span=1h sum(bytes_out) by dst_ip "
            "| where sum>500000000 "
            "| join dst_ip [lookup approved_dicom_peers ip AS dst_ip | where isnull(peer_name)]"
        )

    @staticmethod
    def spl_blast_radius(host: str, window: str = "-30m") -> str:
        """Assess scope of compromise for a given host."""
        return (
            f"index=network src_host={host} OR dst_host={host} earliest={window} "
            "| stats dc(dst_ip) as unique_dests, sum(bytes_out) as total_bytes by src_host "
            "| join src_host [search index=endpoint host={host} | stats values(process) as procs by host]"
        )

    # ── Utility ────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_index(spl: str) -> str:
        """Parse index name from SPL string."""
        import re
        m = re.search(r"index=(\w+)", spl)
        return m.group(1) if m else "unknown"

    @property
    def query_count(self) -> int:
        return self._query_count
