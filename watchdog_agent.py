"""
MEDSOC — Watchdog Agent
Continuously polls Splunk via MCP Server across all clinical IT indexes.
Detects anomalies and pushes them to the Triage Agent queue.

Splunk tools used:
  - search  (via Splunk MCP Server)
  - get_index_info
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

from splunk.mcp_client import SplunkMCPClient, MCPQueryResult, SplunkConfig

logger = logging.getLogger("medsoc.agent.watchdog")


@dataclass
class WatchdogAlert:
    """Anomaly detected by Watchdog — passed to Triage Agent."""
    alert_id:    str
    severity:    str          # CRITICAL / HIGH / MEDIUM
    category:    str
    index:       str
    spl_query:   str
    events:      list[dict]
    event_count: int
    detected_at: datetime = field(default_factory=datetime.utcnow)
    raw_sample:  str = ""


# Polling schedule per index (seconds between polls)
POLL_INTERVALS = {
    "ehr_access":   30,    # EHR access — frequent (HIPAA critical)
    "iomt_devices": 20,    # Medical device network — very frequent
    "endpoint":     15,    # Workstation EDR — most frequent (ransomware risk)
    "auth_events":  20,    # Active Directory — frequent (credential attacks)
    "network":      45,    # Network flows — less frequent (volume)
}


class WatchdogAgent:
    """
    Agent 1 of 4 in the MEDSOC pipeline.

    Responsibilities:
      - Runs scheduled SPL queries against Splunk MCP Server
      - Applies threshold-based anomaly detection
      - Enriches events with index metadata
      - Forwards WatchdogAlert objects to Triage Agent

    Trigger logic (rule-based, fast):
      ehr_access   → outside_care_team=true AND records>10
      iomt_devices → dst_ip matches threat intel
      endpoint     → WRITE_ENCRYPT events >100/min (ransomware)
      auth_events  → FAILED_LOGIN >15 unique targets in 3 min
      network      → outbound bytes >500 MB from known server
    """

    def __init__(
        self,
        mcp: SplunkMCPClient,
        on_alert: Callable[[WatchdogAlert], None],
    ):
        self.mcp      = mcp
        self.on_alert = on_alert
        self._running = False
        self._alert_seq = 0
        self._poll_stats: dict[str, dict] = {
            idx: {"polls": 0, "alerts": 0, "last_poll": None}
            for idx in POLL_INTERVALS
        }

    # ── Lifecycle ──────────────────────────────────────────────────────────

    async def start(self):
        """Start all polling coroutines concurrently."""
        self._running = True
        logger.info("Watchdog Agent started — monitoring %d indexes via Splunk MCP",
                    len(POLL_INTERVALS))
        await asyncio.gather(
            self._poll_ehr_access(),
            self._poll_iomt_devices(),
            self._poll_endpoint(),
            self._poll_auth_events(),
            self._poll_network(),
        )

    def stop(self):
        self._running = False
        logger.info("Watchdog Agent stopped.")

    # ── Per-index polling coroutines ────────────────────────────────────────

    async def _poll_ehr_access(self):
        while self._running:
            spl = SplunkMCPClient.spl_ehr_unauthorized_access("-30m")
            result = await self.mcp.search(spl, earliest="-30m")
            self._record_poll("ehr_access")
            if result.success and result.events:
                await self._evaluate_ehr(result)
            await asyncio.sleep(POLL_INTERVALS["ehr_access"])

    async def _poll_iomt_devices(self):
        while self._running:
            spl = SplunkMCPClient.spl_iomt_threat_intel()
            result = await self.mcp.search(spl, earliest="-15m")
            self._record_poll("iomt_devices")
            if result.success and result.events:
                await self._evaluate_iomt(result)
            await asyncio.sleep(POLL_INTERVALS["iomt_devices"])

    async def _poll_endpoint(self):
        while self._running:
            spl = SplunkMCPClient.spl_ransomware_indicator()
            result = await self.mcp.search(spl, earliest="-5m")
            self._record_poll("endpoint")
            if result.success and result.events:
                await self._evaluate_endpoint(result)
            await asyncio.sleep(POLL_INTERVALS["endpoint"])

    async def _poll_auth_events(self):
        while self._running:
            spl = SplunkMCPClient.spl_credential_stuffing("-10m")
            result = await self.mcp.search(spl, earliest="-10m")
            self._record_poll("auth_events")
            if result.success and result.events:
                await self._evaluate_auth(result)
            await asyncio.sleep(POLL_INTERVALS["auth_events"])

    async def _poll_network(self):
        while self._running:
            spl = SplunkMCPClient.spl_pacs_exfil()
            result = await self.mcp.search(spl, earliest="-6h")
            self._record_poll("network")
            if result.success and result.events:
                await self._evaluate_network(result)
            await asyncio.sleep(POLL_INTERVALS["network"])

    # ── Threshold evaluators ───────────────────────────────────────────────

    async def _evaluate_ehr(self, r: MCPQueryResult):
        for evt in r.events:
            count = int(evt.get("records_accessed", 0))
            if evt.get("outside_care_team") and count >= 10:
                self._fire_alert(
                    severity="CRITICAL",
                    category="Unauthorized EHR Access",
                    index="ehr_access",
                    spl=r.query,
                    events=r.events,
                    raw=evt.get("_raw", ""),
                )
                return   # one alert per poll cycle

    async def _evaluate_iomt(self, r: MCPQueryResult):
        for evt in r.events:
            if evt.get("threat_score") or evt.get("dst_ip") in self._known_malicious():
                self._fire_alert(
                    severity="HIGH",
                    category="IoMT Network Anomaly",
                    index="iomt_devices",
                    spl=r.query, events=r.events, raw=evt.get("_raw", ""),
                )
                return

    async def _evaluate_endpoint(self, r: MCPQueryResult):
        for evt in r.events:
            if int(evt.get("file_events", 0)) >= 100 and evt.get("type") == "WRITE_ENCRYPT":
                self._fire_alert(
                    severity="CRITICAL",
                    category="Ransomware Indicator",
                    index="endpoint",
                    spl=r.query, events=r.events, raw=evt.get("_raw", ""),
                )
                return

    async def _evaluate_auth(self, r: MCPQueryResult):
        for evt in r.events:
            if int(evt.get("count", 0)) >= 15 and int(evt.get("unique_targets", 0)) >= 3:
                self._fire_alert(
                    severity="HIGH",
                    category="Credential Stuffing Attack",
                    index="auth_events",
                    spl=r.query, events=r.events, raw=evt.get("_raw", ""),
                )
                return

    async def _evaluate_network(self, r: MCPQueryResult):
        for evt in r.events:
            if int(evt.get("bytes_out", 0)) >= 500_000_000:
                self._fire_alert(
                    severity="MEDIUM",
                    category="PACS Data Exfiltration",
                    index="network",
                    spl=r.query, events=r.events, raw=evt.get("_raw", ""),
                )
                return

    # ── Helpers ────────────────────────────────────────────────────────────

    def _fire_alert(self, severity, category, index, spl, events, raw):
        self._alert_seq += 1
        alert = WatchdogAlert(
            alert_id=f"MSOC-{self._alert_seq:05d}",
            severity=severity,
            category=category,
            index=index,
            spl_query=spl,
            events=events,
            event_count=len(events),
            raw_sample=raw,
        )
        self._poll_stats[index]["alerts"] += 1
        logger.warning("[ALERT] %s | %s | %s | events=%d",
                       alert.alert_id, severity, category, len(events))
        self.on_alert(alert)

    def _record_poll(self, index: str):
        self._poll_stats[index]["polls"]     += 1
        self._poll_stats[index]["last_poll"]  = datetime.utcnow().isoformat()

    @staticmethod
    def _known_malicious() -> list[str]:
        from sim.clinical_events import MALICIOUS_IPS
        return MALICIOUS_IPS

    def stats(self) -> dict:
        return {"poll_stats": self._poll_stats, "total_alerts": self._alert_seq}
