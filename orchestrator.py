"""
MEDSOC — Agent Orchestrator
Wires Watchdog → Triage → Investigation → Response into a single
async pipeline. Entry point for running the full MEDSOC system.

Usage:
    # Demo mode (sim layer — no Splunk instance required)
    python orchestrator.py --sim

    # Production mode (requires SPLUNK_HOST + SPLUNK_TOKEN env vars)
    python orchestrator.py

Environment variables:
    SPLUNK_HOST      Splunk Enterprise hostname (default: localhost)
    SPLUNK_PORT      Management port (default: 8089)
    SPLUNK_TOKEN     Splunk auth token (generate in Settings → Tokens)
    MEDSOC_SIM       Set to "1" to force sim mode
"""

import asyncio
import logging
import os
import sys
from datetime import datetime

from splunk.mcp_client import SplunkMCPClient, SplunkConfig
from agents.watchdog_agent import WatchdogAgent, WatchdogAlert
from agents.triage_agent import TriageAgent, ThreatAssessment
from agents.investigation_agent import InvestigationAgent
from agents.response_agent import ResponseAgent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("medsoc.orchestrator")

SIM_MODE = os.getenv("MEDSOC_SIM", "1") == "1" or "--sim" in sys.argv


class MEDSOCOrchestrator:
    """
    Coordinates all four MEDSOC agents.

                 Splunk MCP Server (foundation: Splunk machine data)
                         │
                         ▼
    ┌─────────────────────────────────────────────────────┐
    │ MEDSOC Orchestrator                                 │
    │                                                     │
    │  [Watchdog]→[Triage]→[Investigation]→[Response]    │
    │       ↑                                    ↓        │
    │   Splunk SPL              Human-in-the-Loop UI      │
    └─────────────────────────────────────────────────────┘
    """

    def __init__(self):
        config        = SplunkConfig()
        self.mcp      = SplunkMCPClient(config, sim_mode=SIM_MODE)
        self.triage   = TriageAgent(sim_mode=SIM_MODE)
        self.invest   = InvestigationAgent(self.mcp)
        self.response = ResponseAgent(hitl_callback=self._on_hitl_required)
        self.watchdog = WatchdogAgent(self.mcp, on_alert=self._enqueue_alert)
        self._alert_queue: asyncio.Queue[WatchdogAlert] = asyncio.Queue()
        self._pipeline_count = 0

    # ── Lifecycle ──────────────────────────────────────────────────────────

    async def run(self):
        logger.info("=" * 60)
        logger.info("MEDSOC — Medical Security Operations Center")
        logger.info("Hospital: Federal Teaching Hospital, Gombe, Nigeria")
        logger.info("Mode: %s", "SIMULATION" if SIM_MODE else "PRODUCTION")
        logger.info("Splunk MCP Server: %s", "simulated" if SIM_MODE else self.mcp.config.host)
        logger.info("=" * 60)

        connected = await self.mcp.connect()
        if not connected:
            logger.error("Failed to connect to Splunk MCP Server. Aborting.")
            return

        logger.info("Splunk MCP Server connected. Starting 4-agent pipeline...")

        await asyncio.gather(
            self.watchdog.start(),         # Agent 1: polls Splunk forever
            self._pipeline_consumer(),     # Agents 2–4: process alert queue
        )

    async def shutdown(self):
        self.watchdog.stop()
        await self.triage.close()
        await self.mcp.disconnect()
        logger.info("MEDSOC shutdown complete.")

    # ── Alert queue ────────────────────────────────────────────────────────

    def _enqueue_alert(self, alert: WatchdogAlert):
        """Called synchronously by Watchdog Agent on anomaly detection."""
        try:
            self._alert_queue.put_nowait(alert)
            logger.info("Alert queued: %s | %s", alert.alert_id, alert.category)
        except asyncio.QueueFull:
            logger.warning("Alert queue full — dropping %s", alert.alert_id)

    async def _pipeline_consumer(self):
        """Dequeues alerts and runs them through Agents 2–4."""
        while True:
            alert = await self._alert_queue.get()
            try:
                await self._run_pipeline(alert)
            except Exception as exc:
                logger.error("Pipeline error for %s: %s", alert.alert_id, exc, exc_info=True)
            finally:
                self._alert_queue.task_done()

    async def _run_pipeline(self, alert: WatchdogAlert):
        self._pipeline_count += 1
        logger.info("─── Pipeline start: %s ───", alert.alert_id)

        # Agent 2: Triage (Foundation-sec scoring)
        logger.info("[2/4] Triage Agent — Foundation-sec-1.1-8b-instruct")
        assessment: ThreatAssessment = await self.triage.assess(alert)
        logger.info("      Score=%.1f | Class=%s | MITRE=%s | Escalate=%s",
                    assessment.threat_score, assessment.threat_class,
                    assessment.mitre_technique, assessment.escalate_to_human)

        # Agent 3: Investigation (deep SPL correlation)
        logger.info("[3/4] Investigation Agent — SPL correlation via MCP")
        report = await self.invest.investigate(assessment)
        logger.info("      Correlated=%d events | Root cause: %s",
                    len(report.correlated_events), report.root_cause[:60])

        # Agent 4: Response (playbook + HITL)
        logger.info("[4/4] Response Agent — playbook selection + execution")
        result = await self.response.respond(report)
        logger.info("      Playbook=%s | Actions=%d | HITL=%s",
                    result.playbook_id, len(result.actions), result.hitl_required)

        logger.info("─── Pipeline complete: %s ───", alert.alert_id)
        self._print_summary(alert, assessment, report, result)

    # ── HITL callback ──────────────────────────────────────────────────────

    async def _on_hitl_required(self, result):
        """
        Production: push to Clinical IT Staff dashboard / PagerDuty.
        Demo: auto-approve after 5 seconds (with console prompt).
        """
        hitl_actions = [a for a in result.actions if a.requires_hitl]
        logger.info("⚠  HUMAN APPROVAL REQUIRED — %s", result.playbook_id)
        for a in hitl_actions:
            logger.info("   Pending: [%s] %s", a.action_id, a.description)

        if SIM_MODE:
            logger.info("   [SIM MODE] Auto-approving in 5s — in production a human clicks 'Approve'")
            await asyncio.sleep(5)
            await self.response.approve(result, approver="it_security_admin@fth-gombe.ng")

    # ── Summary ────────────────────────────────────────────────────────────

    @staticmethod
    def _print_summary(alert, assessment, report, result):
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║  MEDSOC INCIDENT SUMMARY
╠══════════════════════════════════════════════════════════════╣
  Alert ID    : {alert.alert_id}
  Category    : {alert.category}
  Threat Score: {assessment.threat_score}/10 ({assessment.threat_class})
  MITRE       : {assessment.mitre_technique} — {assessment.mitre_name}
  Confidence  : {assessment.confidence:.0%}
  Regulatory  : {', '.join(assessment.regulatory)}
  Root Cause  : {report.root_cause[:80]}
  Patient Risk: {report.patient_risk[:80]}
  Playbook    : {result.playbook_id} ({len(result.actions)} actions)
  HITL        : {'APPROVED' if result.hitl_approved else 'PENDING' if result.hitl_required else 'NOT REQUIRED'}
  SPL Queries : {len(report.spl_queries_run)} executed via Splunk MCP
  Correlated  : {len(report.correlated_events)} events
╚══════════════════════════════════════════════════════════════╝
""")

    @property
    def stats(self) -> dict:
        return {
            "pipelines_run":    self._pipeline_count,
            "alerts_pending":   self._alert_queue.qsize(),
            "spl_queries":      self.mcp.query_count,
            "model_inferences": self.triage.inference_count,
            "actions_executed": self.response.execution_count,
            "watchdog_stats":   self.watchdog.stats(),
        }


# ── Entry point ────────────────────────────────────────────────────────────

async def main():
    orchestrator = MEDSOCOrchestrator()
    try:
        await orchestrator.run()
    except KeyboardInterrupt:
        logger.info("Shutdown requested.")
    finally:
        await orchestrator.shutdown()
        stats = orchestrator.stats
        logger.info("Final stats: %s", stats)


if __name__ == "__main__":
    asyncio.run(main())
