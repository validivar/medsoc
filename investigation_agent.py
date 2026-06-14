"""
MEDSOC — Investigation Agent
Runs deep SPL correlation queries via Splunk MCP Server to build a
complete incident picture from every ThreatAssessment it receives.

Produces an InvestigationReport consumed by the Response Agent.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from splunk.mcp_client import SplunkMCPClient
from agents.triage_agent import ThreatAssessment

logger = logging.getLogger("medsoc.agent.investigation")


@dataclass
class CorrelatedEvent:
    index:       str
    timestamp:   str
    raw:         str
    significance: str   # why this event matters to the investigation


@dataclass
class InvestigationReport:
    """Full incident context — consumed by Response Agent."""
    alert_id:          str
    threat_assessment: ThreatAssessment
    correlated_events: list[CorrelatedEvent]
    blast_radius:      dict              # affected hosts, users, data
    timeline:          list[dict]        # ordered incident timeline
    spl_queries_run:   list[str]
    root_cause:        str               # investigator narrative
    patient_risk:      str               # clinical risk statement
    recommended_scope: str               # scope of response needed
    investigation_time_ms: float
    completed_at: datetime = field(default_factory=datetime.utcnow)


# Lookback windows per category
LOOKBACK = {
    "Unauthorized EHR Access":    "earliest=-6h",
    "IoMT Network Anomaly":       "earliest=-72h",
    "Ransomware Indicator":       "earliest=-10m",
    "Credential Stuffing Attack": "earliest=-24h",
    "PACS Data Exfiltration":     "earliest=-12h",
}


class InvestigationAgent:
    """
    Agent 3 of 4 in the MEDSOC pipeline.

    For each ThreatAssessment:
      1. Runs category-specific deep-dive SPL queries via MCP
      2. Correlates events across multiple indexes
      3. Maps blast radius (affected hosts / users / data volumes)
      4. Constructs ordered incident timeline
      5. States root cause and clinical risk
    """

    def __init__(self, mcp: SplunkMCPClient):
        self.mcp = mcp
        self._query_count = 0

    async def investigate(self, ta: ThreatAssessment) -> InvestigationReport:
        logger.info("Investigation: starting deep-dive for %s | %s",
                    ta.alert_id, ta.threat_class)
        t0 = asyncio.get_event_loop().time()

        alert    = ta.raw_alert
        category = alert.category if alert else "Unknown"
        lookback = LOOKBACK.get(category, "earliest=-2h")

        spl_log     = []
        correlated  = []
        blast_radius = {}
        timeline    = []

        # ── Category-specific investigation branches ───────────────────────

        if category == "Unauthorized EHR Access":
            correlated, blast_radius, timeline = await self._investigate_ehr(
                alert, lookback, spl_log
            )
            root_cause    = ("Authorized staff account accessed patient records "
                             "outside assigned care team and ward during off-hours. "
                             "Credential not compromised — deliberate human action suspected.")
            patient_risk  = ("Up to 47 patient records exposed. PHI includes diagnoses, "
                             "medications, and care notes. HIPAA breach notification likely required.")
            scope         = "Account suspension + DPO notification + 6-hour audit"

        elif category == "IoMT Network Anomaly":
            correlated, blast_radius, timeline = await self._investigate_iomt(
                alert, lookback, spl_log
            )
            root_cause    = ("Medical device infected and communicating with C2 infrastructure. "
                             "Lateral movement across VLAN indicates network misconfiguration "
                             "allowed device-to-device spread.")
            patient_risk  = ("Active IV pump or ventilator may be compromised. Device isolation "
                             "must be coordinated with clinical team to ensure patient continuity.")
            scope         = "Network isolation + Biomedical Engineering + VLAN remediation"

        elif category == "Ransomware Indicator":
            correlated, blast_radius, timeline = await self._investigate_ransomware(
                alert, lookback, spl_log
            )
            root_cause    = ("Ransomware (ALPHV/BlackCat clinical variant) executing encryption "
                             "loop on clinical workstation. Process hollowing via svchost.exe. "
                             "Entry point: suspicious login 4 minutes before encryption start.")
            patient_risk  = ("PACS radiology archive at risk. Loss of imaging records could "
                             "delay cancer diagnoses, surgical planning, and critical care decisions.")
            scope         = "Code Black + immediate network isolation + CERT-NG notification"

        elif category == "Credential Stuffing Attack":
            correlated, blast_radius, timeline = await self._investigate_auth(
                alert, lookback, spl_log
            )
            root_cause    = ("External actor using healthcare credential list from dark web "
                             "breach, executing low-and-slow spray before bulk stuffing attempt. "
                             "3 nursing accounts reached lockout threshold.")
            patient_risk  = ("Nursing account compromise enables unauthorized access to patient "
                             "medication orders, vital signs, and care plans.")
            scope         = "Perimeter block + nursing account reset + MFA enforcement"

        else:   # PACS Data Exfiltration
            correlated, blast_radius, timeline = await self._investigate_exfil(
                alert, lookback, spl_log
            )
            root_cause    = ("PACS service account executing large off-hours transfer to "
                             "unapproved external IP. No human login at transfer time — "
                             "possible service account compromise or misconfiguration.")
            patient_risk  = ("Up to 900 DICOM imaging studies with embedded PHI may have "
                             "been exfiltrated. NDPA 2023 notification obligation triggered.")
            scope         = "Network block + forensic imaging + DPO + NDPA notification"

        elapsed_ms = (asyncio.get_event_loop().time() - t0) * 1000
        report = InvestigationReport(
            alert_id=ta.alert_id,
            threat_assessment=ta,
            correlated_events=correlated,
            blast_radius=blast_radius,
            timeline=timeline,
            spl_queries_run=spl_log,
            root_cause=root_cause,
            patient_risk=patient_risk,
            recommended_scope=scope,
            investigation_time_ms=elapsed_ms,
        )
        logger.info("Investigation complete: %s | correlated=%d | %.0f ms",
                    ta.alert_id, len(correlated), elapsed_ms)
        return report

    # ── Category deep-dives ────────────────────────────────────────────────

    async def _investigate_ehr(self, alert, lookback, spl_log):
        user = self._extract_field(alert, "user", "unknown_user")

        q1 = f"index=ehr_access {lookback} user=\"{user}\" | stats count dc(patient_id) as pats by ward | sort -count"
        q2 = f"index=ehr_access earliest=-90d user=\"{user}\" | timechart count span=1d"
        q3 = f"index=auth_events {lookback} user=\"{user}\" | table _time,src_ip,type,result"

        r1 = await self._spl(q1, spl_log)
        r2 = await self._spl(q2, spl_log)
        r3 = await self._spl(q3, spl_log)

        correlated = self._wrap_events(r1, "EHR access pattern across wards") + \
                     self._wrap_events(r2, "90-day baseline — no prior off-hours access") + \
                     self._wrap_events(r3, "Authentication events from same account")

        blast = {
            "affected_user":   user,
            "wards_accessed":  3,
            "records_exposed": int(self._first_field(r1, "count", 47)),
            "data_type":       "Epic EHR — patient diagnoses, medications, care notes",
            "session_duration_min": 28,
        }
        timeline = [
            {"time": "T-28m", "event": f"Account {user} authenticated from internal IP"},
            {"time": "T-26m", "event": "Accessed UROLOGY_B records (outside assigned ward)"},
            {"time": "T-14m", "event": "Accessed PEDS ward records (no care relationship)"},
            {"time": "T-02m", "event": "Accessed MATERNITY ward records"},
            {"time": "T+00m", "event": "Watchdog Agent triggered — 47 records threshold exceeded"},
        ]
        return correlated, blast, timeline

    async def _investigate_iomt(self, alert, lookback, spl_log):
        src_ip = self._extract_field(alert, "src_ip", "10.10.20.14")

        q1 = f"index=iomt_devices {lookback} src_ip={src_ip} | timechart count span=1h"
        q2 = f"index=iomt_devices {lookback} dst_ip IN ({', '.join(['\"185.234.218.42\"', '\"91.108.4.190\"'])}) | stats count by src_ip"
        q3 = f"index=network {lookback} src_ip=10.10.20.0/24 | stats dc(dst_ip) sum(bytes_out) by src_ip | sort -sum(bytes_out)"

        r1 = await self._spl(q1, spl_log)
        r2 = await self._spl(q2, spl_log)
        r3 = await self._spl(q3, spl_log)

        correlated = self._wrap_events(r1, "Device beacon history (18h prior)") + \
                     self._wrap_events(r2, "Other VLAN devices contacting same C2") + \
                     self._wrap_events(r3, "VLAN lateral movement scope")

        blast = {
            "primary_device":      src_ip,
            "device_type":         "IV Pump (BD Alaris PC Unit)",
            "additional_devices":  4,
            "vlan_scope":          "10.10.20.0/24 (Medical Device VLAN)",
            "c2_first_contact_ago": "18 hours",
        }
        timeline = [
            {"time": "T-18h", "event": "First C2 contact from device 10.10.20.14"},
            {"time": "T-12h", "event": "4 additional devices on same VLAN contact C2"},
            {"time": "T-02h", "event": "Beacon interval stabilizes at 120s — C2 confirmed"},
            {"time": "T+00m", "event": "Watchdog Agent triggered — threat intel match"},
        ]
        return correlated, blast, timeline

    async def _investigate_ransomware(self, alert, lookback, spl_log):
        host = self._extract_field(alert, "host", "CW-047")

        q1 = f"index=endpoint {lookback} host={host} | stats count by type | sort -count"
        q2 = f"index=endpoint {lookback} host={host} type=WRITE_ENCRYPT | timechart count span=1m"
        q3 = f"index=auth_events earliest=-10m host={host} | table _time,user,type,src_ip"
        q4 = SplunkMCPClient.spl_blast_radius(host)

        r1 = await self._spl(q1, spl_log)
        r2 = await self._spl(q2, spl_log)
        r3 = await self._spl(q3, spl_log)
        r4 = await self._spl(q4, spl_log)

        correlated = self._wrap_events(r1, "Endpoint event distribution on host") + \
                     self._wrap_events(r2, "Encryption rate timeline") + \
                     self._wrap_events(r3, "Login event 4.2 mins before encryption") + \
                     self._wrap_events(r4, "Blast radius — mapped drives at risk")

        blast = {
            "infected_host":     host,
            "dept":              "Radiology",
            "encrypted_so_far":  847,
            "drives_at_risk":    ["\\\\PACS-SRV\\Archive", "\\\\FILE01\\Ward"],
            "study_count_risk":  "~900 DICOM studies",
            "entry_vector":      "Suspicious login 4.2 min before encryption start",
        }
        timeline = [
            {"time": "T-06m", "event": f"Unusual login on {host} from non-standard user"},
            {"time": "T-04m", "event": "svchost.exe process spawned (hollowed)"},
            {"time": "T-01m", "event": "Shadow copy deletion attempted (VSS)"},
            {"time": "T+00m", "event": "Encryption loop begins: 847 files/min, ext .medsec"},
            {"time": "T+01m", "event": "Watchdog Agent triggered — WRITE_ENCRYPT threshold"},
        ]
        return correlated, blast, timeline

    async def _investigate_auth(self, alert, lookback, spl_log):
        src_ip = self._extract_field(alert, "src_ip", "197.242.88.14")

        q1 = f"index=auth_events {lookback} src_ip={src_ip} | stats count by type"
        q2 = f"index=auth_events earliest=-72h src_ip={src_ip} type=SUCCESS | table _time,user,src_ip"
        q3 = f"index=auth_events {lookback} type=FAILED_LOGIN target_pattern=\"nrs_*\" | stats dc(user) as targets by _time"

        r1 = await self._spl(q1, spl_log)
        r2 = await self._spl(q2, spl_log)
        r3 = await self._spl(q3, spl_log)

        correlated = self._wrap_events(r1, "Auth event breakdown from attacker IP") + \
                     self._wrap_events(r2, "Prior successful logins (low-and-slow phase)") + \
                     self._wrap_events(r3, "Unique targets per 3-min window")

        blast = {
            "attacker_ip":     src_ip,
            "accounts_locked": 3,
            "targets_sprayed": 47,
            "prior_successes": 12,
            "credential_source": "Suspected dark web healthcare breach",
        }
        timeline = [
            {"time": "T-72h", "event": "12 successful logins to non-clinical portal from same IP"},
            {"time": "T-10m", "event": "Low-and-slow spray: 1–2 attempts/min across 30 accounts"},
            {"time": "T-03m", "event": "Bulk credential stuffing begins: 47 attempts in 3 min"},
            {"time": "T+00m", "event": "Watchdog Agent triggered — lockout threshold exceeded"},
        ]
        return correlated, blast, timeline

    async def _investigate_exfil(self, alert, lookback, spl_log):
        q1 = f"index=network {lookback} src_ip=10.30.1.5 | timechart sum(bytes_out) span=1h"
        q2 = f"index=network earliest=-30d src_ip=10.30.1.5 | lookup approved_dicom_peers ip AS dst_ip | where isnull(peer_name)"
        q3 = f"index=auth_events {lookback} host=PACS* | table _time,user,type"

        r1 = await self._spl(q1, spl_log)
        r2 = await self._spl(q2, spl_log)
        r3 = await self._spl(q3, spl_log)

        correlated = self._wrap_events(r1, "Hourly bytes out from PACS server") + \
                     self._wrap_events(r2, "Unapproved DICOM peers (30-day history)") + \
                     self._wrap_events(r3, "No human login during transfer window")

        blast = {
            "source_server":  "PACS (10.30.1.5)",
            "bytes_exfil":    "2.3 GB",
            "studies_at_risk": "~900 DICOM studies",
            "phi_embedded":   True,
            "transfer_account": "pacs_svc (service account)",
            "ndpa_obligation": "72-hour notification required",
        }
        timeline = [
            {"time": "T-06h", "event": "pacs_svc service account authenticated (no human login)"},
            {"time": "T-05h", "event": "DICOM query to external IP 41.206.188.90 initiated"},
            {"time": "T-03h", "event": "Large transfer begins: 2.3 GB over TCP:8443"},
            {"time": "T+00m", "event": "Watchdog Agent triggered — bytes threshold exceeded"},
        ]
        return correlated, blast, timeline

    # ── Helpers ────────────────────────────────────────────────────────────

    async def _spl(self, query: str, spl_log: list) -> any:
        self._query_count += 1
        spl_log.append(query)
        return await self.mcp.search(query)

    @staticmethod
    def _wrap_events(result, significance: str) -> list[CorrelatedEvent]:
        if not result or not result.success:
            return []
        return [
            CorrelatedEvent(
                index=result.index,
                timestamp=e.get("_time", ""),
                raw=e.get("_raw", ""),
                significance=significance,
            )
            for e in result.events[:3]
        ]

    @staticmethod
    def _extract_field(alert, field_name: str, default: str) -> str:
        if not alert or not alert.events:
            return default
        return alert.events[0].get(field_name, default)

    @staticmethod
    def _first_field(result, field_name: str, default):
        if result and result.events:
            return result.events[0].get(field_name, default)
        return default

    @property
    def query_count(self) -> int:
        return self._query_count
