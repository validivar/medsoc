"""
MEDSOC — Response Agent
Selects and executes remediation playbooks based on InvestigationReport.
All account-level and network-isolation actions gate on human-in-the-loop
approval from Clinical IT Staff before execution.

Playbooks:
  CLINICAL-BREACH-001  → Unauthorized EHR access
  IOMT-COMPROMISE-003  → Medical device C2 / compromise
  RANSOM-CLINICAL-001  → Ransomware (Code Black)
  CRED-ATTACK-002      → Credential stuffing
  EXFIL-DICOM-001      → PACS data exfiltration
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Callable

from agents.investigation_agent import InvestigationReport

logger = logging.getLogger("medsoc.agent.response")


class ActionType(str, Enum):
    NETWORK_BLOCK     = "network_block"
    ACCOUNT_SUSPEND   = "account_suspend"
    PASSWORD_RESET    = "password_reset"
    MFA_ENFORCE       = "mfa_enforce"
    DEVICE_ISOLATE    = "device_isolate"
    ALERT_CREATE      = "splunk_alert_create"
    ESCALATE_HUMAN    = "escalate_human"
    NOTIFY_DPO        = "notify_dpo"
    NOTIFY_CISO       = "notify_ciso"
    ACTIVATE_RUNBOOK  = "activate_runbook"
    PRESERVE_FORENSIC = "preserve_forensic"
    NOTIFY_REGULATOR  = "notify_regulator"


@dataclass
class PlaybookAction:
    action_id:    str
    action_type:  ActionType
    description:  str
    parameters:   dict
    requires_hitl: bool    # Human-in-the-loop required before execution
    executed:     bool  = False
    executed_at:  Optional[datetime] = None
    result:       Optional[str]      = None


@dataclass
class PlaybookResult:
    playbook_id:   str
    alert_id:      str
    actions:       list[PlaybookAction]
    hitl_required: bool
    hitl_approved: bool = False
    approved_by:   Optional[str] = None
    approved_at:   Optional[datetime] = None
    audit_trail:   list[str] = field(default_factory=list)
    completed_at:  Optional[datetime] = None


# ── Playbook library ────────────────────────────────────────────────────────

PLAYBOOKS: dict[str, Callable[[InvestigationReport], list[PlaybookAction]]] = {}

def _register(category):
    def decorator(fn):
        PLAYBOOKS[category] = fn
        return fn
    return decorator


@_register("Unauthorized EHR Access")
def _ehr_playbook(report: InvestigationReport) -> list[PlaybookAction]:
    user = report.blast_radius.get("affected_user", "unknown")
    return [
        PlaybookAction("ACT-01", ActionType.ACCOUNT_SUSPEND,
            f"Suspend account: {user}",
            {"account": user, "duration": "pending_investigation"},
            requires_hitl=True),
        PlaybookAction("ACT-02", ActionType.NOTIFY_DPO,
            "Notify Data Protection Officer — potential HIPAA/NDPA breach",
            {"breach_type": "EHR unauthorized access", "record_count": report.blast_radius.get("records_exposed")},
            requires_hitl=False),
        PlaybookAction("ACT-03", ActionType.ALERT_CREATE,
            "Create Splunk alert: monitor account if reinstated",
            {"spl": f'index=ehr_access user="{user}" | where outside_care_team=true', "cron": "*/5 * * * *"},
            requires_hitl=False),
        PlaybookAction("ACT-04", ActionType.NOTIFY_CISO,
            "Escalate to CISO + Hospital Management",
            {"priority": "CRITICAL", "summary": report.root_cause},
            requires_hitl=False),
        PlaybookAction("ACT-05", ActionType.PRESERVE_FORENSIC,
            "Preserve 6-hour EHR audit log for investigation",
            {"index": "ehr_access", "user": user, "window": "-6h"},
            requires_hitl=False),
    ]


@_register("IoMT Network Anomaly")
def _iomt_playbook(report: InvestigationReport) -> list[PlaybookAction]:
    device_ip = report.blast_radius.get("primary_device", "unknown")
    return [
        PlaybookAction("ACT-01", ActionType.ESCALATE_HUMAN,
            "Notify clinical team — patient on device must be assessed before isolation",
            {"ward": "WARD-B", "device_ip": device_ip, "patient_check": True},
            requires_hitl=False),
        PlaybookAction("ACT-02", ActionType.DEVICE_ISOLATE,
            f"Isolate device from network VLAN: {device_ip}",
            {"ip": device_ip, "vlan": "iomt_devices", "method": "ACL"},
            requires_hitl=True),
        PlaybookAction("ACT-03", ActionType.NETWORK_BLOCK,
            "Block egress to C2 subnet at perimeter firewall",
            {"dst_network": "185.234.218.0/24", "protocol": "TCP", "port": 443},
            requires_hitl=False),
        PlaybookAction("ACT-04", ActionType.NOTIFY_CISO,
            "Alert Biomedical Engineering team — device firmware forensics required",
            {"priority": "HIGH", "device_count": report.blast_radius.get("additional_devices", 1)},
            requires_hitl=False),
        PlaybookAction("ACT-05", ActionType.PRESERVE_FORENSIC,
            "Capture network forensic dump from IoMT VLAN",
            {"interface": "iomt_vlan", "duration_min": 30},
            requires_hitl=False),
    ]


@_register("Ransomware Indicator")
def _ransomware_playbook(report: InvestigationReport) -> list[PlaybookAction]:
    host = report.blast_radius.get("infected_host", "CW-047")
    return [
        PlaybookAction("ACT-01", ActionType.ACTIVATE_RUNBOOK,
            "CODE BLACK — Activate Hospital Incident Command",
            {"runbook": "RANSOM-CLINICAL-001", "priority": "P0"},
            requires_hitl=True),
        PlaybookAction("ACT-02", ActionType.DEVICE_ISOLATE,
            f"IMMEDIATE network isolation: {host} (verify patient safety first)",
            {"host": host, "method": "switch_port_shutdown", "patient_check": True},
            requires_hitl=True),
        PlaybookAction("ACT-03", ActionType.PRESERVE_FORENSIC,
            f"Volume snapshot: {host} — DO NOT power off (preserve encryption state)",
            {"host": host, "method": "VSS_snapshot", "power_off": False},
            requires_hitl=False),
        PlaybookAction("ACT-04", ActionType.NOTIFY_REGULATOR,
            "Notify CERT-NG + Federal Ministry of Health",
            {"agencies": ["CERT-NG", "FMoH", "NDPC"], "incident_type": "ransomware"},
            requires_hitl=False),
        PlaybookAction("ACT-05", ActionType.NETWORK_BLOCK,
            "Block ransomware C2 at perimeter — known IOC list",
            {"ioc_list": "ALPHV_BlackCat_IOCs_2026", "block_method": "NGFW_EDL"},
            requires_hitl=False),
    ]


@_register("Credential Stuffing Attack")
def _cred_playbook(report: InvestigationReport) -> list[PlaybookAction]:
    src_ip = report.blast_radius.get("attacker_ip", "unknown")
    return [
        PlaybookAction("ACT-01", ActionType.NETWORK_BLOCK,
            f"Block source IP at perimeter: {src_ip}",
            {"ip": src_ip, "duration": "indefinite", "method": "NGFW_block"},
            requires_hitl=False),
        PlaybookAction("ACT-02", ActionType.PASSWORD_RESET,
            "Force password reset: all nrs_* (nursing) accounts",
            {"account_pattern": "nrs_*", "notify_managers": True},
            requires_hitl=True),
        PlaybookAction("ACT-03", ActionType.MFA_ENFORCE,
            "Enable MFA for nursing staff portal immediately",
            {"portal": "clinical_staff_portal", "method": "TOTP"},
            requires_hitl=True),
        PlaybookAction("ACT-04", ActionType.NOTIFY_CISO,
            "Alert nursing managers — account access review required",
            {"priority": "HIGH", "accounts_affected": report.blast_radius.get("accounts_locked", 3)},
            requires_hitl=False),
        PlaybookAction("ACT-05", ActionType.ALERT_CREATE,
            "Create Splunk alert: monitor nrs_* logins from external IPs",
            {"spl": 'index=auth_events type=FAILED_LOGIN target_pattern="nrs_*" src_category="external" | stats count by src_ip | where count>5'},
            requires_hitl=False),
    ]


@_register("PACS Data Exfiltration")
def _pacs_playbook(report: InvestigationReport) -> list[PlaybookAction]:
    return [
        PlaybookAction("ACT-01", ActionType.NETWORK_BLOCK,
            "Block PACS server egress port 8443 to external IPs",
            {"src_ip": "10.30.1.5", "port": 8443, "direction": "egress"},
            requires_hitl=False),
        PlaybookAction("ACT-02", ActionType.PRESERVE_FORENSIC,
            "Forensic copy of PACS transfer logs (48h window)",
            {"server": "PACS", "log_type": "DICOM_transfer", "window_h": 48},
            requires_hitl=False),
        PlaybookAction("ACT-03", ActionType.NOTIFY_DPO,
            "Notify DPO — NDPA 2023 §37: 72-hour breach notification obligation",
            {"regulation": "NDPA_2023", "section": "37", "deadline_hours": 72},
            requires_hitl=False),
        PlaybookAction("ACT-04", ActionType.ESCALATE_HUMAN,
            "Contact Radiology Head — was transfer authorized?",
            {"contact": "hod_radiology", "urgency": "immediate"},
            requires_hitl=False),
        PlaybookAction("ACT-05", ActionType.NOTIFY_REGULATOR,
            "Prepare NDPC notification if transfer confirmed unauthorized",
            {"agency": "NDPC_Nigeria", "phi_count": "~900 DICOM studies"},
            requires_hitl=True),
    ]


# ── Response Agent ─────────────────────────────────────────────────────────

class ResponseAgent:
    """
    Agent 4 of 4 in the MEDSOC pipeline.

    For each InvestigationReport:
      1. Selects the appropriate playbook
      2. Separates auto-executable vs. HITL-required actions
      3. Executes auto actions immediately
      4. Queues HITL actions and notifies Clinical IT Staff
      5. On human approval: executes remaining actions
      6. Generates audit trail with full provenance
    """

    def __init__(self, hitl_callback: Optional[Callable] = None):
        self.hitl_callback  = hitl_callback   # called when human approval needed
        self._exec_count    = 0
        self._audit_records = []

    async def respond(self, report: InvestigationReport) -> PlaybookResult:
        category   = report.threat_assessment.raw_alert.category if report.threat_assessment.raw_alert else "Unknown"
        playbook_fn = PLAYBOOKS.get(category)

        if not playbook_fn:
            logger.error("No playbook for category: %s", category)
            return PlaybookResult(
                playbook_id="UNKNOWN", alert_id=report.alert_id,
                actions=[], hitl_required=False,
            )

        actions       = playbook_fn(report)
        hitl_required = any(a.requires_hitl for a in actions)
        playbook_id   = self._playbook_id(category)

        result = PlaybookResult(
            playbook_id=playbook_id,
            alert_id=report.alert_id,
            actions=actions,
            hitl_required=hitl_required,
        )

        logger.info("Response: playbook %s | %d actions | hitl=%s",
                    playbook_id, len(actions), hitl_required)

        # Execute auto actions immediately
        for action in actions:
            if not action.requires_hitl:
                await self._execute(action, result)

        # Gate HITL actions
        if hitl_required:
            hitl_actions = [a for a in actions if a.requires_hitl]
            logger.info("Response: %d actions awaiting human approval — %s",
                        len(hitl_actions), [a.description for a in hitl_actions])
            if self.hitl_callback:
                await self.hitl_callback(result)

        return result

    async def approve(self, result: PlaybookResult, approver: str) -> PlaybookResult:
        """Called when Clinical IT Staff approves pending HITL actions."""
        result.hitl_approved = True
        result.approved_by   = approver
        result.approved_at   = datetime.utcnow()
        result.audit_trail.append(
            f"[{datetime.utcnow().isoformat()}] Human approval granted by {approver}"
        )

        for action in result.actions:
            if action.requires_hitl and not action.executed:
                await self._execute(action, result)

        result.completed_at = datetime.utcnow()
        logger.info("Response: playbook %s approved by %s — all actions complete",
                    result.playbook_id, approver)
        return result

    async def _execute(self, action: PlaybookAction, result: PlaybookResult):
        """Dispatch action to appropriate execution handler."""
        logger.info("Executing: %s — %s", action.action_id, action.description)
        await asyncio.sleep(0.1)   # simulate execution latency

        # In production each ActionType maps to a real integration:
        # NETWORK_BLOCK     → Palo Alto NGFW API / Splunk SOAR
        # ACCOUNT_SUSPEND   → Active Directory / Azure AD API
        # PASSWORD_RESET    → AD / Entra ID forced reset
        # MFA_ENFORCE       → Identity Provider (Okta / Azure AD MFA)
        # DEVICE_ISOLATE    → Switch SNMP API / NAC
        # ALERT_CREATE      → Splunk MCP Server: create_alert tool
        # NOTIFY_*          → Email / SMS / PagerDuty / Teams webhook
        # PRESERVE_FORENSIC → Splunk archiving / S3 / Evidence locker

        action.executed    = True
        action.executed_at = datetime.utcnow()
        action.result      = f"Executed at {action.executed_at.isoformat()} — SUCCESS"
        self._exec_count  += 1

        audit_entry = (
            f"[{datetime.utcnow().isoformat()}] "
            f"{action.action_id} | {action.action_type.value} | "
            f"{action.description} | EXECUTED"
        )
        result.audit_trail.append(audit_entry)
        self._audit_records.append(audit_entry)

    @staticmethod
    def _playbook_id(category: str) -> str:
        return {
            "Unauthorized EHR Access":   "CLINICAL-BREACH-001",
            "IoMT Network Anomaly":      "IOMT-COMPROMISE-003",
            "Ransomware Indicator":      "RANSOM-CLINICAL-001",
            "Credential Stuffing Attack":"CRED-ATTACK-002",
            "PACS Data Exfiltration":    "EXFIL-DICOM-001",
        }.get(category, "GENERIC-RESPONSE-000")

    @property
    def execution_count(self) -> int:
        return self._exec_count

    def full_audit_trail(self) -> list[str]:
        return self._audit_records.copy()
