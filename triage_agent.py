"""
MEDSOC — Triage Agent
Scores every WatchdogAlert using Splunk's Foundation-sec-1.1-8b-instruct
hosted model. Outputs a structured ThreatAssessment consumed by the
Investigation Agent.

Splunk Hosted Model used:
  foundation-sec-1.1-8b-instruct
  https://www.splunk.com/en_us/blog/security/foundation-sec.html
  GA: February 18, 2026 — Splunk AI Platform

MITRE ATT&CK mapping, HIPAA/NDPA breach classification, and
clinical impact scoring are performed at this layer.
"""

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import httpx

from agents.watchdog_agent import WatchdogAlert

logger = logging.getLogger("medsoc.agent.triage")

# Splunk Hosted Models endpoint
# Docs: https://docs.splunk.com/Documentation/SplunkCloud/latest/AI/HostedModels
SPLUNK_AI_ENDPOINT = os.getenv(
    "SPLUNK_AI_ENDPOINT",
    "https://{SPLUNK_HOST}/services/ml/models/foundation-sec-1.1-8b-instruct/generate"
)
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN", "")

# MITRE ATT&CK technique mapping (clinical IT context)
MITRE_MAP = {
    "Unauthorized EHR Access":     ("T1078", "Valid Accounts"),
    "IoMT Network Anomaly":        ("T1071.001", "Application Layer Protocol: Web Protocols"),
    "Ransomware Indicator":        ("T1486", "Data Encrypted for Impact"),
    "Credential Stuffing Attack":  ("T1110.004", "Brute Force: Credential Stuffing"),
    "PACS Data Exfiltration":      ("T1048", "Exfiltration Over Alternative Protocol"),
}

# Clinical impact dimensions
IMPACT_DIMS = {
    "Unauthorized EHR Access":    {"patient_privacy": 10, "hipaa_breach": 9, "care_continuity": 3},
    "IoMT Network Anomaly":       {"patient_safety": 9,  "device_integrity": 8, "care_continuity": 8},
    "Ransomware Indicator":       {"care_continuity": 10, "data_availability": 10, "patient_safety": 8},
    "Credential Stuffing Attack": {"patient_privacy": 6,  "hipaa_breach": 5,  "care_continuity": 3},
    "PACS Data Exfiltration":     {"patient_privacy": 9,  "ndpa_breach": 9,   "imaging_access": 7},
}


@dataclass
class ThreatAssessment:
    """Foundation-sec output — consumed by Investigation + Response Agents."""
    alert_id:         str
    threat_score:     float            # 0.0–10.0
    confidence:       float            # 0.0–1.0
    threat_class:     str              # e.g. "ransomware_encryption"
    mitre_technique:  str              # e.g. "T1486"
    mitre_name:       str
    tags:             list[str]
    impact:           dict[str, int]   # per-dimension impact scores
    narrative:        str              # Foundation-sec natural-language summary
    regulatory:       list[str]        # applicable regs: HIPAA, NDPA, etc.
    escalate_to_human: bool
    assessed_at:      datetime = field(default_factory=datetime.utcnow)
    model:            str = "foundation-sec-1.1-8b-instruct"
    raw_alert:        Optional[WatchdogAlert] = None


class TriageAgent:
    """
    Agent 2 of 4 in the MEDSOC pipeline.

    Responsibilities:
      - Receives WatchdogAlert from queue
      - Calls Foundation-sec-1.1-8b-instruct via Splunk Hosted Models
      - Parses model output into ThreatAssessment
      - Applies human-escalation threshold (score ≥ 7.0 or patient_safety ≥ 8)
      - Forwards to Investigation Agent

    Foundation-sec is security-tuned on Splunk machine data — it natively
    understands SPL event formats, SIEM field names, and threat patterns.
    """

    ESCALATION_THRESHOLD_SCORE   = 7.0
    ESCALATION_THRESHOLD_SAFETY  = 8

    def __init__(self, sim_mode: bool = False):
        self.sim_mode     = sim_mode
        self._http        = httpx.AsyncClient(timeout=30.0, verify=False)
        self._infer_count = 0

    async def assess(self, alert: WatchdogAlert) -> ThreatAssessment:
        """Run Foundation-sec assessment on a WatchdogAlert."""
        logger.info("Triage: assessing %s | %s", alert.alert_id, alert.category)

        if self.sim_mode:
            return await self._sim_assess(alert)

        prompt = self._build_prompt(alert)
        try:
            raw_output = await self._call_foundation_sec(prompt)
            assessment = self._parse_output(raw_output, alert)
        except Exception as exc:
            logger.error("Foundation-sec call failed: %s — falling back to rule-based triage", exc)
            assessment = self._rule_based_fallback(alert)

        self._infer_count += 1
        assessment.raw_alert = alert
        logger.info("Triage: %s score=%.1f confidence=%.2f escalate=%s",
                    alert.alert_id, assessment.threat_score,
                    assessment.confidence, assessment.escalate_to_human)
        return assessment

    # ── Foundation-sec prompt engineering ──────────────────────────────────

    def _build_prompt(self, alert: WatchdogAlert) -> str:
        return f"""You are Foundation-sec-1.1-8b-instruct, Splunk's security-tuned language model.
Analyze this clinical IT security alert from a Federal Teaching Hospital SIEM and return ONLY valid JSON.

ALERT:
- ID:       {alert.alert_id}
- Severity: {alert.severity}
- Category: {alert.category}
- Index:    {alert.index}
- Raw event sample: {alert.raw_sample}
- SPL query that triggered: {alert.spl_query}

RESPOND with ONLY this JSON structure (no markdown, no preamble):
{{
  "threat_score": <float 0-10>,
  "confidence": <float 0-1>,
  "threat_class": "<snake_case_class>",
  "tags": ["<tag1>", "<tag2>"],
  "narrative": "<2-3 sentence plain English summary of the threat and clinical risk>",
  "regulatory": ["<applicable_reg>"],
  "escalate_to_human": <true|false>
}}
"""

    async def _call_foundation_sec(self, prompt: str) -> dict:
        """POST to Splunk Hosted Models — foundation-sec-1.1-8b-instruct."""
        url = SPLUNK_AI_ENDPOINT.format(SPLUNK_HOST=os.getenv("SPLUNK_HOST", "localhost"))
        response = await self._http.post(
            url,
            headers={
                "Authorization": f"Bearer {SPLUNK_TOKEN}",
                "Content-Type": "application/json",
            },
            json={
                "model": "foundation-sec-1.1-8b-instruct",
                "prompt": prompt,
                "max_tokens": 400,
                "temperature": 0.1,   # low temp for consistent structured output
            },
        )
        response.raise_for_status()
        body = response.json()
        text = body.get("choices", [{}])[0].get("text", "{}")
        return json.loads(text)

    def _parse_output(self, raw: dict, alert: WatchdogAlert) -> ThreatAssessment:
        mitre_id, mitre_name = MITRE_MAP.get(alert.category, ("T0000", "Unknown"))
        impact_dims = IMPACT_DIMS.get(alert.category, {})
        score = float(raw.get("threat_score", 5.0))
        return ThreatAssessment(
            alert_id=alert.alert_id,
            threat_score=score,
            confidence=float(raw.get("confidence", 0.75)),
            threat_class=raw.get("threat_class", "unknown"),
            mitre_technique=mitre_id,
            mitre_name=mitre_name,
            tags=raw.get("tags", []),
            impact=impact_dims,
            narrative=raw.get("narrative", ""),
            regulatory=raw.get("regulatory", []),
            escalate_to_human=(
                score >= self.ESCALATION_THRESHOLD_SCORE or
                impact_dims.get("patient_safety", 0) >= self.ESCALATION_THRESHOLD_SAFETY
            ),
        )

    # ── Simulation mode ────────────────────────────────────────────────────

    async def _sim_assess(self, alert: WatchdogAlert) -> ThreatAssessment:
        """Return pre-computed assessment for demo mode without real API call."""
        await asyncio.sleep(0.4)   # simulate inference latency

        SCORE_MAP = {
            "CRITICAL": 9.2, "HIGH": 7.8, "MEDIUM": 6.4, "LOW": 3.1,
        }
        score = SCORE_MAP.get(alert.severity, 5.0)
        mitre_id, mitre_name = MITRE_MAP.get(alert.category, ("T0000", "Unknown"))
        impact_dims = IMPACT_DIMS.get(alert.category, {})

        narratives = {
            "Unauthorized EHR Access":
                "A staff account accessed 47+ patient records outside their assigned care team "
                "after hours. This matches insider threat and unauthorized access patterns with "
                "high PHI exfiltration risk and HIPAA breach implications.",
            "IoMT Network Anomaly":
                "A medical device is beaconing to a known-malicious external IP at 120-second "
                "intervals. This pattern is consistent with C2 communication post-compromise, "
                "with direct patient safety implications if the device is disrupted.",
            "Ransomware Indicator":
                "A clinical workstation is encrypting files at 847+ per minute with a novel "
                "extension, matching ALPHV/BlackCat ransomware behavior. Shared drives "
                "including PACS archives are at immediate risk.",
            "Credential Stuffing Attack":
                "An external IP executed 47 failed logins targeting nursing accounts in 3 "
                "minutes, consistent with credential-stuffing using a dark web healthcare "
                "breach dataset. 3 accounts reached lockout.",
            "PACS Data Exfiltration":
                "The PACS server transmitted 2.3 GB to an unapproved external IP via a service "
                "account during off-hours. The payload likely contains DICOM imaging studies "
                "with embedded PHI, triggering NDPA 2023 notification obligations.",
        }

        self._infer_count += 1
        ta = ThreatAssessment(
            alert_id=alert.alert_id,
            threat_score=score,
            confidence=round(0.87 + (score / 100), 2),
            threat_class=alert.category.lower().replace(" ", "_"),
            mitre_technique=mitre_id,
            mitre_name=mitre_name,
            tags=list(impact_dims.keys())[:4],
            impact=impact_dims,
            narrative=narratives.get(alert.category, "Threat detected in clinical IT infrastructure."),
            regulatory=self._regs_for(alert.category),
            escalate_to_human=score >= self.ESCALATION_THRESHOLD_SCORE,
            raw_alert=alert,
        )
        return ta

    @staticmethod
    def _regs_for(category: str) -> list[str]:
        mapping = {
            "Unauthorized EHR Access":   ["HIPAA Privacy Rule", "NDPA 2023 (Nigeria)"],
            "PACS Data Exfiltration":    ["NDPA 2023 (Nigeria)", "HIPAA Security Rule"],
            "Ransomware Indicator":      ["CISA Healthcare Ransomware Advisory", "FMoH Incident Reporting"],
            "IoMT Network Anomaly":      ["FDA Medical Device Cybersecurity", "ISO 80001-1"],
            "Credential Stuffing Attack":["HIPAA Security Rule", "NDPA 2023 (Nigeria)"],
        }
        return mapping.get(category, ["Hospital Information Security Policy"])

    # ── Rule-based fallback (no model available) ───────────────────────────

    def _rule_based_fallback(self, alert: WatchdogAlert) -> ThreatAssessment:
        score = {"CRITICAL": 8.5, "HIGH": 7.0, "MEDIUM": 5.5, "LOW": 2.0}.get(alert.severity, 5.0)
        mitre_id, mitre_name = MITRE_MAP.get(alert.category, ("T0000", "Unknown"))
        return ThreatAssessment(
            alert_id=alert.alert_id, threat_score=score,
            confidence=0.65, threat_class=alert.category.lower().replace(" ", "_"),
            mitre_technique=mitre_id, mitre_name=mitre_name,
            tags=[alert.category], impact={},
            narrative=f"Rule-based triage: {alert.category} detected. Foundation-sec unavailable.",
            regulatory=self._regs_for(alert.category),
            escalate_to_human=score >= self.ESCALATION_THRESHOLD_SCORE,
        )

    @property
    def inference_count(self) -> int:
        return self._infer_count

    async def close(self):
        await self._http.aclose()
