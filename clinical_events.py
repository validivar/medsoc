"""
MEDSOC — Clinical IT Simulation Layer
Generates FHIR-aligned synthetic telemetry that mirrors real Splunk MCP
Server responses. Used in demo mode — a production MEDSOC deployment
connects directly to hospital Splunk infrastructure via MCP.

Why synthetic data: patient privacy (NDPA 2023, HIPAA) requires that
no real PHI appear in demo environments. All events below are fabricated.
"""

import asyncio
import random
import re
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional
from splunk.mcp_client import MCPQueryResult


# ── Synthetic hospital topology ────────────────────────────────────────────

HOSPITAL_NAME = "Federal Teaching Hospital, Gombe"
HOSPITAL_DOMAIN = "fth-gombe.ng"

WARDS = ["UROLOGY_A", "UROLOGY_B", "PEDS", "MATERNITY", "CARDIO", "RADIOLOGY",
         "ICU", "A_AND_E", "GENERAL_B", "ONCOLOGY"]

STAFF_ACCOUNTS = [
    "dr.k.abdullahi", "dr.m.ibrahim", "nrs.a.bello", "nrs.f.hassan",
    "nrs.i.yusuf",    "hmo.o.gideon", "admin.it",   "pacs_svc",
    "backup_svc",     "lab.technician1",
]

WORKSTATIONS = [f"CW-{str(i).zfill(3)}" for i in range(1, 60)]
IOMT_IPS     = [f"10.10.20.{i}" for i in range(10, 40)]
SERVERS      = {"pacs": "10.30.1.5", "ehr": "10.0.1.15", "ad": "10.0.0.5"}
MALICIOUS_IPS = ["185.234.218.42", "197.242.88.14", "41.206.188.90",
                  "91.108.4.190",  "104.21.66.139"]


# ── Event schema ───────────────────────────────────────────────────────────

@dataclass
class SyntheticEvent:
    index: str
    sourcetype: str
    host: str
    source: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW
    category: str
    raw: str               # simulated raw log line
    fields: dict           # structured fields
    timestamp: datetime    = field(default_factory=datetime.utcnow)


# ── Event generators ───────────────────────────────────────────────────────

class EHRAccessGenerator:
    """Epic EHR access log events — unauthorized after-hours access."""

    @staticmethod
    def after_hours_access() -> SyntheticEvent:
        user     = random.choice([s for s in STAFF_ACCOUNTS if "dr." in s or "nrs." in s])
        ward     = random.choice(WARDS)
        count    = random.randint(15, 62)
        ts_hour  = random.randint(0, 4)      # 00:00–04:59 after hours
        ts_str   = f"{ts_hour:02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}"
        raw = (f'index=ehr_access user="{user}@{HOSPITAL_DOMAIN}" '
               f'timestamp="{ts_str}" records_accessed={count} ward="{ward}" '
               f'outside_care_team=TRUE dept_match=FALSE session_ip="192.168.10.{random.randint(10,80)}"')
        return SyntheticEvent(
            index="ehr_access", sourcetype="epic:access",
            host=SERVERS["ehr"], source="EpicAuditLog",
            severity="CRITICAL", category="Unauthorized EHR Access",
            raw=raw,
            fields={
                "user": f"{user}@{HOSPITAL_DOMAIN}", "ward": ward,
                "records_accessed": count, "outside_care_team": True,
                "timestamp": ts_str,
            },
        )


class IoMTGenerator:
    """Medical device network telemetry — C2 beaconing."""

    @staticmethod
    def c2_beacon() -> SyntheticEvent:
        device_ip  = random.choice(IOMT_IPS)
        malicious  = random.choice(MALICIOUS_IPS)
        bytes_out  = random.randint(38000, 55000)
        device_types = ["IV Pump (BD Alaris PC)", "Ventilator (Puritan Bennett 980)",
                        "Patient Monitor (Mindray VS-900)", "Infusion Pump (Braun Space)"]
        dtype      = random.choice(device_types)
        serial     = f"2024{random.randint(10000,99999)}"
        raw = (f'index=iomt_devices src_ip={device_ip} dst_ip={malicious} '
               f'port=443 proto=TCP bytes_out={bytes_out} '
               f'device_type="{dtype}" serial="{serial}" '
               f'ward="{random.choice(WARDS)}"')
        return SyntheticEvent(
            index="iomt_devices", sourcetype="network:flow",
            host=device_ip, source="PaloAltoNGFW",
            severity="HIGH", category="IoMT Network Anomaly",
            raw=raw,
            fields={
                "src_ip": device_ip, "dst_ip": malicious,
                "device_type": dtype, "bytes_out": bytes_out, "serial": serial,
            },
        )


class EndpointGenerator:
    """Clinical workstation EDR telemetry — ransomware patterns."""

    @staticmethod
    def ransomware_indicator() -> SyntheticEvent:
        host       = random.choice(WORKSTATIONS)
        file_count = random.randint(600, 1100)
        ext        = random.choice([".medsec", ".locked", ".enc", ".hospital"])
        dept       = random.choice(["RADIOLOGY", "CLINICAL_ADMIN", "LAB", "PHARMACY"])
        raw = (f'index=endpoint host="{host}" process="svchost.exe" '
               f'file_events={file_count} type="WRITE_ENCRYPT" entropy=HIGH '
               f'extension="{ext}" dept="{dept}" duration_sec=60 '
               f'mapped_drives="\\\\PACS-SRV\\Archive,\\\\FILE01\\Ward"')
        return SyntheticEvent(
            index="endpoint", sourcetype="crowdstrike:edr",
            host=host, source="CrowdStrikeHorizon",
            severity="CRITICAL", category="Ransomware Indicator",
            raw=raw,
            fields={
                "host": host, "file_events": file_count, "extension": ext,
                "process": "svchost.exe", "dept": dept,
            },
        )


class AuthEventGenerator:
    """AD / LDAP authentication events — credential stuffing."""

    @staticmethod
    def credential_stuffing() -> SyntheticEvent:
        src_ip    = random.choice(MALICIOUS_IPS)
        attempts  = random.randint(30, 65)
        lockouts  = random.randint(2, 5)
        raw = (f'index=auth_events src_ip={src_ip} type=FAILED_LOGIN '
               f'domain="{HOSPITAL_DOMAIN}" count={attempts} '
               f'duration_sec=180 target_pattern="nrs_*" lockouts={lockouts} '
               f'country="NG" asn="AS{random.randint(10000,60000)}"')
        return SyntheticEvent(
            index="auth_events", sourcetype="wineventlog:security",
            host=SERVERS["ad"], source="WinEventLog",
            severity="HIGH", category="Credential Stuffing",
            raw=raw,
            fields={
                "src_ip": src_ip, "attempts": attempts,
                "lockouts": lockouts, "target_pattern": "nrs_*",
            },
        )


class NetworkGenerator:
    """Network flow telemetry — PACS data exfiltration."""

    @staticmethod
    def pacs_exfil() -> SyntheticEvent:
        dst_ip    = random.choice(MALICIOUS_IPS)
        bytes_out = random.randint(1_500_000_000, 3_200_000_000)
        hour      = random.randint(1, 5)
        raw = (f'index=network src_ip={SERVERS["pacs"]} dst_ip={dst_ip} '
               f'bytes_out={bytes_out} proto=TCP port=8443 '
               f'time="{hour:02d}:{random.randint(0,59):02d}" '
               f'server="PACS" service_account="pacs_svc" '
               f'scheduled_transfer=FALSE peer_approved=FALSE')
        return SyntheticEvent(
            index="network", sourcetype="pan:traffic",
            host=SERVERS["pacs"], source="PaloAltoNGFW",
            severity="MEDIUM", category="PACS Data Exfiltration",
            raw=raw,
            fields={
                "src_ip": SERVERS["pacs"], "dst_ip": dst_ip,
                "bytes_out": bytes_out, "service_account": "pacs_svc",
            },
        )


# ── SimLayer dispatcher ────────────────────────────────────────────────────

class SimLayer:
    """
    Intercepts SPL queries and returns realistic synthetic events.
    Mirrors the MCPQueryResult schema from SplunkMCPClient.search().
    """

    _GENERATORS = {
        "ehr_access":    EHRAccessGenerator.after_hours_access,
        "iomt_devices":  IoMTGenerator.c2_beacon,
        "endpoint":      EndpointGenerator.ransomware_indicator,
        "auth_events":   AuthEventGenerator.credential_stuffing,
        "network":       NetworkGenerator.pacs_exfil,
    }

    @classmethod
    async def execute_spl(
        cls, spl: str, earliest: str, max_results: int
    ) -> MCPQueryResult:
        """Route SPL to matching generator and return formatted events."""
        await asyncio.sleep(random.uniform(0.1, 0.35))   # simulate network latency

        index = cls._extract_index(spl)
        gen   = cls._GENERATORS.get(index)

        if not gen:
            return MCPQueryResult(
                success=True, events=[], total_count=0,
                query=spl, execution_time_ms=120.0, index=index,
            )

        # Generate 1-5 matching events
        count  = random.randint(1, 5)
        events = []
        for _ in range(count):
            evt = gen()
            events.append({
                "_time":       (datetime.utcnow() - timedelta(
                                    minutes=random.randint(1, 30))).isoformat(),
                "_raw":        evt.raw,
                "index":       evt.index,
                "sourcetype":  evt.sourcetype,
                "host":        evt.host,
                "source":      evt.source,
                "severity":    evt.severity,
                "category":    evt.category,
                **evt.fields,
            })

        return MCPQueryResult(
            success=True,
            events=events,
            total_count=count + random.randint(50, 900),   # broader match count
            query=spl,
            execution_time_ms=random.uniform(80, 340),
            index=index,
        )

    @staticmethod
    def _extract_index(spl: str) -> str:
        m = re.search(r"index=(\w+)", spl)
        return m.group(1) if m else "unknown"

    @classmethod
    async def generate_background_noise(cls, interval_sec: float = 5.0):
        """Yield low-severity routine events for the watchdog feed."""
        noise_events = [
            {"severity": "LOW", "category": "Scheduled Scan",  "index": "vulnerability",
             "raw": "index=vulnerability scanner=Nessus status=COMPLETE critical=0 high=2 medium=14"},
            {"severity": "LOW", "category": "Backup Job",      "index": "endpoint",
             "raw": "index=endpoint host=BACKUP-SRV type=BACKUP_COMPLETE size_gb=142"},
            {"severity": "LOW", "category": "Patch Deployed",  "index": "endpoint",
             "raw": "index=endpoint type=PATCH_DEPLOY kb=KB5035853 hosts=23 pending_reboot=2"},
            {"severity": "MEDIUM", "category": "Config Change","index": "network",
             "raw": "index=network type=FIREWALL_RULE_CHANGE user=admin.it change_id=CHG0047"},
        ]
        while True:
            await asyncio.sleep(interval_sec)
            yield random.choice(noise_events)
