# 🛡 MEDSOC — Medical Security Operations Center

> **A 4-agent autonomous security operations system built specifically for hospital IT infrastructure.



![Architecture](architecture.svg)

---

## What it does

Hospitals are the most ransomware-targeted sector on earth. A single attack can delay surgeries, lock EHR records, and endanger lives. But most hospital IT teams are understaffed and overwhelmed with false positives.

**MEDSOC** is a four-agent autonomous security operations system built specifically for clinical IT infrastructure. It ingests machine data from EHR systems, medical device networks, workstations, Active Directory, and network flows — all through **Splunk as the intelligence backbone** — and autonomously detects, investigates, and responds to threats before they become incidents.

The key design principle: **AI handles the noise, humans handle the judgment calls.** Account suspension, network isolation, and regulatory notifications all gate on human approval. Routine blocking, logging, and enrichment execute automatically.

---

## Architecture

```
[Clinical IT Systems]
  Epic EHR · IoMT Devices · Workstations · AD · NGFW / PACS
        │
        ▼  (log ingestion)
[Splunk Enterprise / Cloud]
  Indexes: ehr_access · iomt_devices · endpoint · auth_events · network
        │
        ▼  (Model Context Protocol)
[Splunk MCP Server ─ GA Feb 4, 2026]
  Tools: search · list_indexes · get_index_info · create_alert
        │
        ▼
[MEDSOC Orchestrator]
  ┌──────────────────────────────────────────────────────┐
  │  ① WATCHDOG AGENT    → polls Splunk via MCP (15–45s) │
  │  ② TRIAGE AGENT      → Foundation-sec-1.1-8b scoring │
  │  ③ INVESTIGATION     → deep SPL correlation          │
  │  ④ RESPONSE AGENT    → playbooks + HITL gate         │
  └──────────────────────────────────────────────────────┘
        │
        ▼
[MEDSOC Dashboard]           [Splunk Alerts]    [Audit Trail]
  Human-in-the-loop UI        MCP create_alert   HIPAA / NDPA
  Clinical IT Staff approval  Persistent rules   Evidence log
```

---

## Splunk capabilities used

| Capability | Role in MEDSOC | Special Prize |
|---|---|---|
| **Splunk MCP Server** (GA Feb 4, 2026) | Primary data interface for all 4 agents — `search`, `list_indexes`, `create_alert` tools | Best Use of Splunk MCP Server |
| **Foundation-sec-1.1-8b-instruct** (Splunk Hosted Models, GA Feb 18, 2026) | Threat scoring, MITRE ATT&CK mapping, regulatory breach classification | Best Use of Splunk Hosted Models |
| **Splunk AI Assistant** | Natural-language SPL generation for investigation queries | Best Use of Splunk Developer Tools |
| **Splunk SIEM indexes** | 6 clinical IT indexes — EHR access, IoMT, endpoint, auth, network | Best of Security |

---

## The four agents

### ① Watchdog Agent
Continuously polls each Splunk index via the MCP Server `search` tool on a per-index schedule (15–45 second intervals). Applies threshold rules specific to clinical IT patterns — after-hours EHR record volumes, IoMT outbound to threat intel IPs, ransomware file encryption rates, credential stuffing against nursing accounts, PACS data exfiltration volumes.

### ② Triage Agent
Sends every anomaly to **Foundation-sec-1.1-8b-instruct** via Splunk Hosted Models. Foundation-sec is trained on security machine data and natively understands Splunk field names, SPL event formats, and SIEM threat patterns. Outputs: threat score (0–10), MITRE ATT&CK technique, clinical impact dimensions, regulatory obligations (HIPAA, NDPA 2023 Nigeria), and escalation decision.

### ③ Investigation Agent
Runs 3–6 correlated SPL queries per incident via MCP to build complete incident context: blast radius, affected users, at-risk data volumes, root cause narrative, ordered incident timeline. Generates the clinical risk statement that Clinical IT Staff see when approving actions.

### ④ Response Agent
Selects the appropriate playbook (5 clinical playbooks across all threat categories), executes non-destructive actions immediately (logging, enrichment, notifications), and gates account-level and network-isolation actions on **human-in-the-loop approval**. Full audit trail generated for every action with timestamp and approver identity.

---

## Threat scenarios covered

| Category | Splunk Index | Foundation-sec Class | Playbook |
|---|---|---|---|
| After-hours EHR access (Insider Threat) | `ehr_access` | `insider_access` | CLINICAL-BREACH-001 |
| Medical device C2 beacon (IoMT) | `iomt_devices` | `c2_beacon` | IOMT-COMPROMISE-003 |
| Ransomware encryption (Radiology) | `endpoint` | `ransomware_encryption` | RANSOM-CLINICAL-001 |
| Nursing account credential stuffing | `auth_events` | `credential_stuffing` | CRED-ATTACK-002 |
| PACS imaging data exfiltration | `network` | `data_exfiltration` | EXFIL-DICOM-001 |

---

## Demo environment

> The live demo uses **synthetic, FHIR-aligned clinical IT telemetry** to protect patient privacy. A production MEDSOC deployment connects directly to hospital Splunk infrastructure via the MCP Server.
>
> This is standard practice in healthcare tech demos — NDPA 2023 (Nigeria) and HIPAA require that no real PHI appear in non-production environments.

**Demo:** [Live on https://vercel.com/validivar/medsoc) · See `dashboard/index.html`

---

## Repo structure

```
MEDSOC/
├── architecture.svg          # System architecture diagram
├── dashboard/
│   └── index.html            # Live demo dashboard (single file, deploy via Netlify Drop)
├── agents/
│   ├── watchdog_agent.py     # Agent 1: Splunk MCP polling + anomaly detection
│   ├── triage_agent.py       # Agent 2: Foundation-sec threat scoring
│   ├── investigation_agent.py# Agent 3: Deep SPL correlation
│   └── response_agent.py     # Agent 4: Playbook execution + HITL gate
├── splunk/
│   └── mcp_client.py         # Splunk MCP Server client wrapper
├── sim/
│   └── clinical_events.py    # Synthetic clinical IT event generator (demo mode)
├── orchestrator.py           # Main orchestrator — wires all 4 agents
└── requirements.txt
```

---

## Setup

### Demo mode (no Splunk instance required)
```bash
git clone https://github.com/validivar>/MEDSOC
cd MEDSOC
pip install -r requirements.txt --break-system-packages
python orchestrator.py --sim
```

Open `dashboard/index.html` in your browser (or drag-and-drop to [https://vercel.com/validivar/medsoc)).

### Production mode (requires Splunk Enterprise/Cloud)

1. Install Splunk Enterprise (free trial) or use Splunk Cloud
2. Generate an auth token: **Settings → Tokens → New Token**
3. Install Splunk MCP Server: `npx -y splunk-mcp` (requires Node 18+)
4. Set environment variables:
   ```bash
   export SPLUNK_HOST=your-splunk-host.com
   export SPLUNK_PORT=8089
   export SPLUNK_TOKEN=your-token-here
   export MEDSOC_SIM=0
   ```
5. Run: `python orchestrator.py`

---

## Why healthcare IT?

Hospitals are 3× more likely to be hit by ransomware than other sectors. The average ransomware attack on a hospital costs **$1.27M per day in downtime** (IBM Security Report 2025). In Nigeria, the 2023 National Data Protection Act created new 72-hour breach notification obligations — but most Federal Teaching Hospitals have no automated detection pipeline.

MEDSOC closes that gap using infrastructure they already have (or can deploy via Splunk free trial) and a technology stack (Splunk MCP + Foundation-sec) designed exactly for this problem.

**Built by:** Mikhail Ikpoma, Founder[Senary Systems].

---

## License

MIT — see [LICENSE](LICENSE)
