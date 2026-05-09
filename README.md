# 🏛️ SOCrates

> *Every CVE deserves an interrogation.*

**SOCrates** is an autonomous Security Operations Center analyst. Drop in a CVE ID and it fetches live threat intel, identifies the APT groups known to exploit that vendor, simulates the full attack kill chain with real tool names, maps every phase to MITRE ATT&CK v16, and generates a production-ready incident response report — complete with a validated Sigma detection rule and effort-labeled remediation steps.

Zero human input beyond the CVE ID. End-to-end in under a minute.

Built for the [AMD x LabLab.ai Developer Hackathon](https://lablab.ai/ai-hackathons/amd-developer) (May 2026) by **git happens**.

---

## How It Works

```
CVE ID → 🔍 Scout → ☠️ Adversary → 📋 Coroner → IR Report
```

Three specialized agents run sequentially, each with its own context window and tools:

| Agent | Model | What it does |
|-------|-------|-------------|
| 🔍 **Scout** | Llama 3.3 70B | Pulls live CVE data from NVD, checks CISA KEV catalog, fetches vendor advisories |
| ☠️ **Adversary** | Llama 3.3 70B | Profiles threat actors, simulates the full 6-phase kill chain, names real offensive tools |
| 📋 **Coroner** | Qwen 2.5 72B | Maps kill chain to MITRE ATT&CK v16, writes the IR report, generates valid Sigma rule |

---

## What You Get

**Scout output:**
- CVSS score + severity (v4 → v3.1 → v3.0 → v2 priority)
- ⚠️ CISA KEV flag — date added, ransomware campaign use, required action
- Vendor advisory excerpt (Fortinet, Palo Alto, Microsoft, Cisco, Red Hat, VMware)
- Affected CPE configurations, reference URLs

**Adversary output:**
- Threat actor context — which APT/criminal groups target this vendor, their objectives
- 6-phase kill chain: Initial Access → Execution → Persistence → Privilege Escalation → Lateral Movement → Impact
- Real offensive tool names at each step (Sliver, Cobalt Strike, Mimikatz, CrackMapExec, Impacket, BloodHound, etc.)
- Confidence score (HIGH/MEDIUM/LOW) per phase
- CVE chaining — what secondary vulnerabilities an attacker chains next

**Coroner output:**
- Executive summary (2–3 sentences for leadership)
- Attack path mapped to specific MITRE ATT&CK v16 technique IDs (697 techniques, all 15 tactics)
- One valid Sigma detection rule (UUID, correct tags, validated with sigma-cli — zero errors)
- Effort-labeled remediation: 🟢 Quick win / 🟡 Medium effort / 🔴 Heavy lift

**Frontend:**
- Live streaming output — each agent's work appears as it completes
- Pipeline status bar + run metrics (time, tokens, $0.00)
- 🧠 Agent Trace tab — live tool calls, reasoning, handoffs between agents
- 📥 Download Report button — exports full IR report as `.md`

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Orchestration | [CrewAI](https://github.com/crewAIInc/crewAI) — sequential multi-agent pipeline |
| Scout + Adversary | Llama 3.3 70B (q8_0) via Ollama |
| Coroner | Qwen 2.5 72B (q4_K_M) via Ollama |
| Compute | AMD Instinct MI300X — 192GB VRAM, both models resident simultaneously |
| Threat Intel | [NVD REST API v2.0](https://nvd.nist.gov/) (live) + [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (live, 1hr cache) |
| MITRE Data | ATT&CK v16 STIX bundle — 697 techniques parsed locally |
| Threat Actors | 20-group curated DB (MITRE ATT&CK Group profiles + CISA advisories) |
| Frontend | [Gradio](https://gradio.app/) — 4 tabs, streaming output |

---

## Quick Start

### Prerequisites
- Python 3.11+
- Ollama with `llama3.3:70b-instruct-q8_0` and `qwen2.5:72b-instruct-q4_K_M` pulled
- Or: an OpenAI-compatible vLLM endpoint (see [AMD cloud setup](#amd-cloud-setup))

```bash
git clone https://github.com/sreenidhi-n/socrates.git
cd socrates

# Install
pip install -e .

# Configure
cp .env.example .env
# Edit .env — set LLAMA_BASE_URL, QWEN_BASE_URL, VLLM_API_KEY
# NVD_API_KEY is optional but recommended (higher rate limits)

# Launch
python app.py
# → http://localhost:7860
```

### CLI usage
```bash
# Run the pipeline directly (prints final IR report)
python -m socrates.crew CVE-2024-21762
```

---

## AMD Cloud Setup

SOCrates runs on AMD Instinct MI300X via Ollama. The MI300X's 192GB VRAM holds both 70B-class models in memory simultaneously — no model-swap latency between agents.

```bash
# 1. Provision an AMD Developer Cloud droplet
# Image: ROCm 7.2 | Size: gpu-mi300x-192gb

# 2. SSH in and run the setup script
bash scripts/setup_cloud.sh   # installs Ollama + ROCm deps

# 3. Pull models
ollama pull llama3.3:70b-instruct-q8_0
ollama pull qwen2.5:72b-instruct-q4_K_M

# 4. Open a tunnel from your local machine
ssh -NT -L 11435:localhost:11434 root@<droplet-ip>

# 5. Set your .env
LLAMA_BASE_URL=http://localhost:11435/v1
QWEN_BASE_URL=http://localhost:11435/v1
VLLM_API_KEY=ollama
```

The `scripts/` directory also includes `serve_llama.sh` and `serve_qwen.sh` for vLLM deployments if you prefer that over Ollama.

---

## Project Structure

```
socrates/
├── app.py                         # Gradio frontend — run this
├── pyproject.toml
├── .env.example                   # Copy to .env and configure
│
├── src/socrates/
│   ├── config.py                  # All settings — endpoints, keys, paths
│   ├── crew.py                    # CrewAI pipeline — Scout → Adversary → Coroner
│   │
│   ├── agents/
│   │   ├── scout.py               # Threat intel collector
│   │   ├── adversary.py           # Attack path simulator
│   │   └── coroner.py             # IR report generator
│   │
│   ├── tools/
│   │   ├── nvd_tool.py            # NVD API + CISA KEV + vendor advisory enrichment
│   │   ├── mitre_tool.py          # ATT&CK v16 scored relevance search
│   │   ├── threat_actor_tool.py   # 20-group threat actor DB lookup
│   │   └── cve_parser.py          # CVE ID validation helpers
│   │
│   └── data/
│       ├── attack.json            # MITRE ATT&CK v16 — 697 techniques (local)
│       └── threat_actors.json     # 20 APT/criminal groups with targeting profiles
│
└── scripts/
    ├── setup_cloud.sh             # AMD cloud node provisioning
    ├── serve_llama.sh             # vLLM serving script for Llama
    ├── serve_qwen.sh              # vLLM serving script for Qwen
    ├── build_attack_json.py       # One-time: downloads + parses MITRE STIX bundle
    └── test_pipeline.py           # End-to-end smoke test
```

---

## Intelligence Sources

Everything is sourced — nothing hallucinated in:

| Source | Data | Freshness |
|--------|------|-----------|
| [NVD REST API v2.0](https://nvd.nist.gov/developers/api-dashboard) | CVSS scores, affected CPEs, references | Live |
| [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Active exploitation status, ransomware flag | Live, 1hr cache |
| Vendor security advisories | Fortinet PSIRT, Palo Alto Unit42, Microsoft MSRC, Cisco, Red Hat, VMware | Live (fetched from NVD ref URLs) |
| [MITRE ATT&CK v16](https://attack.mitre.org/) | 697 techniques across 15 tactics | Local STIX bundle |
| MITRE ATT&CK Group profiles + CISA advisories | 20 threat actor groups, targeting patterns | Curated |

---

## Threat Actor Coverage

20 groups sourced from MITRE ATT&CK Group profiles and CISA advisories:

APT1, APT28 (Fancy Bear), APT29 (Cozy Bear), APT32 (OceanLotus), APT33 (Refined Kitten), APT38, APT41 (Winnti), FIN7, Gamaredon, HAFNIUM, INDRIK SPIDER (Evil Corp), Lazarus Group, Rocke Group, Sandworm Team, Scattered Spider, TeamTNT, Tortoiseshell, Turla, Volt Typhoon, Wizard Spider

Attribution language is "associated with" — not "confirmed to have exploited". A production version would parse the full STIX Groups relationships bundle for machine-verified mappings.

---

## Demo CVEs

| CVE | Vulnerability | CVSS | Notes |
|-----|--------------|------|-------|
| CVE-2024-21762 | Fortinet FortiOS/FortiProxy — unauthenticated RCE | 9.8 | In CISA KEV, ransomware flag, Sandworm/Volt Typhoon/Wizard Spider attribution |
| CVE-2024-3400 | Palo Alto PAN-OS GlobalProtect — unauthenticated RCE | 10.0 | In CISA KEV, full pipeline verified |

---

## Why Agents?

**Separation of context windows** — Scout doesn't pollute the Adversary's reasoning with raw NVD JSON, and the Adversary's adversarial simulation doesn't bleed into Coroner's structured report writing.

**Model specialization** — Llama 3.3 70B for lateral adversarial reasoning; Qwen 2.5 72B for structured document synthesis. The right model for the right job.

**Independent failure isolation** — a noisy Scout run doesn't corrupt the IR report. Any single agent can be upgraded, fine-tuned, or swapped without touching the others.

**Auditability** — the Agent Trace tab shows every tool call, intermediate thought, and agent handoff. "Is this just a fancy prompt?" — no, show them the trace.

---

## Why AMD?

The MI300X's 192GB VRAM holds both 70B-class models in memory simultaneously. No model-swap overhead between agents. No OpenAI API key. No per-token billing. On-premises deployable — your threat intel never leaves your network. Cost per run: **$0.00**.

---

## License

MIT

---

*Built by **git happens** for the AMD x LabLab.ai Developer Hackathon, May 2026.*
*"Every CVE deserves an interrogation."*
