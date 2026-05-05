# 🏛️ SOCrates

> *The wisest analyst in your SOC — and it never sleeps.*

**SOCrates** is an autonomous Security Operations Center analyst powered by multi-agent AI. It takes a CVE, reasons through the attack path, maps it to MITRE ATT&CK, and generates a full incident response report — with zero human in the loop.

Built for the [AMD x LabLab.ai Developer Hackathon](https://lablab.ai/ai-hackathons/amd-developer) (May 2026) by **git happens**.

## How it works

```
CVE Published → Scout → Chaos Gremlin → Coroner → Threat Briefing
```

1. **The Scout** — Pulls threat intelligence from NVD/CVE feeds. Structures vulnerability data.
2. **The Chaos Gremlin** — Simulates attacker reasoning. Generates a kill chain with attack paths.
3. **The Coroner** — Maps the kill chain to MITRE ATT&CK. Writes the incident response report.

All orchestrated by CrewAI, running on open-source models (Llama + Qwen) on AMD Instinct MI300X GPUs.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Orchestration | [CrewAI](https://github.com/crewAIInc/crewAI) |
| Models | Llama 3.x + Qwen 3.x via [vLLM](https://docs.vllm.ai/) |
| Compute | AMD Developer Cloud (Instinct MI300X, ROCm) |
| Threat Intel | [NVD REST API](https://nvd.nist.gov/) |
| MITRE Mapping | ATT&CK STIX data |
| Frontend | Gradio |

## Quick Start

```bash
# Clone
git clone https://github.com/<your-username>/socrates.git
cd socrates

# Install deps
pip install -e .

# Copy env template and configure
cp .env.example .env
# Edit .env with your vLLM endpoints

# Run the pipeline
python -m socrates.crew

# Or launch the Gradio UI
python app.py
```

## Project Structure

```
socrates/
├── CLAUDE.md              # Claude Code project context
├── src/socrates/
│   ├── config.py          # Settings + model endpoints
│   ├── crew.py            # CrewAI orchestrator
│   ├── agents/            # Scout, Gremlin, Coroner
│   └── tools/             # NVD API, MITRE lookup
├── app.py                 # Gradio frontend
├── scripts/               # Cloud setup scripts
└── docs/                  # Architecture + demo docs
```

## License

MIT

---

*"The unexamined vulnerability is not worth ignoring."*
