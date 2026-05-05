# SOCrates — Claude Code Context

## What is this?
SOCrates is an autonomous SOC (Security Operations Center) analyst.
Multi-agent system: CVE drops → kill chain simulated → IR report generated.
Built for AMD x LabLab.ai Developer Hackathon (May 9-10, 2026).
Team: "git happens"

## Tech stack
- **Orchestration:** CrewAI
- **Models:** Llama (Scout + Gremlin) + Qwen (Coroner) via vLLM on AMD MI300X
- **Threat intel:** NVD REST API (nvd.nist.gov)
- **MITRE mapping:** ATT&CK STIX JSON (local subset)
- **Frontend:** Gradio (deployed as HF Space)
- **Infra:** AMD Developer Cloud (DigitalOcean GPU Droplets, vLLM Quick Start image)

## Architecture
CrewAI crew with 3 agents + coordinator (sequential pipeline):
1. **Scout** — pulls CVE data from NVD API, structures threat intel
2. **Chaos Gremlin** — simulates attack path reasoning, generates kill chain
3. **Coroner** — maps to MITRE ATT&CK, writes IR report

Pipeline: Scout → Gremlin → Coroner

## Key files
- `src/socrates/crew.py` — main crew definition, agent wiring
- `src/socrates/agents/` — individual agent definitions (scout.py, gremlin.py, coroner.py)
- `src/socrates/tools/` — CrewAI tools (nvd_tool.py, mitre_tool.py, cve_parser.py)
- `src/socrates/config.py` — model endpoints, API keys, all settings
- `app.py` — Gradio frontend (HF Space entry point)
- `scripts/` — cloud setup and model serving shell scripts

## Model connectivity
Models are served via vLLM on AMD cloud, exposed as OpenAI-compatible endpoints.
CrewAI connects using:
```python
from crewai import LLM
llama = LLM(model="openai/llama", base_url=os.getenv("LLAMA_BASE_URL"), api_key=os.getenv("VLLM_API_KEY"))
qwen = LLM(model="openai/qwen", base_url=os.getenv("QWEN_BASE_URL"), api_key=os.getenv("VLLM_API_KEY"))
```

## Environment variables (see .env.example)
- `LLAMA_BASE_URL` — vLLM endpoint for Llama (e.g., http://<ip>:8000/v1)
- `QWEN_BASE_URL` — vLLM endpoint for Qwen (e.g., http://<ip>:8090/v1)
- `VLLM_API_KEY` — API key for vLLM instances
- `NVD_API_KEY` — optional, for higher NVD rate limits

## Conventions
- Python 3.11+
- Use `uv` for package management if available, otherwise pip
- Type hints on all functions
- Docstrings on all public functions
- Output reports as Markdown
- Keep agent prompts in their respective agent files (not a separate prompts dir)

## What NOT to do
- Don't hardcode model endpoints — always use config.py / env vars
- Don't fine-tune anything — use base models as-is
- Don't build a fancy frontend — Gradio with tabs is enough
- Don't scrape Reddit/HN — NVD API is the only external data source
- Don't attempt actual exploitation or scanning — simulation/reasoning only
- Don't add unnecessary dependencies — keep it lean

## Hackathon context
- Full planning docs are in the Obsidian vault at:
  `/Users/Sreenidhi/Desktop/C2-Vault/Hackathons/AMD-LabLab-May2026/`
- Files: 00-idea-sketch.md, 01-submission-checklist.md, 02-implementation-plan.md
