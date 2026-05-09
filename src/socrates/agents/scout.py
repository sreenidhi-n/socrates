"""The Scout — Threat Intelligence Collector.

Pulls CVE data from NVD, structures it into actionable threat intel.
The analyst who reads every feed at 6am and highlights the scary ones.
"""

from crewai import Agent, LLM

from socrates.config import LLAMA_BASE_URL, LLAMA_MODEL_NAME, VLLM_API_KEY
from socrates.tools.nvd_tool import NVDSearchTool


def create_scout() -> Agent:
    """Create the Scout agent for threat intelligence collection."""
    llm = LLM(
        model=f"openai/{LLAMA_MODEL_NAME}",
        base_url=LLAMA_BASE_URL,
        api_key=VLLM_API_KEY,
        max_retries=3,
    )

    return Agent(
        role="Threat Intelligence Analyst",
        goal=(
            "Collect and structure vulnerability intelligence from the NVD database. "
            "Identify critical details: CVE ID, CVSS score, affected systems, "
            "exploit availability, and attack vector. Prioritize by severity."
        ),
        backstory=(
            "You are a senior threat intelligence analyst at a world-class SOC. "
            "Every morning you scan vulnerability feeds before anyone else is awake. "
            "You have an uncanny ability to spot the CVEs that will actually matter — "
            "the ones that attackers will weaponize within days. You structure your "
            "findings clearly so the red team and IR team can act on them immediately."
        ),
        llm=llm,
        tools=[NVDSearchTool()],
        verbose=True,
    )
