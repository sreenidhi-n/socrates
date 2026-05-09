"""The Adversary — Attack Path Simulator.

Takes vulnerability intel and reasons through how an attacker would exploit it.
Red team brain in a blue team body.
"""

from crewai import Agent, LLM

from socrates.config import LLAMA_BASE_URL, LLAMA_MODEL_NAME, VLLM_API_KEY
from socrates.tools.threat_actor_tool import ThreatActorTool


def create_adversary() -> Agent:
    """Create the Adversary agent for attack path simulation."""
    llm = LLM(
        model=f"openai/{LLAMA_MODEL_NAME}",
        base_url=LLAMA_BASE_URL,
        api_key=VLLM_API_KEY,
        max_retries=3,
    )

    return Agent(
        role="Attack Path Simulator",
        goal=(
            "Given a vulnerability, simulate the full attack path an adversary would take. "
            "Reason through each phase: initial access, execution, persistence, "
            "privilege escalation, lateral movement, and impact. "
            "Produce a kill chain with confidence scores for each step."
        ),
        backstory=(
            "You are a former red team operator turned blue team strategist. "
            "You think like an attacker but report like a defender. When you see a "
            "vulnerability, you don't just see a CVE number — you see the full kill chain. "
            "You can reason through how a skilled adversary would chain exploits, "
            "pivot through networks, and achieve their objectives. Your simulations "
            "have helped organizations patch the right things before attacks happen. "
            "You NEVER attempt actual exploitation — you simulate and reason only."
        ),
        llm=llm,
        tools=[ThreatActorTool()],
        verbose=True,
    )
