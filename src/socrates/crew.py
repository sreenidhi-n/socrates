"""SOCrates Crew — The autonomous SOC analyst pipeline.

Orchestrates Scout → Chaos Gremlin → Coroner in a sequential pipeline.
"""

from crewai import Crew, Task

from socrates.agents.coroner import create_coroner
from socrates.agents.gremlin import create_gremlin
from socrates.agents.scout import create_scout


def build_crew(cve_query: str) -> Crew:
    """Build the SOCrates crew for a given CVE query.

    Args:
        cve_query: A CVE ID (e.g., 'CVE-2024-3400') or search keyword.

    Returns:
        A configured CrewAI Crew ready to execute.
    """
    # Create agents
    scout = create_scout()
    gremlin = create_gremlin()
    coroner = create_coroner()

    # Define tasks
    intel_task = Task(
        description=(
            f"Research the following vulnerability: {cve_query}\n\n"
            "Use the NVD search tool to pull the full CVE details. "
            "Structure your findings into a threat intelligence brief including:\n"
            "- CVE ID and CVSS score\n"
            "- Severity assessment\n"
            "- Attack vector and complexity\n"
            "- Affected systems and products\n"
            "- Whether public exploits are available\n"
            "- Key references and advisories\n\n"
            "Be thorough — the attack simulation team depends on your intel."
        ),
        expected_output=(
            "A structured threat intelligence brief in Markdown format with all "
            "available CVE details, severity assessment, and affected systems."
        ),
        agent=scout,
    )

    killchain_task = Task(
        description=(
            "Based on the threat intelligence brief provided by the Scout, "
            "simulate a realistic attack path that an adversary would take to exploit "
            "this vulnerability.\n\n"
            "Walk through each phase of the kill chain:\n"
            "1. **Initial Access** — How would an attacker first exploit this vulnerability?\n"
            "2. **Execution** — What would they execute on the target system?\n"
            "3. **Persistence** — How would they maintain access?\n"
            "4. **Privilege Escalation** — How would they elevate permissions?\n"
            "5. **Lateral Movement** — How would they spread through the network?\n"
            "6. **Impact** — What is the worst-case outcome?\n\n"
            "For each step, provide:\n"
            "- The specific technique or method\n"
            "- Confidence level (HIGH/MEDIUM/LOW) that this step is feasible\n"
            "- Prerequisites for this step\n\n"
            "Think like an attacker. Be specific and realistic."
        ),
        expected_output=(
            "A detailed simulated kill chain in Markdown format with each phase, "
            "specific techniques, confidence scores, and prerequisites."
        ),
        agent=gremlin,
    )

    report_task = Task(
        description=(
            "Based on the threat intelligence brief and the simulated kill chain, "
            "produce a professional incident response report.\n\n"
            "The report must include:\n"
            "1. **Executive Summary** — 2-3 sentence overview for leadership\n"
            "2. **Vulnerability Details** — CVE info, CVSS, affected systems\n"
            "3. **Attack Path Analysis** — The kill chain mapped to MITRE ATT&CK techniques\n"
            "   - Use the MITRE ATT&CK lookup tool to find matching techniques\n"
            "   - Map each kill chain step to specific ATT&CK technique IDs\n"
            "4. **Impact Assessment** — Blast radius, potential damage\n"
            "5. **Detection Recommendations** — How to detect this attack\n"
            "   - Include pseudo-detection rules (Sigma-style or YARA-style)\n"
            "6. **Remediation Steps** — Priority-ordered actions to take\n"
            "7. **References** — Links to advisories and resources\n\n"
            "Write for both technical and executive audiences. Be actionable."
        ),
        expected_output=(
            "A complete incident response report in Markdown format with MITRE ATT&CK "
            "mappings, detection rules, and remediation recommendations."
        ),
        agent=coroner,
    )

    # Build the crew
    crew = Crew(
        agents=[scout, gremlin, coroner],
        tasks=[intel_task, killchain_task, report_task],
        verbose=True,
    )

    return crew


def run(cve_query: str) -> str:
    """Run the full SOCrates pipeline for a CVE query.

    Args:
        cve_query: A CVE ID or search keyword.

    Returns:
        The final incident response report as a string.
    """
    crew = build_crew(cve_query)
    result = crew.kickoff()
    return str(result)


if __name__ == "__main__":
    import sys

    query = sys.argv[1] if len(sys.argv) > 1 else "CVE-2024-3400"
    print(f"\n🏛️ SOCrates analyzing: {query}\n")
    report = run(query)
    print("\n" + "=" * 80)
    print(report)
