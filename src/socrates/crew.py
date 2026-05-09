"""SOCrates Crew — The autonomous SOC analyst pipeline.

Orchestrates Scout → Adversary → Coroner in a sequential pipeline.
"""

import queue
import re
import threading
from collections.abc import Generator
from typing import Any, Optional

from crewai import Crew, Task

from socrates.agents.coroner import create_coroner
from socrates.agents.adversary import create_adversary
from socrates.agents.scout import create_scout

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# CrewAI injects "JUST THE FINAL ANSWER IN THE REQUIRED FORMAT:" into task prompts.
# Smaller LLMs sometimes echo this boilerplate at the start of their response.
# Strip everything up to and including that marker.
_BOILERPLATE_RE = re.compile(
    r".*?JUST THE FINAL ANSWER IN THE REQUIRED FORMAT:\s*",
    re.DOTALL | re.IGNORECASE,
)

# Map tool names to human-readable narrative labels
_TOOL_LABELS = {
    "nvd_cve_search": "NVD API",
    "mitre_attack_lookup": "MITRE ATT&CK",
    "threat_actor_lookup": "Threat Actor DB",
}

# Map agent role substrings to display names
_AGENT_LABELS = {
    "scout": "🔍 Scout",
    "attack path": "☠️ Adversary",
    "incident": "📋 Coroner",
    "coroner": "📋 Coroner",
    "adversary": "☠️ Adversary",
}


def _clean_output(text: str) -> str:
    """Strip CrewAI boilerplate that models sometimes echo at the start of their response."""
    cleaned = _BOILERPLATE_RE.sub("", text, count=1)
    return cleaned.strip() if cleaned.strip() else text.strip()


def _agent_label(output: Any) -> str:
    """Try to extract a friendly agent name from the step output."""
    try:
        agent_str = str(getattr(output, "agent", "") or "").lower()
        for key, label in _AGENT_LABELS.items():
            if key in agent_str:
                return label
    except Exception:
        pass
    return "Agent"


def _format_step(output: Any) -> str:
    """Format a CrewAI step output as a readable narrative trace line."""
    try:
        if hasattr(output, "tool") and hasattr(output, "tool_input"):
            tool_name = getattr(output, "tool", "tool")
            tool_input = str(getattr(output, "tool_input", "")).strip()[:120]
            label = _TOOL_LABELS.get(tool_name, tool_name)
            agent = _agent_label(output)

            # Extract a one-line thought if present (first non-empty line)
            log = _ANSI_RE.sub("", getattr(output, "log", "") or "").strip()
            thought_lines = [l.strip() for l in log.splitlines() if l.strip()]
            thought = thought_lines[0][:200] if thought_lines else ""

            text = f"{agent} → calling **{label}** with `{tool_input}`"
            if thought:
                text += f"\n  _{thought}_"

        elif hasattr(output, "return_values"):
            agent = _agent_label(output)
            # Show a short preview of the result, not the whole thing
            val = str(output.return_values).strip()
            val = _ANSI_RE.sub("", val)
            preview = val[:300].replace("\n", " ")
            text = f"{agent} → ✅ **done** — _{preview}{'...' if len(val) > 300 else ''}_"

        else:
            # Raw string output — clean and truncate
            raw = _ANSI_RE.sub("", str(output)).strip()
            # Skip pure ANSI noise and raw CrewAI object reprs (ToolResult,
            # AgentFinish) — these duplicate info already shown in formatted lines
            if not raw or len(raw) < 5:
                return ""
            if raw.startswith(("ToolResult(", "AgentFinish(", "AgentAction(")):
                return ""
            text = raw[:400]

    except Exception:
        text = _ANSI_RE.sub("", str(output))[:400]

    return text.strip()


def build_crew(
    cve_query: str,
    task_callback: Optional[Any] = None,
    step_callback: Optional[Any] = None,
) -> Crew:
    """Build the SOCrates crew for a given CVE query.

    Args:
        cve_query: A CVE ID (e.g., 'CVE-2024-3400') or search keyword.

    Returns:
        A configured CrewAI Crew ready to execute.
    """
    # Create agents
    scout = create_scout()
    adversary = create_adversary()
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
            "**Step 0 — Threat Actor Profiling:**\n"
            "Use the threat_actor_lookup tool with the affected vendor/product name from Scout's brief "
            "(e.g., 'fortinet', 'palo alto', 'cisco', 'microsoft exchange'). "
            "Include a **Threat Actor Context** section at the top of your kill chain. "
            "List which APT groups and criminal actors are associated with this vendor/product "
            "based on their documented MITRE ATT&CK profiles — note their typical objectives "
            "(espionage vs. ransomware vs. destructive) and how that shapes likely post-exploitation goals.\n\n"
            "Walk through each phase of the kill chain:\n"
            "1. **Initial Access** — How would an attacker first exploit this vulnerability?\n"
            "2. **Execution** — What would they execute on the target system?\n"
            "3. **Persistence** — How would they maintain access?\n"
            "4. **Privilege Escalation** — How would they elevate permissions?\n"
            "5. **Lateral Movement** — How would they spread through the network?\n"
            "6. **Impact** — What is the worst-case outcome?\n\n"
            "**CVE Chaining:**\n"
            "After the kill chain phases, add a **Chained Attack Scenarios** section. "
            "Reason about what class of secondary vulnerability an attacker would chain next — "
            "for example: after gaining a web shell on a perimeter appliance, what local privilege "
            "escalation CVEs would they look for? What lateral movement vectors does this initial "
            "foothold enable? Be specific about the post-exploitation objectives.\n\n"
            "For each kill chain step, provide:\n"
            "- The specific technique or method\n"
            "- **Real-world tools** an adversary would use at this step — name them explicitly "
            "(e.g. Sliver, Cobalt Strike, Metasploit, Mimikatz, CrackMapExec, Impacket, "
            "BloodHound, Chisel, frp, nc, curl, wget, PowerShell Empire, etc.)\n"
            "- Confidence level (HIGH/MEDIUM/LOW) that this step is feasible\n"
            "- Prerequisites for this step\n\n"
            "Think like an attacker. Be specific and realistic — name the tools, name the commands."
        ),
        expected_output=(
            "A detailed simulated kill chain in Markdown format with each phase, "
            "specific techniques, confidence scores, and prerequisites."
        ),
        agent=adversary,
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
            "5. **Detection Rules** — Write ONE valid Sigma detection rule targeting the most\n"
            "   detectable step of the kill chain (e.g. initial exploitation, web shell drop,\n"
            "   or reverse shell callback). The rule MUST be valid Sigma YAML inside a\n"
            "   fenced code block and include ALL of these fields:\n"
            "   ```yaml\n"
            "   title: <specific descriptive title for this CVE>\n"
            "   id: <generate a random UUID v4, e.g. 3f4a1b2c-d5e6-7890-abcd-ef1234567890>\n"
            "   status: experimental\n"
            "   description: <one sentence on what this detects>\n"
            "   references:\n"
            "       - https://nvd.nist.gov/vuln/detail/<CVE-ID>\n"
            "   author: SOCrates\n"
            "   tags:\n"
            "       - attack.<technique_id_lowercase>   # ONLY technique IDs, e.g. attack.t1190\n"
            "       # DO NOT use tactic names like attack.initial_access — those are invalid\n"
            "   logsource:\n"
            "       product: <vendor product>      # e.g. palo-alto, fortinet, windows\n"
            "       service: <service>             # e.g. globalprotect, firewall, sysmon\n"
            "   detection:\n"
            "       selection:\n"
            "           <FieldName>: '<specific value matching exploitation pattern>'\n"
            "       condition: selection\n"
            "   falsepositives:\n"
            "       - Unknown\n"
            "   level: critical\n"
            "   ```\n"
            "   Base the detection fields on the CVE's actual exploitation pattern from\n"
            "   Scout's intel — not generic placeholders.\n"
            "6. **Remediation Steps** — Priority-ordered actions. For EACH step, prefix it with "
            "an effort/impact label using this format:\n"
            "   - 🟢 **Quick win (< 1 hr):** <action> — e.g. apply vendor patch, block IP\n"
            "   - 🟡 **Medium effort (2–8 hrs):** <action> — e.g. rotate credentials, audit logs\n"
            "   - 🔴 **Heavy lift (days):** <action> — e.g. network re-segmentation, full rebuild\n"
            "   Order by: quick wins first, then medium, then heavy. At least 5 steps total.\n"
            "7. **References** — Links to advisories and resources\n\n"
            "Write for both technical and executive audiences. Be actionable.\n"
            "Cross-check the Adversary's kill chain against Scout's reported attackVector and\n"
            "privilegesRequired — flag any inconsistencies explicitly."
        ),
        expected_output=(
            "A complete incident response report in Markdown format with MITRE ATT&CK "
            "mappings, one valid Sigma YAML detection rule, and remediation steps."
        ),
        agent=coroner,
    )

    # Build the crew
    crew = Crew(
        agents=[scout, adversary, coroner],
        tasks=[intel_task, killchain_task, report_task],
        verbose=True,
        task_callback=task_callback,
        step_callback=step_callback,
    )

    return crew


def run(cve_query: str) -> str:
    """Run the full SOCrates pipeline and return the final IR report."""
    crew = build_crew(cve_query)
    result = crew.kickoff()
    return str(result)


def run_detailed(cve_query: str) -> tuple[str, str, str]:
    """Run the full SOCrates pipeline and return each agent's output separately.

    Returns:
        Tuple of (scout_intel, kill_chain, ir_report)
    """
    crew = build_crew(cve_query)
    result = crew.kickoff()
    outputs = result.tasks_output or []

    def _get(idx: int) -> str:
        return str(outputs[idx]) if idx < len(outputs) else ""

    return _get(0), _get(1), _get(2)


def run_streaming(
    cve_query: str,
) -> Generator[tuple[str, str, str, dict | None, str], None, None]:
    """Run the pipeline, yielding (scout, adversary, coroner, metrics, trace) as agents work.

    - First three elements update when each agent's task completes.
    - Fourth element is None during the run, then a metrics dict on the final yield.
    - Fifth element is the accumulated agent reasoning trace, updated on every step.
    """
    import time as _time

    q: queue.Queue = queue.Queue()
    outputs = ["", "", ""]
    completed = 0
    trace_lines: list[str] = []

    _HANDOFF_MSGS = [
        "🔍 **Scout** finished intel gathering → handing brief to ☠️ Adversary",
        "☠️ **Adversary** finished kill chain simulation → handing to 📋 Coroner",
        "📋 **Coroner** finished IR report → analysis complete ✅",
    ]

    def _on_task(task_output: Any) -> None:
        nonlocal completed
        # Use .raw for full output — str(TaskOutput) returns a truncated summary
        content = _clean_output(getattr(task_output, "raw", None) or str(task_output))
        handoff = _HANDOFF_MSGS[completed] if completed < len(_HANDOFF_MSGS) else ""
        q.put({"type": "task", "content": content, "handoff": handoff})

    def _on_step(step_output: Any) -> None:
        line = _format_step(step_output)
        if line:
            q.put({"type": "trace", "line": line})

    def _run() -> None:
        start = _time.perf_counter()
        try:
            crew = build_crew(cve_query, task_callback=_on_task, step_callback=_on_step)
            result = crew.kickoff()
            elapsed = _time.perf_counter() - start
            tokens = 0
            if hasattr(result, "token_usage") and result.token_usage:
                tokens = getattr(result.token_usage, "total_tokens", 0)
            # Capture definitive full outputs from kickoff result — task_callback
            # may receive truncated TaskOutput objects depending on CrewAI version
            final_outputs = []
            for to in result.tasks_output or []:
                final_outputs.append(_clean_output(getattr(to, "raw", None) or str(to)))
            q.put({"type": "metrics", "elapsed": elapsed, "tokens": tokens,
                   "final_outputs": final_outputs})
        except Exception as exc:
            q.put(exc)
        finally:
            q.put(None)  # sentinel — always fires

    threading.Thread(target=_run, daemon=True).start()

    while True:
        try:
            item = q.get(timeout=300)  # 5 min max per agent
        except queue.Empty:
            break

        if item is None:
            break

        if isinstance(item, BaseException):
            raise item

        trace_str = "\n\n---\n\n".join(trace_lines)
        item_type = item.get("type") if isinstance(item, dict) else None

        if item_type == "trace":
            trace_lines.append(item["line"])
            trace_str = "\n\n---\n\n".join(trace_lines)
            yield (outputs[0], outputs[1], outputs[2], None, trace_str)

        elif item_type == "task":
            handoff = item.get("handoff", "")
            if handoff:
                trace_lines.append(handoff)
            outputs[completed] = item["content"]
            completed += 1
            trace_str = "\n\n---\n\n".join(trace_lines)
            yield (outputs[0], outputs[1], outputs[2], None, trace_str)

        elif item_type == "metrics":
            # Override with definitive full content from kickoff result
            for i, content in enumerate(item.get("final_outputs") or []):
                if i < len(outputs) and content:
                    outputs[i] = content
            yield (outputs[0], outputs[1], outputs[2], item, trace_str)


if __name__ == "__main__":
    import sys

    query = sys.argv[1] if len(sys.argv) > 1 else "CVE-2024-3400"
    print(f"\n🏛️ SOCrates analyzing: {query}\n")
    report = run(query)
    print("\n" + "=" * 80)
    print(report)
