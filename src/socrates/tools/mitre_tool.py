"""MITRE ATT&CK lookup tool for CrewAI.

Provides technique lookups from a local subset of the ATT&CK framework.
Uses a curated JSON of common techniques to avoid loading the full STIX bundle.
"""

import json
import os

from crewai.tools import BaseTool

from socrates.config import MITRE_DATA_PATH


class MITRELookupTool(BaseTool):
    """Look up MITRE ATT&CK techniques by keyword or technique ID."""

    name: str = "mitre_attack_lookup"
    description: str = (
        "Search MITRE ATT&CK techniques by keyword or technique ID (e.g., 'T1190' or 'initial access'). "
        "Returns technique details including tactic, description, and detection guidance. "
        "Use this to map attack steps to the ATT&CK framework."
    )

    def _run(self, query: str) -> str:
        """Look up MITRE ATT&CK techniques."""
        if not os.path.exists(MITRE_DATA_PATH):
            return (
                "MITRE ATT&CK data not found. Using built-in knowledge to map techniques. "
                "Please ensure attack.json is in the data directory."
            )

        with open(MITRE_DATA_PATH) as f:
            techniques = json.load(f)

        query_lower = query.lower().strip()
        keywords = [w for w in query_lower.split() if len(w) > 2]
        scored: list[tuple[int, dict]] = []

        for tech in techniques:
            tech_id = tech.get("id", "").lower()
            name = tech.get("name", "").lower()
            tactic = tech.get("tactic", "").lower()
            description = tech.get("description", "").lower()
            detection = tech.get("detection", "").lower()

            score = 0

            # Exact technique ID match — highest priority
            if query_lower == tech_id:
                score = 1000
            elif query_lower in tech_id:
                score = 500
            # Exact phrase in name or tactic — high priority
            elif query_lower in name:
                score = 200
            elif query_lower in tactic:
                score = 150
            else:
                if not keywords:
                    continue
                # All keywords must be present somewhere
                combined = f"{tech_id} {name} {tactic} {description} {detection}"
                if not all(kw in combined for kw in keywords):
                    continue

                # Score: weight tactic and name matches more than description hits
                for kw in keywords:
                    if kw in tactic:
                        score += 30
                    if kw in name:
                        score += 20
                    if kw in description:
                        score += 5
                    if kw in detection:
                        score += 3

            if score > 0:
                scored.append((score, tech))

        if not scored:
            return f"No MITRE ATT&CK techniques found for: {query}. Try a broader search term."

        scored.sort(key=lambda x: x[0], reverse=True)

        results = []
        for _, tech in scored[:10]:
            result = (
                f"**{tech.get('id', 'N/A')} — {tech.get('name', 'Unknown')}**\n"
                f"  Tactic: {tech.get('tactic', 'N/A')}\n"
                f"  Description: {tech.get('description', 'N/A')}\n"
                f"  Detection: {tech.get('detection', 'N/A')}\n"
            )
            results.append(result)

        return "\n".join(results)
