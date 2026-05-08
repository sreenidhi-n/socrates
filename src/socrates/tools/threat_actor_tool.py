"""Threat actor lookup tool for CrewAI.

Maps CVE context (affected vendor/product) to known threat actors
from a curated local lookup table.
"""

import json
from functools import lru_cache
from pathlib import Path

from crewai.tools import BaseTool

_DATA_FILE = Path(__file__).parent.parent / "data" / "threat_actors.json"


@lru_cache(maxsize=1)
def _load_actors() -> list[dict]:
    with open(_DATA_FILE) as f:
        return json.load(f)


class ThreatActorTool(BaseTool):
    """Look up threat actors known to target a specific vendor or product."""

    name: str = "threat_actor_lookup"
    description: str = (
        "Look up known threat actor groups (APTs, cybercriminal groups) that have "
        "targeted specific vendors, products, or sectors. "
        "Input should be a vendor name, product name, or sector "
        "(e.g., 'fortinet', 'palo alto', 'healthcare', 'cisco vpn'). "
        "Returns matching threat actor groups with their TTPs and notes."
    )

    def _run(self, query: str) -> str:
        """Find threat actors matching the query terms."""
        query_lower = query.lower()
        terms = [t.strip() for t in query_lower.replace(",", " ").split() if len(t.strip()) > 2]

        actors = _load_actors()
        matches: list[tuple[int, dict]] = []

        for actor in actors:
            score = 0
            searchable = " ".join([
                actor.get("name", ""),
                " ".join(actor.get("aliases", [])),
                " ".join(actor.get("sectors", [])),
                " ".join(actor.get("products", [])),
                actor.get("notes", ""),
            ]).lower()

            for term in terms:
                if term in searchable:
                    # Higher weight for product/sector hits
                    if any(term in p for p in actor.get("products", [])):
                        score += 3
                    elif any(term in s for s in actor.get("sectors", [])):
                        score += 2
                    else:
                        score += 1

            if score > 0:
                matches.append((score, actor))

        if not matches:
            return f"No known threat actors found for query: {query}"

        matches.sort(key=lambda x: x[0], reverse=True)
        top = matches[:4]  # top 4 matches

        lines = [
            f"**Threat Actors Associated with: {query}**\n"
            f"*(Based on publicly documented MITRE ATT&CK Group profiles and CISA advisories)*\n"
        ]
        for _, actor in top:
            name = actor["name"]
            aliases = ", ".join(actor.get("aliases", [])[:2])
            alias_str = f" ({aliases})" if aliases else ""
            ttps = ", ".join(actor.get("ttps", [])[:4])
            notes = actor.get("notes", "")
            lines.append(
                f"### {name}{alias_str} [{actor['id']}]\n"
                f"**Key TTPs:** {ttps}\n"
                f"**Profile:** {notes}\n"
            )

        return "\n".join(lines)
