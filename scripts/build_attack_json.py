#!/usr/bin/env python3
"""One-time script: download MITRE ATT&CK STIX bundle and build attack.json.

Fetches the enterprise-attack.json STIX bundle from the official MITRE CTI
GitHub repository, extracts all attack-pattern objects (techniques +
sub-techniques), and writes them to src/socrates/data/attack.json in the
format expected by MITREAttackTool.

Output format per technique:
  {
    "id": "T1190",
    "name": "Exploit Public-Facing Application",
    "tactic": "Initial Access",
    "description": "...",
    "detection": "..."
  }

Run once:
    python scripts/build_attack_json.py
"""

import json
import sys
from pathlib import Path

import httpx

STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
OUT_FILE = Path(__file__).parent.parent / "src" / "socrates" / "data" / "attack.json"

TACTIC_DISPLAY = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


def fetch_stix() -> dict:
    print(f"Downloading MITRE ATT&CK STIX bundle from GitHub (~35 MB)...")
    with httpx.stream("GET", STIX_URL, timeout=120.0, follow_redirects=True) as r:
        r.raise_for_status()
        chunks = []
        total = 0
        for chunk in r.iter_bytes(chunk_size=65536):
            chunks.append(chunk)
            total += len(chunk)
            print(f"\r  {total / 1_048_576:.1f} MB downloaded", end="", flush=True)
        print()
        return json.loads(b"".join(chunks))


def parse_techniques(stix: dict) -> list[dict]:
    techniques: list[dict] = []

    for obj in stix.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        # Extract ATT&CK ID from external_references
        tech_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id", "")
                break
        if not tech_id:
            continue

        name = obj.get("name", "")
        description = obj.get("description", "")
        # Trim overly long descriptions for token efficiency
        if len(description) > 600:
            description = description[:597] + "..."

        detection = obj.get("x_mitre_detection", "")
        if len(detection) > 400:
            detection = detection[:397] + "..."

        # Pick the first tactic from kill_chain_phases
        tactic = ""
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                raw = phase.get("phase_name", "")
                tactic = TACTIC_DISPLAY.get(raw, raw.replace("-", " ").title())
                break

        techniques.append({
            "id": tech_id,
            "name": name,
            "tactic": tactic,
            "description": description,
            "detection": detection,
        })

    # Sort: techniques before sub-techniques, then alphabetically by ID
    techniques.sort(key=lambda t: (
        "." in t["id"],   # sub-techniques after main techniques
        t["id"],
    ))
    return techniques


def main() -> None:
    stix = fetch_stix()
    techniques = parse_techniques(stix)

    # Stats
    main_techs = [t for t in techniques if "." not in t["id"]]
    sub_techs = [t for t in techniques if "." in t["id"]]
    print(f"Parsed {len(techniques)} techniques "
          f"({len(main_techs)} main + {len(sub_techs)} sub-techniques)")

    tactic_counts: dict[str, int] = {}
    for t in techniques:
        tactic_counts[t["tactic"]] = tactic_counts.get(t["tactic"], 0) + 1
    for tactic, count in sorted(tactic_counts.items()):
        print(f"  {tactic}: {count}")

    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_FILE, "w") as f:
        json.dump(techniques, f, indent=2)
    print(f"\nWrote {len(techniques)} techniques → {OUT_FILE}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(1)
