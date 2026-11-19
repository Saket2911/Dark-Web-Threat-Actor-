"""MITRE ATT&CK STIX 2.1 normalizer.

Converts STIX 2.1 objects into normalized dictionaries suitable for persistence
into the CTI platform's relational models.

Preserves all provenance information: original STIX ID, external references,
created/modified timestamps, revoked/deprecated status, and the complete raw
STIX object as raw_payload.
"""

from typing import Any, Dict, List, Optional


# STIX object type -> internal model name mapping
STIX_TYPE_MAP: Dict[str, str] = {
    "intrusion-set": "Actor",
    "campaign": "Campaign",
    "malware": "Malware",
    "tool": "Tool",
    "x-mitre-tactic": "Tactic",
    "attack-pattern": "Technique",
    "relationship": "Relationship",
}


def normalize_stix_object(obj: Any) -> Dict[str, Any]:
    """Normalize a single STIX 2.1 object into a normalized record dict.

    Args:
        obj: A STIX 2.1 object instance (dict from parsed JSON).

    Returns:
        A normalized dictionary with keys:
            - stix_type: Original STIX type
            - stix_id: Original STIX identifier
            - model_type: Internal model name (Actor, Campaign, etc.)
            - external_id: External ID (same as STIX ID for most types)
            - name: Object name
            - description: Object description
            - aliases: List of alias strings
            - created: Creation timestamp (ISO format or None)
            - modified: Modification timestamp (ISO format or None)
            - revoked: Revoked boolean
            - deprecated: Deprecated boolean
            - external_references: List of external reference dicts
            - kill_chain_phases: List of kill chain phase dicts (attack-pattern)
            - raw_payload: Full STIX object as JSON-serializable dict
            - model_type_mapping: How this STIX type maps to internal model
    """
    stix_type = obj.get("type", "")
    stix_id = obj.get("id", "")

    # Determine internal model mapping
    model_type = STIX_TYPE_MAP.get(stix_type, "unknown")

    # Extract aliases - STIX objects may have 'aliases' field or
    # x_mitre_aliases for MITRE-specific objects
    aliases = obj.get("aliases", []) or []

    # Extract external references
    external_refs = obj.get("external_references", []) or []

    # Extract kill chain phases for attack-pattern
    kill_chain_phases = obj.get("kill_chain_phases", []) or []

    # Extract timestamps
    created = obj.get("created")
    modified = obj.get("modified")

    # Extract revoked/deprecated status
    revoked = obj.get("revoked", False)
    deprecated = obj.get("deprecated", False)

    # Build full raw payload - JSON-serializable representation of the object
    raw_payload = _serialize_stix_object(obj)

    return {
        "stix_type": stix_type,
        "stix_id": stix_id,
        "model_type": model_type,
        "external_id": stix_id,
        "name": obj.get("name", ""),
        "description": obj.get("description", ""),
        "aliases": aliases,
        "created": created,
        "modified": modified,
        "revoked": bool(revoked),
        "deprecated": bool(deprecated),
        "external_references": external_refs,
        "kill_chain_phases": kill_chain_phases,
        "raw_payload": raw_payload,
        "model_type_mapping": STIX_TYPE_MAP.get(stix_type),
    }


def _serialize_stix_object(obj: Any) -> Dict[str, Any]:
    """Serialize a STIX object to a JSON-serializable dictionary.

    Handles stix2 objects which may have special serialization needs.
    If the input is already a plain dict (from JSON parsing), return it as-is.
    """
    # If it's already a plain dict, return it directly
    if isinstance(obj, dict):
        return dict(obj)
    # If it's a stix2 object with to_dict(), use that
    if hasattr(obj, "to_dict"):
        try:
            return obj.to_dict()
        except Exception:
            pass
    # Fallback: convert to dict via __dict__
    if hasattr(obj, "__dict__"):
        result = {}
        for key, value in obj.__dict__.items():
            if key.startswith("_"):
                continue
            if isinstance(value, (str, int, float, bool, type(None))):
                result[key] = value
            elif isinstance(value, list):
                result[key] = [
                    item.to_dict() if hasattr(item, "to_dict") else str(item)
                    for item in value
                ]
            elif isinstance(value, dict):
                result[key] = {
                    k: v.to_dict() if hasattr(v, "to_dict") else str(v)
                    for k, v in value.items()
                }
            else:
                result[key] = str(value)
        return result
    # Last resort: string representation
    return {"raw": str(obj)}


def normalize_stix_bundle(bundle_data: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a complete STIX 2.1 bundle.

    Args:
        bundle_data: Parsed STIX bundle JSON dict.

    Returns:
        A dict with normalized objects grouped by model type:
            {
                "actors": [...],
                "campaigns": [...],
                "malware": [...],
                "tools": [...],
                "tactics": [...],
                "techniques": [...],
                "relationships": [...],
                "unknown": [...],
                "bundle_metadata": {...}
            }
    """
    objects = bundle_data.get("objects", []) or []

    normalized = {
        "actors": [],
        "campaigns": [],
        "malware": [],
        "tools": [],
        "tactics": [],
        "techniques": [],
        "relationships": [],
        "unknown": [],
        "bundle_metadata": {
            "bundle_id": bundle_data.get("id", ""),
            "bundle_type": bundle_data.get("type", ""),
            "bundle_spec_version": bundle_data.get("spec_version", ""),
            "object_count": len(objects),
        },
    }

    for obj in objects:
        normalized_obj = normalize_stix_object(obj)
        model_type = normalized_obj["model_type"]

        if model_type == "Actor":
            normalized["actors"].append(normalized_obj)
        elif model_type == "Campaign":
            normalized["campaigns"].append(normalized_obj)
        elif model_type == "Malware":
            normalized["malware"].append(normalized_obj)
        elif model_type == "Tool":
            normalized["tools"].append(normalized_obj)
        elif model_type == "Tactic":
            normalized["tactics"].append(normalized_obj)
        elif model_type == "Technique":
            normalized["techniques"].append(normalized_obj)
        elif model_type == "Relationship":
            normalized["relationships"].append(normalized_obj)
        else:
            normalized["unknown"].append(normalized_obj)

    return normalized


def extract_technique_tactic_mapping(
    techniques: List[Dict[str, Any]],
    tactics: List[Dict[str, Any]],
) -> List[Dict[str, str]]:
    """Extract technique-to-tactic relationships from kill_chain_phases.

    ATT&CK techniques reference tactics through kill_chain_phases. This
    function builds mapping pairs that can be used to create
    technique-uses-tactic relationships.

    Args:
        techniques: List of normalized technique objects.
        tactics: List of normalized tactic objects.

    Returns:
        List of dicts with keys: technique_external_id, tactic_external_id,
        phase_name.
    """
    # Build tactic lookup by external_id (STIX ID)
    tactic_by_id = {
        t["external_id"]: t for t in tactics if t.get("external_id")
    }

    mappings = []
    for tech in techniques:
        for phase in tech.get("kill_chain_phases", []):
            phase_name = phase.get("phase_name", "")
            # The kill_chain_phase_name corresponds to tactic name,
            # not STIX ID. We need to match by name.
            for tactic in tactics:
                if tactic.get("name") == phase_name:
                    mappings.append({
                        "technique_external_id": tech["external_id"],
                        "tactic_external_id": tactic["external_id"],
                        "phase_name": phase_name,
                    })
                    break

    return mappings
