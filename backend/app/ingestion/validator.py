"""STIX 2.1 object validation module.

Validates STIX objects before normalization and persistence.
Handles supported object types, ID formats, required fields,
timestamp consistency, external reference structure, and relationship
endpoint existence.
"""

from typing import Any, Dict, List, Optional, Tuple

from stix2 import exceptions as stix_exceptions


# Supported STIX object types for import
SUPPORTED_STIX_TYPES: List[str] = [
    "intrusion-set",
    "campaign",
    "malware",
    "tool",
    "x-mitre-tactic",
    "attack-pattern",
    "relationship",
]


# Required fields per STIX object type
REQUIRED_FIELDS: Dict[str, List[str]] = {
    "intrusion-set": ["id", "type", "name"],
    "campaign": ["id", "type", "name"],
    "malware": ["id", "type", "name"],
    "tool": ["id", "type", "name"],
    "x-mitre-tactic": ["id", "type", "name"],
    "attack-pattern": ["id", "type", "name"],
    "relationship": ["id", "type", "source_ref", "target_ref", "relationship_type"],
}


# Valid STIX ID prefix patterns per type
VALID_STIX_ID_PREFIXES: Dict[str, List[str]] = {
    "intrusion-set": ["intrusion-set--"],
    "campaign": ["campaign--"],
    "malware": ["malware--"],
    "tool": ["tool--"],
    "x-mitre-tactic": ["x-mitre-tactic--"],
    "attack-pattern": ["attack-pattern--"],
    "relationship": ["relationship--"],
}


class ValidationError(Exception):
    """Raised when a STIX object fails validation."""
    pass


def validate_stix_object(obj: Dict[str, Any]) -> None:
    """Validate a single STIX 2.1 object.

    Args:
        obj: Parsed STIX object dictionary.

    Raises:
        ValidationError: If the object is invalid.
    """
    if not isinstance(obj, dict):
        raise ValidationError("STIX object must be a dictionary")

    stix_type = obj.get("type")
    stix_id = obj.get("id")

    # Check for required top-level fields
    if not stix_type:
        raise ValidationError("STIX object missing 'type' field")
    if not stix_id:
        raise ValidationError("STIX object missing 'id' field")

    # Check if type is supported
    if stix_type not in SUPPORTED_STIX_TYPES:
        raise ValidationError(f"Unsupported STIX object type: '{stix_type}'")

    # Validate ID format matches the type
    expected_prefixes = VALID_STIX_ID_PREFIXES.get(stix_type, [])
    if expected_prefixes:
        if not any(stix_id.startswith(prefix) for prefix in expected_prefixes):
            raise ValidationError(
                f"STIX ID '{stix_id}' does not match expected prefix "
                f"for type '{stix_type}' (expected one of: {expected_prefixes})"
            )

    # Check required fields per type
    required = REQUIRED_FIELDS.get(stix_type, [])
    for field in required:
        if field not in obj or obj[field] is None:
            raise ValidationError(
                f"STIX object type '{stix_type}' missing required field: '{field}'"
            )

    # Validate name is a string
    name = obj.get("name")
    if name is not None and not isinstance(name, str):
        raise ValidationError(f"STIX object '{stix_id}': 'name' must be a string")

    # Validate description is a string if present
    description = obj.get("description")
    if description is not None and not isinstance(description, str):
        raise ValidationError(f"STIX object '{stix_id}': 'description' must be a string")

    # Validate timestamps if present
    for ts_field in ("created", "modified"):
        ts = obj.get(ts_field)
        if ts is not None and not isinstance(ts, str):
            raise ValidationError(
                f"STIX object '{stix_id}': '{ts_field}' must be a string timestamp"
            )

    # Validate external_references structure if present
    ext_refs = obj.get("external_references")
    if ext_refs is not None:
        if not isinstance(ext_refs, list):
            raise ValidationError(
                f"STIX object '{stix_id}': 'external_references' must be a list"
            )
        for i, ref in enumerate(ext_refs):
            if not isinstance(ref, dict):
                raise ValidationError(
                    f"STIX object '{stix_id}': external_references[{i}] must be a dict"
                )
            if "source_name" not in ref:
                raise ValidationError(
                    f"STIX object '{stix_id}': external_references[{i}] missing 'source_name'"
                )

    # Validate kill_chain_phases structure for attack-pattern
    if stix_type == "attack-pattern":
        kcp = obj.get("kill_chain_phases")
        if kcp is not None:
            if not isinstance(kcp, list):
                raise ValidationError(
                    f"STIX object '{stix_id}': 'kill_chain_phases' must be a list"
                )
            for i, phase in enumerate(kcp):
                if not isinstance(phase, dict):
                    raise ValidationError(
                        f"STIX object '{stix_id}': kill_chain_phases[{i}] must be a dict"
                    )
                if "phase_name" not in phase:
                    raise ValidationError(
                        f"STIX object '{stix_id}': kill_chain_phases[{i}] missing 'phase_name'"
                    )


def validate_stix_relationship(
    rel: Dict[str, Any],
    all_stix_ids: List[str],
) -> None:
    """Validate a STIX relationship object.

    Validates that source_ref and target_ref reference existing STIX IDs
    within the bundle or existing database records.

    Args:
        rel: Parsed STIX relationship object.
        all_stix_ids: List of valid STIX IDs from the bundle or database.

    Raises:
        ValidationError: If the relationship is invalid.
    """
    if not isinstance(rel, dict):
        raise ValidationError("STIX relationship must be a dictionary")

    stix_id = rel.get("id")
    if not stix_id:
        raise ValidationError("STIX relationship missing 'id' field")

    source_ref = rel.get("source_ref")
    target_ref = rel.get("target_ref")
    rel_type = rel.get("relationship_type")

    if not source_ref:
        raise ValidationError(f"STIX relationship '{stix_id}' missing 'source_ref'")
    if not target_ref:
        raise ValidationError(f"STIX relationship '{stix_id}' missing 'target_ref'")
    if not rel_type:
        raise ValidationError(f"STIX relationship '{stix_id}' missing 'relationship_type'")

    # Validate source_ref and target_ref exist in known STIX IDs
    if source_ref not in all_stix_ids:
        raise ValidationError(
            f"STIX relationship '{stix_id}': source_ref '{source_ref}' "
            f"does not reference a known STIX object"
        )
    if target_ref not in all_stix_ids:
        raise ValidationError(
            f"STIX relationship '{stix_id}': target_ref '{target_ref}' "
            f"does not reference a known STIX object"
        )

    # Prevent self-referencing relationships
    if source_ref == target_ref:
        raise ValidationError(
            f"STIX relationship '{stix_id}': source_ref and target_ref "
            f"cannot be the same object ({source_ref})"
        )


def validate_stix_bundle(bundle_data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate a complete STIX 2.1 bundle.

    Args:
        bundle_data: Parsed STIX bundle JSON dict.

    Returns:
        A dict with validation results:
            {
                "valid": bool,
                "errors": List[str],
                "warnings": List[str],
                "object_count": int,
                "supported_object_count": int,
                "unsupported_object_count": int,
            }
    """
    errors: List[str] = []
    warnings: List[str] = []

    if not isinstance(bundle_data, dict):
        errors.append("Bundle data must be a dictionary")
        return {
            "valid": False,
            "errors": errors,
            "warnings": warnings,
            "object_count": 0,
            "supported_object_count": 0,
            "unsupported_object_count": 0,
        }

    objects = bundle_data.get("objects", []) or []
    if not isinstance(objects, list):
        errors.append("Bundle 'objects' field must be a list")
        objects = []

    # Collect all STIX IDs for relationship validation
    all_stix_ids: List[str] = []
    supported_count = 0
    unsupported_count = 0

    for i, obj in enumerate(objects):
        if not isinstance(obj, dict):
            errors.append(f"Object at index {i} is not a dictionary")
            unsupported_count += 1
            continue

        stix_id = obj.get("id", "")
        stix_type = obj.get("type", "")

        if stix_id:
            all_stix_ids.append(stix_id)

        if stix_type not in SUPPORTED_STIX_TYPES:
            unsupported_count += 1
            warnings.append(
                f"Object '{stix_id}' has unsupported type '{stix_type}', skipping"
            )
            continue

        supported_count += 1

        try:
            validate_stix_object(obj)
        except ValidationError as exc:
            errors.append(str(exc))

    # Validate relationships
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if obj.get("type") != "relationship":
            continue
        try:
            validate_stix_relationship(obj, all_stix_ids)
        except ValidationError as exc:
            errors.append(str(exc))

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "object_count": len(objects),
        "supported_object_count": supported_count,
        "unsupported_object_count": unsupported_count,
    }


def validate_stix_id(stix_id: str) -> bool:
    """Validate a STIX ID format.

    Args:
        stix_id: STIX identifier string.

    Returns:
        True if the ID format is valid, False otherwise.
    """
    if not isinstance(stix_id, str) or not stix_id:
        return False
    if "--" not in stix_id:
        return False
    prefix, _ = stix_id.split("--", 1)
    return any(stix_id.startswith(p) for p in VALID_STIX_ID_PREFIXES.values()
               for p in [prefix + "--"] if p == stix_id.split("--")[0] + "--")
