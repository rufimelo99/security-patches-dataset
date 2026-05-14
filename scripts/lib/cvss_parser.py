"""
CVSS vector parser utility.

Parses CVSS v2.0 and v3.x vector strings into structured dicts.
"""

from cvss import CVSS2, CVSS3


# --- Mapping tables ---

V3_AV = {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL", "P": "PHYSICAL"}
V3_AC = {"L": "LOW", "H": "HIGH"}
V3_PR = {"N": "NONE", "L": "LOW", "H": "HIGH"}
V3_UI = {"N": "NONE", "R": "REQUIRED"}
V3_S  = {"U": "UNCHANGED", "C": "CHANGED"}
V3_CIA = {"N": "NONE", "L": "LOW", "H": "HIGH"}

V2_AV  = {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL"}
V2_AC  = {"L": "LOW", "M": "MEDIUM", "H": "HIGH"}
V2_Au  = {"N": "NONE", "S": "SINGLE", "M": "MULTIPLE"}
V2_CIA = {"N": "NONE", "P": "PARTIAL", "C": "COMPLETE"}


def parse_cvss_vector(vector_string):
    """
    Parse a CVSS vector string and return a structured dict.

    Supports CVSS v3.x (prefixed with "CVSS:3.x/...") and v2.0 (no prefix).

    Returns None if parsing fails or input is None/empty.
    """
    if not vector_string:
        return None

    try:
        if vector_string.startswith("CVSS:3"):
            return _parse_v3(vector_string)
        else:
            return _parse_v2(vector_string)
    except Exception:
        return None


def _parse_v3(vector_string):
    c = CVSS3(vector_string)
    m = c.metrics

    # Derive version from prefix (e.g. "CVSS:3.1/..." → "3.1")
    version = vector_string.split("/")[0].replace("CVSS:", "")

    base_score = float(c.scores()[0])
    base_severity = c.severities()[0].upper()

    return {
        "cvss_version": version,
        "vector_string": vector_string,
        "base_score": base_score,
        "base_severity": base_severity,
        "attack_vector": V3_AV.get(m.get("AV")),
        "attack_complexity": V3_AC.get(m.get("AC")),
        "privileges_required": V3_PR.get(m.get("PR")),
        "user_interaction": V3_UI.get(m.get("UI")),
        "scope": V3_S.get(m.get("S")),
        "authentication": None,
        "confidentiality_impact": V3_CIA.get(m.get("C")),
        "integrity_impact": V3_CIA.get(m.get("I")),
        "availability_impact": V3_CIA.get(m.get("A")),
        "exploitability_score": None,
        "impact_score": None,
    }


def _parse_v2(vector_string):
    c = CVSS2(vector_string)
    m = c.metrics

    base_score = float(c.scores()[0])
    base_severity = c.severities()[0].upper()

    return {
        "cvss_version": "2.0",
        "vector_string": vector_string,
        "base_score": base_score,
        "base_severity": base_severity,
        "attack_vector": V2_AV.get(m.get("AV")),
        "attack_complexity": V2_AC.get(m.get("AC")),
        "privileges_required": None,
        "user_interaction": None,
        "scope": None,
        "authentication": V2_Au.get(m.get("Au")),
        "confidentiality_impact": V2_CIA.get(m.get("C")),
        "integrity_impact": V2_CIA.get(m.get("I")),
        "availability_impact": V2_CIA.get(m.get("A")),
        "exploitability_score": None,
        "impact_score": None,
    }
