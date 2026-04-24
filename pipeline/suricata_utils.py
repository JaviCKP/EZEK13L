from __future__ import annotations


NOISE_SIGNATURE_PATTERNS = (
    "invalid checksum",
    "ethertype unknown",
    "applayer detect protocol only one direction",
    "stream fin out of window",
    "stream closewait fin out of window",
    "fragmentation overlap",
    "frag ipv4 fragmentation overlap",
)

TELEMETRY_SIGNATURE_PREFIXES = (
    "et info ",
)

TELEMETRY_SIGNATURE_PATTERNS = (
    "weak encryption parameters",
    "package management",
    "user-agent",
    "dropbox observed",
    "ntlm session setup",
    "ntlmv1 session setup",
    "device metadata retrieval client",
)


def alert_signature(row: dict) -> str:
    alert = row.get("alert")
    if isinstance(alert, dict):
        signature = alert.get("signature")
        if signature:
            return str(signature)
    return ""


def alert_signature_lower(row: dict) -> str:
    return alert_signature(row).strip().lower()


def classify_suricata_alert(row: dict) -> str:
    if row.get("event_type") != "alert":
        return "non_alert"

    signature = alert_signature_lower(row)
    if not signature:
        return "telemetry"

    if any(pattern in signature for pattern in NOISE_SIGNATURE_PATTERNS):
        return "noise"

    if signature.startswith(TELEMETRY_SIGNATURE_PREFIXES):
        return "telemetry"

    if any(pattern in signature for pattern in TELEMETRY_SIGNATURE_PATTERNS):
        return "telemetry"

    return "threat"


def should_guard_learning(row: dict) -> bool:
    return classify_suricata_alert(row) != "noise"
