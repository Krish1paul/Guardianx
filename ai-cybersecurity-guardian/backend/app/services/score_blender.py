"""Score blending: ML baseline + Threat Intelligence signal — M4.

Design rules
------------
1.  The ML/rule-engine baseline score is ALWAYS the primary signal.
2.  TI can only INCREASE the score, never decrease it.
    Rationale: a clean TI result does not mean a URL is safe (TI databases
    are incomplete); but a malicious result is strong corroborating evidence.
3.  The TI boost is bounded by ``max_boost`` (default 30 points).
4.  The final score is clamped to [0, 100].
5.  Classification thresholds (LOW/MEDIUM/HIGH/CRITICAL) are unchanged.
6.  Every TI boost generates a typed ``RiskReason`` entry.
7.  Provider errors and UNKNOWN status produce zero boost and no reason.

Boost schedule
--------------
-  MALICIOUS : boost = max_boost × confidence  (default up to 30)
-  SUSPICIOUS: boost = (max_boost // 2) × confidence  (default up to 15)
-  CLEAN     : boost = 0   (clean signal does not lower ML score)
-  UNKNOWN   : boost = 0
-  provider_error: boost = 0
"""

from __future__ import annotations

from app.services.ti_types import ThreatIntelResult, ThreatIntelStatus


def blend(
    baseline_score: int,
    ti_result: ThreatIntelResult,
    *,
    max_boost: int = 30,
) -> tuple[int, list[dict[str, str]]]:
    """Blend ML baseline score with TI reputation signal.

    Parameters
    ----------
    baseline_score:
        ML/rule-engine risk score [0, 100].
    ti_result:
        Result from the TI provider (may be an error result).
    max_boost:
        Maximum score points that TI may contribute.

    Returns
    -------
    final_score:
        Blended score clamped to [0, 100].
    ti_reasons:
        List of ``RiskReason``-compatible dicts to append to the reasons list.
        Empty when no boost is applied.
    """
    if ti_result.provider_error or ti_result.status == ThreatIntelStatus.UNKNOWN:
        return baseline_score, []

    boost = _compute_boost(ti_result, max_boost)
    final_score = max(0, min(100, baseline_score + boost))
    reasons = _build_reasons(ti_result, boost)
    return final_score, reasons


def _compute_boost(result: ThreatIntelResult, max_boost: int) -> int:
    """Return the integer score boost for this TI result."""
    confidence = result.confidence if result.confidence is not None else 1.0

    if result.status == ThreatIntelStatus.MALICIOUS:
        return round(max_boost * confidence)
    if result.status == ThreatIntelStatus.SUSPICIOUS:
        return round((max_boost // 2) * confidence)
    # CLEAN → no boost
    return 0


def _build_reasons(result: ThreatIntelResult, boost: int) -> list[dict[str, str]]:
    """Build reason dict(s) describing the TI finding."""
    if boost == 0 and result.status == ThreatIntelStatus.CLEAN:
        # Still add an informational CLEAN reason (no severity boost)
        return [
            {
                "code": "TI_REPUTATION",
                "severity": "LOW",
                "message": (
                    f"[{result.provider}] URL found in reputation database and rated clean."
                ),
            }
        ]

    if boost == 0:
        return []

    if result.status == ThreatIntelStatus.MALICIOUS:
        severity = "CRITICAL"
        base_msg = f"[{result.provider}] URL flagged as MALICIOUS"
    else:
        severity = "HIGH"
        base_msg = f"[{result.provider}] URL flagged as SUSPICIOUS"

    detail = f": {result.reason}" if result.reason else "."
    cached_note = " (cached result)" if result.cached else ""

    return [
        {
            "code": "TI_REPUTATION",
            "severity": severity,
            "message": f"{base_msg}{detail}{cached_note} Score boosted by {boost} points.",
        }
    ]
