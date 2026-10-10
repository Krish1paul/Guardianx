"""Incident Correlation Engine — M8.

Provides deterministic, explainable correlation across multi-vector security events
(URL scans, message scans, file scans, threat intelligence).

Key Principles:
- Purely defensive correlation — answers:
  "Are these separate detections actually part of the same threat?"
- Strong & Medium signal matching with strict rejection of weak-only signals.
- Diminishing returns on repeated indicators.
- Strict score clamping in [0, 100] and confidence in [0.0, 1.0].
- Automated deduplication against existing OPEN and INVESTIGATING incidents.
- Strict tenant isolation enforced at database query level.

"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.file_scan import FileScan
from app.models.incident import Incident, IncidentEvent
from app.models.message_scan import MessageScan
from app.models.url_scan import URLScan
from app.schemas.unified_analysis import ThreatCategory
from app.services.analyzers.unified_risk_engine import (
    clamp_confidence,
    clamp_score,
    score_to_classification,
)
from app.services.intelligence.indicator_normalizer import (
    IndicatorNormalizer,
    IndicatorType,
    NormalizedIndicator,
)


@dataclass
class CorrelationCandidate:
    """Standardized representation of a newly scanned event for correlation."""

    event_id: uuid.UUID
    event_type: str  # "url_scan", "message_scan", "file_scan"
    user_id: uuid.UUID
    risk_score: int
    classification: str
    confidence: float
    created_at: datetime
    indicators: list[NormalizedIndicator]
    threat_categories: list[str]
    reasons: list[dict[str, Any]]
    raw_reference: str  # URL or filename or subject snippet


class CorrelationEngine:
    """Deterministic security incident correlation and lifecycle engine."""

    LOOKBACK_DAYS: int = 30
    MIN_INCIDENT_TRIGGER_SCORE: int = (
        30  # Don't create standalone incidents for trivial/clean events
    )

    def __init__(self, db: Session) -> None:
        self.db = db

    # ---------------------------------------------------------------------------
    # Public correlation entrypoints
    # ---------------------------------------------------------------------------

    def correlate_url_scan(self, scan: URLScan) -> Incident | None:
        """Correlate a URLScan event into an incident."""
        indicators = IndicatorNormalizer.extract_url_indicators(scan.normalized_url)
        reasons_list = scan.reasons if isinstance(scan.reasons, list) else []

        candidate = CorrelationCandidate(
            event_id=scan.id,
            event_type="url_scan",
            user_id=scan.user_id,
            risk_score=scan.risk_score,
            classification=scan.classification,
            confidence=0.90 if scan.threat_intel else 0.85,
            created_at=scan.created_at,
            indicators=indicators,
            threat_categories=["MALICIOUS_LINK"],
            reasons=reasons_list,
            raw_reference=scan.normalized_url,
        )
        return self._process_candidate(candidate)

    def correlate_message_scan(self, scan: MessageScan) -> Incident | None:
        """Correlate a MessageScan event into an incident."""
        indicators: list[NormalizedIndicator] = [
            NormalizedIndicator(
                type=IndicatorType.MESSAGE_HASH,
                value=scan.message_hash,
                metadata={},
            )
        ]
        if scan.sender:
            indicators.extend(IndicatorNormalizer.extract_sender_indicators(scan.sender))

        # Extract embedded URLs
        extracted_urls = scan.extracted_urls if isinstance(scan.extracted_urls, list) else []
        for item in extracted_urls:
            target_url = item.get("url") if isinstance(item, dict) else str(item)
            if target_url:
                indicators.extend(IndicatorNormalizer.extract_url_indicators(target_url))

        reasons_list = scan.reasons if isinstance(scan.reasons, list) else []
        threat_cats = [
            r.get("category", "SOCIAL_ENGINEERING") for r in reasons_list if isinstance(r, dict)
        ]

        candidate = CorrelationCandidate(
            event_id=scan.id,
            event_type="message_scan",
            user_id=scan.user_id,
            risk_score=scan.risk_score,
            classification=scan.classification,
            confidence=scan.confidence,
            created_at=scan.created_at,
            indicators=indicators,
            threat_categories=threat_cats or ["SOCIAL_ENGINEERING"],
            reasons=reasons_list,
            raw_reference=scan.subject or "Suspicious Message",
        )
        return self._process_candidate(candidate)

    def correlate_file_scan(self, scan: FileScan) -> Incident | None:
        """Correlate a FileScan event into an incident."""
        indicators: list[NormalizedIndicator] = [
            NormalizedIndicator(
                type=IndicatorType.FILE_HASH,
                value=scan.file_hash,
                metadata={"filename": scan.filename},
            )
        ]
        reasons_list = scan.reasons if isinstance(scan.reasons, list) else []

        candidate = CorrelationCandidate(
            event_id=scan.id,
            event_type="file_scan",
            user_id=scan.user_id,
            risk_score=scan.risk_score,
            classification=scan.classification,
            confidence=scan.confidence,
            created_at=scan.created_at,
            indicators=indicators,
            threat_categories=["SUSPICIOUS_ATTACHMENT"],
            reasons=reasons_list,
            raw_reference=scan.filename,
        )
        return self._process_candidate(candidate)

    # ---------------------------------------------------------------------------
    # Core Correlation Algorithm
    # ---------------------------------------------------------------------------

    def _process_candidate(self, candidate: CorrelationCandidate) -> Incident | None:
        """Correlate candidate against existing user incidents or create a new one."""
        lookback_cutoff = datetime.now(candidate.created_at.tzinfo) - timedelta(
            days=self.LOOKBACK_DAYS
        )

        # 1. Fetch active open/investigating incidents for this user
        stmt = (
            select(Incident)
            .where(
                Incident.user_id == candidate.user_id,
                Incident.status.in_(["OPEN", "INVESTIGATING"]),
                Incident.last_seen >= lookback_cutoff,
            )
            .order_by(Incident.last_seen.desc())
        )
        active_incidents = list(self.db.scalars(stmt).all())

        candidate_indicator_values = {ind.value for ind in candidate.indicators}
        candidate_domains = {
            ind.value
            for ind in candidate.indicators
            if ind.type in (IndicatorType.DOMAIN, IndicatorType.HOSTNAME)
        }
        candidate_hashes = {
            ind.value
            for ind in candidate.indicators
            if ind.type
            in (IndicatorType.URL_HASH, IndicatorType.FILE_HASH, IndicatorType.MESSAGE_HASH)
        }

        matched_incident: Incident | None = None
        match_reason = ""
        is_strong_match = False

        # 2. Check for strong or medium signal match against open incidents
        for inc in active_incidents:
            inc_indicators = inc.indicators if isinstance(inc.indicators, list) else []
            inc_values = {i.get("value") for i in inc_indicators if isinstance(i, dict)}
            inc_domains = {
                i.get("value")
                for i in inc_indicators
                if isinstance(i, dict) and i.get("type") in ("DOMAIN", "HOSTNAME")
            }
            inc_hashes = {
                i.get("value")
                for i in inc_indicators
                if isinstance(i, dict)
                and i.get("type") in ("URL_HASH", "FILE_HASH", "MESSAGE_HASH")
            }

            # Strong match: identical hash
            common_hashes = candidate_hashes.intersection(inc_hashes)
            if common_hashes:
                matched_incident = inc
                match_reason = (
                    f"Identical cryptographic hash matched: {next(iter(common_hashes))[:16]}..."
                )
                is_strong_match = True
                break

            # Strong match: identical domain
            common_domains = candidate_domains.intersection(inc_domains)
            if common_domains:
                matched_incident = inc
                match_reason = (
                    f"Identical infrastructure domain matched: {next(iter(common_domains))}"
                )
                is_strong_match = True
                break

            # Medium match: any other shared indicator (sender email, IP)
            common_all = candidate_indicator_values.intersection(inc_values)
            if common_all:
                matched_incident = inc
                match_reason = f"Associated indicator matched: {next(iter(common_all))}"
                is_strong_match = False
                break

        # 3. If matched, attach event and update incident
        if matched_incident:
            return self._append_to_incident(
                matched_incident, candidate, match_reason, is_strong_match
            )

        # 4. If no open incident matched, evaluate if candidate merits a new incident
        # A standalone incident is created if the candidate risk is >= MIN_INCIDENT_TRIGGER_SCORE
        # or if it exhibits high/critical severity.
        if candidate.risk_score >= self.MIN_INCIDENT_TRIGGER_SCORE:
            return self._create_incident(candidate)

        return None

    def _append_to_incident(
        self,
        incident: Incident,
        candidate: CorrelationCandidate,
        relationship_reason: str,
        is_strong_match: bool,
    ) -> Incident:
        """Attach event to existing incident and recompute risk with diminishing returns."""
        # 1. Create event link
        event_link = IncidentEvent(
            incident_id=incident.id,
            event_type=candidate.event_type,
            event_id=candidate.event_id,
            relationship_reason=relationship_reason,
            created_at=candidate.created_at,
        )
        self.db.add(event_link)

        # 2. Update timestamps and count
        incident.last_seen = max(incident.last_seen, candidate.created_at)
        incident.event_count += 1
        incident.updated_at = candidate.created_at

        # 3. Merge indicators without duplicates
        current_indicators = incident.indicators if isinstance(incident.indicators, list) else []
        existing_keys = {
            f"{i.get('type')}:{i.get('value')}" for i in current_indicators if isinstance(i, dict)
        }
        for ind in candidate.indicators:
            key = f"{ind.type.value}:{ind.value}"
            if key not in existing_keys:
                current_indicators.append(ind.to_dict())
                existing_keys.add(key)
        incident.indicators = current_indicators

        # 4. Diminishing returns score update:
        # Each subsequent event contributes less risk to avoid runaway score inflation
        n = incident.event_count
        diminishing_factor = 0.6 ** (n - 1)
        marginal_contribution = int(round(candidate.risk_score * 0.25 * diminishing_factor))

        # Diversity boost if multi-vector
        vector_types = {e.event_type for e in incident.events}.union({candidate.event_type})
        vector_diversity_boost = 15 if len(vector_types) >= 2 else 0

        new_risk = clamp_score(
            max(incident.risk_score, candidate.risk_score)
            + marginal_contribution
            + vector_diversity_boost
        )
        incident.risk_score = new_risk
        incident.severity = score_to_classification(new_risk).value

        # Update confidence
        boost = 0.05 if is_strong_match else 0.02
        incident.confidence = clamp_confidence(
            max(incident.confidence, candidate.confidence) + boost
        )

        # Update attack stage
        incident.attack_stage = self._classify_attack_stage(vector_types, incident.risk_score)

        # Append correlation reason
        current_reasons = incident.reasons if isinstance(incident.reasons, list) else []
        current_reasons.append(
            {
                "category": ThreatCategory.REPUTATION.value,
                "severity": candidate.classification,
                "title": f"Correlated Event ({candidate.event_type.replace('_', ' ').title()})",
                "explanation": (
                    f"{relationship_reason}. Contributed +{marginal_contribution} risk points."
                ),
                "score_contribution": marginal_contribution,
                "rule_id": "CORRELATION_EVENT_ATTACHED",
            }
        )
        incident.reasons = current_reasons

        self.db.flush()
        self.db.refresh(incident)
        return incident

    def _create_incident(self, candidate: CorrelationCandidate) -> Incident:
        """Create a new Incident entity from a standalone threat event."""
        # Classify attack stage
        attack_stage = self._classify_attack_stage({candidate.event_type}, candidate.risk_score)
        title = self._generate_incident_title(candidate, attack_stage)

        # Explainable reasons
        ref_label = candidate.raw_reference[:50]
        reasons_list: list[dict[str, Any]] = [
            {
                "category": ThreatCategory.STRUCTURAL_ANOMALY.value,
                "severity": candidate.classification,
                "title": f"Initial Detection: {candidate.event_type.replace('_', ' ').title()}",
                "explanation": (
                    f"High threat detection on {ref_label} initiated this security incident."
                ),
                "score_contribution": candidate.risk_score,
                "rule_id": "INCIDENT_INITIAL_DETECTION",
            }
        ]

        # Add candidate specific reasons if present
        for r in candidate.reasons[:3]:
            if isinstance(r, dict):
                reasons_list.append(r)

        incident = Incident(
            user_id=candidate.user_id,
            title=title,
            severity=candidate.classification,
            risk_score=candidate.risk_score,
            confidence=clamp_confidence(candidate.confidence),
            status="OPEN",
            attack_stage=attack_stage,
            first_seen=candidate.created_at,
            last_seen=candidate.created_at,
            event_count=1,
            indicators=[ind.to_dict() for ind in candidate.indicators],
            reasons=reasons_list,
            created_at=candidate.created_at,
            updated_at=candidate.created_at,
        )
        self.db.add(incident)
        self.db.flush()

        # Link event
        event_link = IncidentEvent(
            incident_id=incident.id,
            event_type=candidate.event_type,
            event_id=candidate.event_id,
            relationship_reason="Root trigger event for incident creation",
            created_at=candidate.created_at,
        )
        self.db.add(event_link)
        self.db.flush()

        return incident

    # ---------------------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------------------

    @staticmethod
    def _classify_attack_stage(vector_types: set[str], risk_score: int) -> str:
        """Derive attack-chain stage based on multi-vector evidence."""
        if len(vector_types) >= 2:
            return "MULTI_VECTOR_CAMPAIGN"
        if "file_scan" in vector_types:
            return "SUSPICIOUS_ATTACHMENT"
        if "message_scan" in vector_types:
            return "SOCIAL_ENGINEERING" if risk_score < 75 else "CREDENTIAL_HARVESTING"
        if "url_scan" in vector_types:
            return "MALICIOUS_LINK"
        return "REPEATED_THREAT"

    @staticmethod
    def _generate_incident_title(candidate: CorrelationCandidate, attack_stage: str) -> str:
        """Synthesize a concise, professional title using defensive language."""
        domain_ind = next(
            (
                ind.value
                for ind in candidate.indicators
                if ind.type in (IndicatorType.DOMAIN, IndicatorType.HOSTNAME)
            ),
            None,
        )
        target_label = domain_ind or (
            candidate.raw_reference[:35] + "…"
            if len(candidate.raw_reference) > 35
            else candidate.raw_reference
        )

        if attack_stage == "MULTI_VECTOR_CAMPAIGN":
            return f"Multi-Vector Phishing Campaign Linked to {target_label}"
        if attack_stage == "CREDENTIAL_HARVESTING":
            return f"Potential Credential Harvesting Attempt via {target_label}"
        if attack_stage == "SOCIAL_ENGINEERING":
            return f"Suspicious Social Engineering Communication from {target_label}"
        if attack_stage == "SUSPICIOUS_ATTACHMENT":
            return f"Suspicious File Artifact Detected: {target_label}"
        if attack_stage == "MALICIOUS_LINK":
            return f"High-Risk URL Activity on {target_label}"
        return f"Suspicious Threat Activity Associated with {target_label}"
