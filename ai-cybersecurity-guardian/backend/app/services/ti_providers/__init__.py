"""Threat Intelligence providers package — M4.

Available providers:

- ``MockProvider``        — deterministic, no network calls (default in dev/test)
- ``VirusTotalProvider``  — VirusTotal v3 API (requires VIRUSTOTAL_API_KEY)
"""

from app.services.ti_providers.mock_provider import MockProvider
from app.services.ti_providers.virustotal_provider import VirusTotalProvider

__all__ = ["MockProvider", "VirusTotalProvider"]
