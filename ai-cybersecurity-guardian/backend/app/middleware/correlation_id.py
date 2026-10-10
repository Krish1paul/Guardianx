"""Request and correlation ID tracing middleware — M5 Production Hardening.

Attaches a unique correlation ID to every incoming request, stores it in a
context variable for structured logging and error reporting, and echoes it in
response headers (``X-Request-ID`` and ``X-Correlation-ID``).
"""

from __future__ import annotations

import contextvars
import uuid
from collections.abc import MutableMapping
from typing import Any

from starlette.types import ASGIApp, Receive, Scope, Send

_correlation_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar(
    "correlation_id", default=""
)


def get_correlation_id() -> str:
    """Return the current correlation ID, or empty string if outside request context."""
    return _correlation_id_ctx.get()


class CorrelationIdMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        correlation_id = ""
        # Inspect incoming headers
        headers_dict = dict(scope.get("headers", []))
        for key in (b"x-request-id", b"x-correlation-id"):
            val = headers_dict.get(key)
            if val:
                correlation_id = val.decode("utf-8", errors="ignore").strip()
                break

        if not correlation_id:
            correlation_id = uuid.uuid4().hex

        token = _correlation_id_ctx.set(correlation_id)

        async def send_wrapper(message: MutableMapping[str, Any]) -> None:
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                cid_bytes = correlation_id.encode("utf-8")
                headers.extend(
                    [
                        (b"x-request-id", cid_bytes),
                        (b"x-correlation-id", cid_bytes),
                    ]
                )
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            _correlation_id_ctx.reset(token)
