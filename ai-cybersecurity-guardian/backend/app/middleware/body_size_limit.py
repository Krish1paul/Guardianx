"""Request body size limiter middleware — M5 Production Hardening.

Protects the server from Denial of Service (DoS) attacks via oversized payloads.
Returns HTTP 413 Payload Too Large if Content-Length or received body exceeds limit.
"""

from __future__ import annotations

import json
from collections.abc import MutableMapping
from typing import Any

from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.config import get_settings


class BodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int | None = None) -> None:
        self.app = app
        self._max_bytes = max_bytes

    def _get_max_bytes(self) -> int:
        if self._max_bytes is not None:
            return self._max_bytes
        return get_settings().max_request_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        max_bytes = self._get_max_bytes()
        path = scope.get("path", "")
        # Allow larger limit for static file analysis endpoint
        if path.endswith("/analyze/file"):
            max_bytes = max(max_bytes, 6 * 1024 * 1024)
        headers_dict = dict(scope.get("headers", []))
        content_length_raw = headers_dict.get(b"content-length")

        if content_length_raw is not None:
            try:
                content_length = int(content_length_raw.decode("utf-8"))
                if content_length > max_bytes:
                    await self._send_413(send, max_bytes)
                    return
            except ValueError:
                pass

        bytes_received = 0

        async def receive_wrapper() -> MutableMapping[str, Any]:
            nonlocal bytes_received
            message = await receive()
            if message["type"] == "http.request":
                body = message.get("body", b"")
                bytes_received += len(body)
                if bytes_received > max_bytes:
                    # Signal error by raising or terminating
                    raise BodySizeLimitExceededError(max_bytes)
            return message

        try:
            await self.app(scope, receive_wrapper, send)
        except BodySizeLimitExceededError:
            await self._send_413(send, max_bytes)

    async def _send_413(self, send: Send, max_bytes: int) -> None:
        body = json.dumps(
            {"detail": f"Request body exceeds maximum allowed size of {max_bytes} bytes."}
        ).encode("utf-8")
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("utf-8")),
        ]
        await send({"type": "http.response.start", "status": 413, "headers": headers})
        await send({"type": "http.response.body", "body": body})


class BodySizeLimitExceededError(Exception):
    def __init__(self, max_bytes: int) -> None:
        super().__init__(f"Request body exceeds maximum allowed size of {max_bytes} bytes.")
        self.max_bytes = max_bytes
