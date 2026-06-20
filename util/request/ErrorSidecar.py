from __future__ import annotations

import base64
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any


class BiliRequestErrorSidecar:
    _DISABLED_VALUES = {"0", "false", "no", "off"}

    def __init__(self, *, clock=time.time):
        self._clock = clock

    def record_response(
        self,
        *,
        stage: str,
        method: str,
        url: str,
        data: Any,
        is_json: bool,
        request_headers: dict[str, Any] | None,
        response: Any,
    ) -> None:
        self._write(
            {
                "event": "http_response",
                "stage": stage,
                "request": self._request_snapshot(
                    method=method,
                    url=url,
                    data=data,
                    is_json=is_json,
                    request_headers=request_headers,
                ),
                "response": self._response_snapshot(response),
            }
        )

    def record_exception(
        self,
        *,
        stage: str,
        method: str,
        url: str,
        data: Any,
        is_json: bool,
        request_headers: dict[str, Any] | None,
        exc: BaseException,
        attempt: int,
    ) -> None:
        self._write(
            {
                "event": "http_exception",
                "stage": stage,
                "attempt": attempt,
                "request": self._request_snapshot(
                    method=method,
                    url=url,
                    data=data,
                    is_json=is_json,
                    request_headers=request_headers,
                ),
                "exception": {
                    "type": exc.__class__.__name__,
                    "message": str(exc),
                },
            }
        )

    def _write(self, payload: dict[str, Any]) -> None:
        if str(os.environ.get("BTB_ERROR_SIDECAR_ENABLED", "1")).lower() in (
            self._DISABLED_VALUES
        ):
            return
        try:
            path = self._target_file()
            path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "id": uuid.uuid4().hex,
                "timestamp": self._format_timestamp(self._clock()),
                **payload,
            }
            with path.open("a", encoding="utf-8") as fp:
                fp.write(json.dumps(payload, ensure_ascii=False, default=str))
                fp.write("\n")
        except Exception:
            return

    def _target_file(self) -> Path:
        sidecar_dir = os.environ.get("BTB_ERROR_SIDECAR_DIR")
        if not sidecar_dir:
            log_dir = os.environ.get("BTB_LOG_DIR")
            if not log_dir:
                log_dir = os.path.join(self._exec_path(), "btb_logs")
            sidecar_dir = os.path.join(log_dir, "request_errors")
        day = time.strftime("%Y%m%d", time.localtime(self._clock()))
        return Path(sidecar_dir) / f"bili_request_errors_{day}.jsonl"

    def _exec_path(self) -> str:
        argv0 = sys.argv[0] or ""
        if argv0.endswith(".py"):
            return os.getcwd()
        return os.path.dirname(os.path.realpath(sys.executable))

    def _request_snapshot(
        self,
        *,
        method: str,
        url: str,
        data: Any,
        is_json: bool,
        request_headers: dict[str, Any] | None,
    ) -> dict[str, Any]:
        return {
            "method": method.upper(),
            "url": str(url),
            "body_format": "json" if is_json else "form",
            "body": self._jsonable(data),
            "headers": self._headers_snapshot(request_headers or {}),
        }

    def _response_snapshot(self, response: Any) -> dict[str, Any]:
        return {
            "status_code": getattr(response, "status_code", None),
            "url": str(getattr(response, "url", "")),
            "http_version": self._http_version(response),
            "headers": self._headers_snapshot(getattr(response, "headers", {})),
            "body": self._bounded_text(self._response_text(response)),
        }

    def _headers_snapshot(self, headers: Any) -> list[dict[str, str]]:
        items = None
        for attr in ("multi_items", "items"):
            candidate = getattr(headers, attr, None)
            if candidate is not None:
                try:
                    items = list(candidate())
                    break
                except Exception:
                    pass
        if items is None:
            try:
                items = list(dict(headers).items())
            except Exception:
                return []

        return [
            {
                "name": str(name),
                "value": self._header_value(str(name), value),
            }
            for name, value in items
        ]

    def _header_value(self, name: str, value: Any) -> str:
        text = str(value)
        if name.lower() in {"authorization", "cookie", "proxy-authorization"}:
            if name.lower() == "cookie":
                return self._redact_cookie_header(text)
            return "<redacted>"
        return text

    def _redact_cookie_header(self, value: str) -> str:
        names = []
        for part in value.split(";"):
            name = part.split("=", 1)[0].strip()
            if name:
                names.append(f"{name}=<redacted>")
        return "; ".join(names)

    def _response_text(self, response: Any) -> str:
        try:
            return str(response.text)
        except Exception:
            content = getattr(response, "content", b"")
            if isinstance(content, bytes):
                encoded = base64.b64encode(content).decode("ascii")
                return f"<base64:{encoded}>"
            return str(content)

    def _http_version(self, response: Any) -> str | None:
        extensions = getattr(response, "extensions", None)
        if isinstance(extensions, dict):
            http_version = extensions.get("http_version")
            if isinstance(http_version, bytes):
                return http_version.decode("ascii", "replace")
            if http_version is not None:
                return str(http_version)
        version = getattr(response, "version", None)
        return str(version) if version is not None else None

    def _bounded_text(self, value: str) -> dict[str, Any]:
        limit = self._body_limit()
        text = str(value)
        truncated = len(text) > limit
        if truncated:
            text = text[:limit]
        return {
            "text": text,
            "truncated": truncated,
            "original_length": len(str(value)),
        }

    def _body_limit(self) -> int:
        try:
            return max(
                0,
                int(os.environ.get("BTB_ERROR_SIDECAR_MAX_BODY_CHARS", "200000")),
            )
        except ValueError:
            return 200000

    def _jsonable(self, value: Any) -> Any:
        try:
            json.dumps(value, ensure_ascii=False, default=str)
            return value
        except Exception:
            if isinstance(value, bytes):
                return {"base64": base64.b64encode(value).decode("ascii")}
            return repr(value)

    def _format_timestamp(self, timestamp: float) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(timestamp)) + (
            f".{int((timestamp % 1) * 1000):03d}"
        )
