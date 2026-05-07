from __future__ import annotations

import importlib
import os
from typing import Callable

from libmodsecurity import Intervention, ModSecurity, RulesSet, __version__


def _load_app(import_string: str):
    module_name, _, attr = import_string.partition(":")
    if not module_name:
        raise ValueError(f"invalid WAF_APP {import_string!r}, expected 'module:attr'")
    return getattr(importlib.import_module(module_name), attr or "app")


def _discard_log(_message: str) -> None:
    pass


class ModSecMiddleware:
    def __init__(
        self,
        app,
        engine: ModSecurity,
        rules: RulesSet,
        *,
        log_callback: Callable[[str], None] = _discard_log,
    ):
        self.app = app
        self.engine = engine
        self.rules = rules
        engine.set_log_callback(log_callback)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        with self.engine.transaction(self.rules) as t:
            client = scope.get("client") or ("0.0.0.0", 0)
            server = scope.get("server") or ("0.0.0.0", 0)
            http_version = scope.get("http_version", "1.1")

            t.process_connection(client[0], client[1], server[0], server[1])
            if it := _disruptive(t.intervention()):
                return await _block(send, it, t.id)

            raw_path = scope.get("raw_path") or scope["path"].encode("utf-8")
            qs = scope.get("query_string") or b""
            uri = (raw_path + b"?" + qs) if qs else raw_path
            t.process_uri(uri.decode("latin-1"), scope["method"], http_version)
            if it := _disruptive(t.intervention()):
                return await _block(send, it, t.id)

            for name, value in scope["headers"]:
                t.add_request_header(name.decode("latin-1"), value.decode("latin-1"))
            t.process_request_headers()
            if it := _disruptive(t.intervention()):
                return await _block(send, it, t.id)

            request_body = bytearray()
            while True:
                msg = await receive()
                if msg["type"] == "http.disconnect":
                    return
                if msg["type"] != "http.request":
                    continue
                chunk = msg.get("body") or b""
                if chunk:
                    t.append_request_body(chunk)
                    request_body.extend(chunk)
                if not msg.get("more_body", False):
                    break
            t.process_request_body()
            if it := _disruptive(t.intervention()):
                return await _block(send, it, t.id)

            replayed = False

            async def recv():
                nonlocal replayed
                if not replayed:
                    replayed = True
                    return {
                        "type": "http.request",
                        "body": bytes(request_body),
                        "more_body": False,
                    }
                return {"type": "http.disconnect"}

            response_status = 0
            response_headers: list[tuple[bytes, bytes]] = []
            response_body = bytearray()
            blocked = False

            async def snd(msg):
                nonlocal response_status, response_headers, blocked
                if blocked:
                    return
                if msg["type"] == "http.response.start":
                    response_status = msg["status"]
                    response_headers = list(msg["headers"])
                    for n, v in response_headers:
                        t.add_response_header(n.decode("latin-1"), v.decode("latin-1"))
                    t.process_response_headers(response_status, f"HTTP/{http_version}")
                    if it := _disruptive(t.intervention()):
                        blocked = True
                        await _block(send, it, t.id)
                elif msg["type"] == "http.response.body":
                    chunk = msg.get("body") or b""
                    if chunk:
                        t.append_response_body(chunk)
                        response_body.extend(chunk)
                    if msg.get("more_body", False):
                        return
                    t.process_response_body()
                    if it := _disruptive(t.intervention()):
                        blocked = True
                        await _block(send, it, t.id)
                        return
                    body = bytes(response_body)
                    headers = [
                        (n, v)
                        for n, v in response_headers
                        if n.lower() != b"content-length"
                    ]
                    headers.append((b"content-length", str(len(body)).encode("ascii")))
                    await send(
                        {
                            "type": "http.response.start",
                            "status": response_status,
                            "headers": headers,
                        }
                    )
                    await send(
                        {
                            "type": "http.response.body",
                            "body": body,
                            "more_body": False,
                        }
                    )

            await self.app(scope, recv, snd)


def _disruptive(it: Intervention | None) -> Intervention | None:
    return it if it is not None and it.disruptive else None


async def _block(send, it: Intervention, transaction_id: str) -> None:
    body = b"Request blocked"
    status = it.status if it.status and it.status != 200 else 403
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"text/plain; charset=utf-8"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"x-transaction-id", transaction_id.encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})


_app: ModSecMiddleware | None = None


def _build_app() -> ModSecMiddleware:
    try:
        app_import = os.environ["WAF_APP"]
        rules_path = os.environ["WAF_RULES"]
    except KeyError as e:
        raise RuntimeError(
            f"missing required environment variable: {e.args[0]}"
        ) from None

    engine = ModSecurity()
    engine.set_connector_information(f"python-libmodsecurity-middleware/{__version__}")

    rules = RulesSet()
    if rules.load_from_uri(rules_path) < 0:
        raise RuntimeError(
            f"failed to load rules from {rules_path}: {rules.get_parser_error()}"
        )

    return ModSecMiddleware(_load_app(app_import), engine, rules)


def __getattr__(name: str):
    global _app
    if name == "app":
        if _app is None:
            _app = _build_app()
        return _app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
