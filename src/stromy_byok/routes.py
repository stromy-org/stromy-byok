"""The hardened ``/keys`` registration page.

The page carries **no login of its own**. The holder's identity was verified by
the MCP protocol when the grant was minted, and the opaque short-lived grant is
the page's only guard. That is a deliberate design, not a shortcut: it replaced
an earlier flow that asked users to paste the raw Entra access token their MCP
client had cached — which was OS-specific to dig out, and taught a
phishing-shaped habit.

Every field that scopes the write comes from the **grant**, never the form. The
form carries a token and a key. That is the whole input surface.

Browser hardening, applied to every response:

- ``Cache-Control: no-store`` — a registration page must not sit in a disk
  cache or a shared proxy;
- a restrictive CSP with ``frame-ancestors 'none'`` and no third-party origins,
  so the page cannot be framed for clickjacking and cannot load an external
  script that could read the key out of the form;
- ``Referrer-Policy: no-referrer``, so no downstream host learns the URL (which
  carries the grant token);
- ``X-Content-Type-Options: nosniff``.

The key exists only in a POST body over HTTPS. It is never echoed back into the
rendered HTML, never placed in a URL, and never logged.
"""

from __future__ import annotations

import html
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TypeAlias

from starlette.requests import Request
from starlette.responses import HTMLResponse

from stromy_byok.catalogue import CredentialCatalogue, UnknownCredentialError
from stromy_byok.grants import (
    Grant,
    GrantAction,
    GrantError,
    RegistrationGrantStore,
    consume_for,
)
from stromy_byok.models import (
    AuditAction,
    AuditEvent,
    ValidationOutcome,
    ValidationStatus,
)
from stromy_byok.store import StoreUnavailableError, require_writer
from stromy_byok.validators import validate_key_async

logger = logging.getLogger(__name__)

__all__ = ["KeysRoutes", "SECURITY_HEADERS", "build_keys_routes"]

#: Applied to every response this module emits.
SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": (
        "default-src 'none'; "
        "style-src 'unsafe-inline'; "
        "form-action 'self'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'"
    ),
}

_STYLE = """
  body { font-family: system-ui, sans-serif; max-width: 40rem; margin: 3rem auto;
    padding: 0 1rem; color: #1a1a1a; background: #fff; }
  input { width: 100%; box-sizing: border-box; padding: 0.5rem;
    margin: 0.25rem 0 1rem; }
  .message { padding: 0.75rem; border-radius: 0.25rem; margin-bottom: 1rem; }
  .ok { background: #e6f4ea; }
  .warn { background: #fff4e5; }
  .error { background: #fdecea; }
  button { padding: 0.5rem 1rem; margin-right: 0.5rem; }
  code { background: #f3f3f3; padding: 0.1rem 0.3rem; border-radius: 0.2rem; }
"""

_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{title}</title>
<style>{style}</style>
</head>
<body>
<h1>{heading}</h1>
{body}
</body>
</html>
"""

_INVALID_LINK_MESSAGE = (
    "This registration link is invalid, already used, or has expired. Ask your agent "
    "for a fresh link and open that one — links are single-use and short-lived on purpose."
)


def _respond(body_html: str, status_code: int = 200, *, heading: str, title: str) -> HTMLResponse:
    page = _PAGE.format(title=html.escape(title), heading=html.escape(heading), style=_STYLE, body=body_html)
    return HTMLResponse(page, status_code=status_code, headers=dict(SECURITY_HEADERS))


def _message_block(message: str, cls: str = "ok") -> str:
    return f'<div class="message {cls}">{html.escape(message)}</div>'


def _result(message: str, *, cls: str = "ok", status_code: int = 200, heading: str) -> HTMLResponse:
    return _respond(_message_block(message, cls), status_code, heading=heading, title=heading)


#: An ASGI-style handler: the shape Starlette's ``Route`` expects.
Handler: TypeAlias = Callable[[Request], Awaitable[HTMLResponse]]
#: Resolved per request, so a vault provisioned after startup starts working
#: without a redeploy. Returns "something that may be a reader and/or writer" —
#: ``require_writer`` is what narrows it.
StoreFactory: TypeAlias = Callable[[], object]
AuditSink: TypeAlias = Callable[[AuditEvent], None]


@dataclass(frozen=True)
class KeysRoutes:
    """The GET/POST handler pair, bound to one application's configuration."""

    get: Handler
    post: Handler


def build_keys_routes(
    *,
    catalogue: CredentialCatalogue,
    grant_store: RegistrationGrantStore,
    store_factory: StoreFactory,
    service: str,
    path: str = "/keys",
    audit_sink: AuditSink | None = None,
    validate: bool = True,
) -> KeysRoutes:
    """Build ``GET``/``POST`` handlers for the registration page.

    :param store_factory: zero-arg callable returning the credential store.
        A callable rather than an instance so the store is resolved per
        request — a vault provisioned after startup starts working without a
        redeploy.
    :param audit_sink: optional ``(AuditEvent) -> None``. Events are already
        redacted; the sink never has to filter.
    :param validate: probe the provider before storing. Only a *definitive*
        rejection blocks the write.
    """

    def _audit(event: AuditEvent) -> None:
        if audit_sink is None:
            return
        try:
            audit_sink(event)
        except Exception:  # noqa: BLE001 - auditing must never break registration
            logger.exception("audit sink raised while recording %s", event.action.value)

    def _heading(grant: Grant | None) -> str:
        if grant is None:
            return "Register your provider key"
        try:
            spec = catalogue.get(grant.credential_id)
        except UnknownCredentialError:
            return "Register your provider key"
        return f"Register your {spec.display_name or spec.provider} key"

    def _render_form(grant: Grant, message: str = "", cls: str = "ok") -> str:
        spec = catalogue.get(grant.credential_id)
        label = html.escape(spec.display_name or f"{spec.provider} key")
        signup = ""
        if spec.signup_url:
            safe_url = html.escape(spec.signup_url, quote=True)
            signup = (
                f'<p>Need a key? Create one at <a href="{safe_url}" '
                f'rel="noreferrer noopener">{html.escape(spec.signup_url)}</a>.</p>'
            )
        block = _message_block(message, cls) if message else ""
        disconnect_button = ""
        if grant.action is GrantAction.DISCONNECT:
            # A disconnect grant renders ONLY the disconnect affordance — the
            # action is bound in the grant, so offering "register" here would
            # promise something the POST will correctly refuse.
            return (
                "<p>This will disable the key registered against your account. "
                "You can register a new one afterwards at any time.</p>"
                f"{block}"
                f'<form method="post" action="{html.escape(path, quote=True)}">'
                f'<input type="hidden" name="token" value="{html.escape(grant.token, quote=True)}">'
                '<button type="submit">Disconnect my key</button>'
                "</form>"
            )
        return (
            "<p>This registers your own key against your account, so calls run — and "
            "bill — on <strong>your</strong> key, never the operator's. The key is stored "
            "server-side and is never returned to any agent conversation, tool call, or log.</p>"
            f"{signup}{block}"
            f'<form method="post" action="{html.escape(path, quote=True)}">'
            f'<input type="hidden" name="token" value="{html.escape(grant.token, quote=True)}">'
            f'<label for="provider_key">{label}</label>'
            '<input id="provider_key" name="provider_key" type="password" '
            'autocomplete="off" spellcheck="false" autocapitalize="off">'
            f"{disconnect_button}"
            '<button type="submit">Save key</button>'
            "</form>"
        )

    def _invalid_link(status_code: int = 404) -> HTMLResponse:
        return _result(
            _INVALID_LINK_MESSAGE,
            cls="error",
            status_code=status_code,
            heading="Register your provider key",
        )

    async def keys_get(request: Request) -> HTMLResponse:
        """Render the form for a valid grant. Peeks — never spends — the token."""
        token = request.query_params.get("token", "")
        grant = grant_store.peek(token)
        if grant is None:
            return _invalid_link()
        heading = _heading(grant)
        return _respond(_render_form(grant), heading=heading, title=heading)

    async def keys_post(request: Request) -> HTMLResponse:
        """Bind or disable the credential the grant authorizes. Nothing else."""
        form = await request.form()
        token = str(form.get("token") or "").strip()
        provider_key = str(form.get("provider_key") or "").strip()

        peeked = grant_store.peek(token)
        if peeked is None:
            return _invalid_link()
        heading = _heading(peeked)
        action = peeked.action

        # Validate inputs BEFORE spending the grant, so an empty submission is
        # correctable rather than burning the user's only link.
        if action is GrantAction.REGISTER_OR_ROTATE and not provider_key:
            return _respond(
                _render_form(peeked, "Paste your provider key to continue.", "error"),
                400,
                heading=heading,
                title=heading,
            )

        try:
            store = require_writer(store_factory())
        except StoreUnavailableError as exc:
            logger.error("registration attempted with no writable store: %s", exc)
            return _respond(
                _render_form(
                    peeked,
                    "This server's credential store isn't provisioned yet — ask the "
                    "operator to finish setup before registering a key.",
                    "error",
                ),
                503,
                heading=heading,
                title=heading,
            )

        outcome: ValidationOutcome | None = None
        if action is GrantAction.REGISTER_OR_ROTATE and validate:
            spec = catalogue.get(peeked.credential_id)
            outcome = await validate_key_async(spec, provider_key)
            if outcome.rejects_storage:
                # Definitive rejection: do NOT spend the grant, so the user can
                # correct a mistyped key on the same link.
                _audit(
                    AuditEvent(
                        action=AuditAction.GRANT_DENIED,
                        service=service,
                        outcome="invalid_key",
                        subject_hash=peeked.subject.hashed,
                        subject_kind=peeked.subject.kind,
                        credential_id=peeked.credential_id,
                        workflow=peeked.workflow,
                        reason="provider rejected the key",
                    )
                )
                return _respond(
                    _render_form(peeked, outcome.detail, "error"),
                    400,
                    heading=heading,
                    title=heading,
                )

        try:
            grant = consume_for(grant_store, token, action)
        except GrantError:
            return _invalid_link(409)

        _audit(
            AuditEvent(
                action=AuditAction.GRANT_EXCHANGED,
                service=service,
                outcome="ok",
                subject_hash=grant.subject.hashed,
                subject_kind=grant.subject.kind,
                credential_id=grant.credential_id,
                workflow=grant.workflow,
            )
        )

        if action is GrantAction.DISCONNECT:
            disabled = store.disable(grant.credential_id, grant.subject)
            _audit(
                AuditEvent(
                    action=AuditAction.CREDENTIAL_DISCONNECTED,
                    service=service,
                    outcome="ok" if disabled else "nothing_to_disable",
                    subject_hash=grant.subject.hashed,
                    subject_kind=grant.subject.kind,
                    credential_id=grant.credential_id,
                    workflow=grant.workflow,
                )
            )
            message = (
                "Your key has been disconnected. It is disabled immediately and will not be "
                "used again. If you suspect it leaked, revoke it at the provider too — that "
                "is the only action that stops it being used elsewhere."
                if disabled
                else "There was no active key registered for your account."
            )
            return _result(message, heading=heading)

        store.put_version(grant.credential_id, grant.subject, provider_key, outcome=outcome)
        _audit(
            AuditEvent(
                action=AuditAction.CREDENTIAL_REGISTERED,
                service=service,
                outcome=outcome.status.value if outcome else "stored",
                subject_hash=grant.subject.hashed,
                subject_kind=grant.subject.kind,
                credential_id=grant.credential_id,
                workflow=grant.workflow,
            )
        )

        confirmation = (
            "Key saved. It will never appear in any agent conversation, tool call, or log. "
            "You can close this page."
        )
        cls = "ok"
        if outcome and outcome.status is ValidationStatus.UNVERIFIED_TRANSIENT:
            confirmation = f"{outcome.detail} You can close this page."
            cls = "warn"
        return _result(confirmation, cls=cls, heading=heading)

    return KeysRoutes(get=keys_get, post=keys_post)
