from typing import Callable, List, Optional

class RuleMessage:
    """A structured rule-match record. Populated by libmodsecurity each time
    a non-disruptive SecRule fires, and delivered to the callback registered
    via ModSecurity.set_rule_message_callback()."""

    rule_id: int
    """Numeric rule id (the SecRule `id:N` action)."""

    phase: int
    """SecLanguage phase the rule fired in (1 through 5)."""

    severity: int
    """Rule severity (0=EMERGENCY, 7=DEBUG)."""

    accuracy: int
    """Rule's `accuracy:N` value, or 0 if unset."""

    maturity: int
    """Rule's `maturity:N` value, or 0 if unset."""

    line: int
    """Line number of the rule in its source file."""

    disruptive: bool
    """True if the rule action is disruptive (deny, drop, redirect); False
    for warn/log/pass matches."""

    no_audit_log: bool
    """True if the `noauditlog` action was applied."""

    message: str
    """Value of the rule's `msg:` action."""

    match: str
    """The substring or value that matched the rule's operator."""

    data: str
    """Value of the rule's `logdata:` action."""

    reference: str
    """Variable references describing where the match occurred (e.g.
    "o0,4v9,4")."""

    rev: str
    """Rule revision string from the `rev:` action."""

    ver: str
    """Rule version string from the `ver:` action."""

    file: str
    """Source file the rule was loaded from, or empty if loaded from an
    in-memory string."""

    tags: List[str]
    """List of tags attached to the rule via `tag:`."""

class Intervention:
    """An action requested by ModSecurity (block, redirect, log) following a
    process_* call. Returned by Transaction.intervention()."""

    status: int
    """HTTP status code to return to the client (e.g. 403). Defaults to 200
    if no rule overrode it."""

    url: Optional[str]
    """Redirect URL to send the client to, or None."""

    log: Optional[str]
    """Human-readable log message describing why the action was taken, or
    None."""

    pause: bool
    """Whether the connector should pause processing."""

    disruptive: bool
    """True for disruptive actions (block, redirect); False for log-only
    events."""

class ModSecurity:
    """Top-level ModSecurity engine. One instance is shared across all
    transactions; pair it with a RulesSet to drive request inspection."""

    def __init__(self) -> None: ...
    def set_connector_information(self, info: str) -> None:
        """Set information about the connector using the library.

        Used in audit logs to identify the integration. Recommended pattern:
            "ConnectorName vX.Y.Z-tag (extra)"
        for example, "ModSecurity-nginx v0.0.1-alpha (Whee)".
        """
        ...

    def who_am_i(self) -> str:
        """Return information about the ModSecurity version and platform.

        Format is stable so log parsers can rely on it; new fields are only
        appended to the end of the string.
        """
        ...

    def set_log_callback(self, callback: Optional[Callable[[str], None]]) -> None:
        """Register a callable to receive ModSecurity server-log messages
        as formatted text (Apache-style log lines). Pass None to
        unregister.

        Exceptions raised by the callback are reported via
        sys.unraisablehook and do not propagate into rule evaluation.

        Replaces any previously installed log or rule-message callback on
        this engine. Unregister with set_log_callback(None) before letting
        this ModSecurity instance be garbage collected, otherwise the
        registry entry leaks until process exit.
        """
        ...

    def set_rule_message_callback(
        self, callback: Optional[Callable[[RuleMessage], None]]
    ) -> None:
        """Register a callable to receive structured RuleMessage objects
        (rule id, severity, message, match, tags, etc.) instead of
        formatted text. Pass None to unregister.

        The RuleMessage passed in is fully copied from libmodsecurity; it
        is safe to keep references to it past the callback's return.

        Replaces any previously installed log or rule-message callback on
        this engine. Same lifetime caveat as set_log_callback().
        """
        ...

class RulesSet:
    """A compiled set of SecRules. Load rules with load() or load_from_uri()
    before passing the RulesSet to a Transaction."""

    def __init__(self) -> None: ...
    def load_from_uri(self, uri: str) -> int:
        """Load rules from a file path.

        Returns the number of rules loaded, or -1 on parse failure (call
        get_parser_error() for details).
        """
        ...

    def load(self, plain_rules: str) -> int:
        """Load rules from an in-memory string of SecLanguage directives.

        Returns the number of rules loaded, or -1 on parse failure (call
        get_parser_error() for details).
        """
        ...

    def get_parser_error(self) -> str:
        """Return the parser error from the last failed load. Empty if the
        last load succeeded."""
        ...

class Transaction:
    """A single HTTP request/response analysis cycle.

    Drive a Transaction through the SecRules phases by calling, in order:
      process_connection -> process_uri ->
      add_request_header* -> process_request_headers ->
      append_request_body* -> process_request_body ->
      add_response_header* -> process_response_headers ->
      append_response_body* -> process_response_body ->
      process_logging

    After each step, call intervention() to see whether the engine wants the
    connector to block, redirect, or pause the request.
    """

    def __init__(self, modsecurity: ModSecurity, rules: RulesSet) -> None: ...
    def process_connection(
        self,
        client_ip: str,
        client_port: int,
        server_ip: str,
        server_port: int,
    ) -> int:
        """Run analysis on the connection. Should be the very first call on
        a transaction, before virtual host resolution.

        Remember to call intervention() afterwards.
        """
        ...

    def process_uri(self, uri: str, method: str, http_version: str) -> int:
        """Run analysis on the URI and query-string variables.

        Sits logically between SecLanguage phases 1 and 2. Remember to call
        intervention() afterwards.
        """
        ...

    def add_request_header(self, name: str, value: str) -> int:
        """Feed ModSecurity a request header. Add all headers before calling
        process_request_headers()."""
        ...

    def process_request_headers(self) -> int:
        """Run analysis on the request headers (SecLanguage phase 1). All
        request headers must have been added first via add_request_header().

        Remember to call intervention() afterwards.
        """
        ...

    def append_request_body(self, body: bytes) -> int:
        """Feed ModSecurity request body bytes for inspection. May be called
        repeatedly to stream the body in chunks.

        Buffering each chunk is computationally expensive; check
        intervention() between chunks because rules may set a maximum
        inspection size.
        """
        ...

    def process_request_body(self) -> int:
        """Run analysis on the request body (SecLanguage phase 2). Optional
        if there is no body. The body must have been appended first via
        append_request_body().

        Remember to call intervention() afterwards.
        """
        ...

    def add_response_header(self, name: str, value: str) -> int:
        """Feed ModSecurity a response header. Add all headers before
        calling process_response_headers()."""
        ...

    def process_response_headers(self, status_code: int, protocol: str) -> int:
        """Run analysis on the response headers (SecLanguage phase 3).

        Pass the HTTP status code and the protocol string (for example,
        "HTTP/1.1"). All response headers must have been added first.
        Remember to call intervention() afterwards.
        """
        ...

    def append_response_body(self, body: bytes) -> int:
        """Feed ModSecurity response body bytes for inspection. ModSecurity
        may also rewrite the body (limited support); if it does, do not send
        the original Content-Length header to the client."""
        ...

    def process_response_body(self) -> int:
        """Run analysis on the response body (SecLanguage phase 4). Optional
        if there is no body. The body must have been appended first via
        append_response_body().

        Remember to call intervention() afterwards.
        """
        ...

    def process_logging(self) -> int:
        """Run the logging phase (SecLanguage phase 5). Writes the audit log
        if the transaction is relevant. The response can already have been
        delivered to the client when this is called."""
        ...

    def intervention(self) -> Optional[Intervention]:
        """Return an Intervention if ModSecurity wants the connector to act
        (block, redirect, log), otherwise None. Should be called after each
        process_* step."""
        ...

    def get_rule_messages(self) -> List[RuleMessage]:
        """Return all RuleMessage records collected for this transaction.

        Each entry corresponds to a SecRule that matched during
        evaluation, covering both disruptive and non-disruptive matches.
        Useful for shipping audit events to a SIEM after process_logging()
        has run.
        """
        ...
