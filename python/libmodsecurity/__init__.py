from contextlib import contextmanager
from importlib.metadata import version
from typing import Iterator, Optional

from ._libmodsecurity import (
    Intervention,
    ModSecurity as _ModSecurity,
    RuleMessage,
    RulesSet,
    Transaction,
)


class ModSecurity(_ModSecurity):
    @contextmanager
    def transaction(
        self, rules: RulesSet, id: Optional[str] = None
    ) -> Iterator[Transaction]:
        """Yield a Transaction and guarantee process_logging() runs on exit.

        Use this instead of constructing Transaction directly when audit
        logging matters: process_logging() is what writes the audit record,
        and forgetting it (or skipping it because of an exception) silently
        drops the entry.

        Pass `id` to override the auto-generated transaction id (matches
        modsecurity-nginx's `modsecurity_transaction_id` directive); useful
        for correlating audit entries with upstream request IDs.

        The transaction is finalized even if the body of the `with` block
        raises; any error from process_logging() itself is swallowed so it
        doesn't mask the original exception.
        """
        t = Transaction(self, rules, id)
        try:
            yield t
        finally:
            try:
                t.process_logging()
            except Exception:
                pass


__all__ = [
    "Intervention",
    "ModSecurity",
    "RuleMessage",
    "RulesSet",
    "Transaction",
]
__version__: str = version("libmodsecurity")
