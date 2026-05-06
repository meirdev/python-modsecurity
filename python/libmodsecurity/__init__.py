from contextlib import contextmanager
from typing import Iterator

from ._libmodsecurity import (
    Intervention,
    ModSecurity as _ModSecurity,
    RuleMessage,
    RulesSet,
    Transaction,
)


class ModSecurity(_ModSecurity):
    @contextmanager
    def transaction(self, rules: RulesSet) -> Iterator[Transaction]:
        """Yield a Transaction and guarantee process_logging() runs on exit.

        Use this instead of constructing Transaction directly when audit
        logging matters: process_logging() is what writes the audit record,
        and forgetting it (or skipping it because of an exception) silently
        drops the entry.

        The transaction is finalized even if the body of the `with` block
        raises; any error from process_logging() itself is swallowed so it
        doesn't mask the original exception.
        """
        t = Transaction(self, rules)
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
__version__: str = "3.0.15"
