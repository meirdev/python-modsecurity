from contextlib import AbstractContextManager
from typing import List

from ._libmodsecurity import (
    Intervention as Intervention,
    ModSecurity as _ModSecurity,
    RuleMessage as RuleMessage,
    RulesSet as RulesSet,
    Transaction as Transaction,
)

__version__: str
__all__: List[str]

class ModSecurity(_ModSecurity):
    def transaction(
        self, rules: RulesSet, id: str | None = None
    ) -> AbstractContextManager[Transaction]:
        """Yield a Transaction and guarantee process_logging() runs on exit.

        Use this instead of constructing Transaction directly when audit
        logging matters: process_logging() is what writes the audit record,
        and forgetting it (or skipping it because of an exception) silently
        drops the entry.

        The transaction is finalized even if the body of the `with` block
        raises; any error from process_logging() itself is swallowed so it
        doesn't mask the original exception.
        """
        ...
