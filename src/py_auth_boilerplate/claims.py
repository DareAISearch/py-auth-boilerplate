from collections.abc import Mapping
from typing import Any

from .errors import ForbiddenError


class _Unset:
    __slots__ = ()

    def __repr__(self) -> str:
        return "UNSET"


# Distinguishable sentinel so assert_claim_matches can tell "caller didn't send this field at
# all" apart from "caller explicitly sent null" -- dict.get() collapses both to None otherwise.
UNSET: Any = _Unset()


def assert_claim_matches(
    identity: Mapping[str, Any] | None, claim_name: str, supplied_value: Any = UNSET
) -> None:
    if supplied_value is UNSET:
        return
    if identity is None or supplied_value != identity.get(claim_name):
        raise ForbiddenError(f"{claim_name} does not match the authenticated caller's registered claim")
