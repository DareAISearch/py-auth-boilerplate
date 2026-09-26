import pytest

from py_auth_boilerplate.claims import UNSET, assert_claim_matches
from py_auth_boilerplate.errors import ForbiddenError


class TestAssertClaimMatches:
    def test_is_a_noop_when_supplied_value_is_unset_omitted_entirely(self) -> None:
        assert_claim_matches({"webhook_url": "https://caller.example.com/hook"}, "webhook_url")

    def test_is_a_noop_when_supplied_value_is_unset_even_if_identity_is_none(self) -> None:
        assert_claim_matches(None, "webhook_url", UNSET)

    def test_passes_when_supplied_value_matches_the_registered_claim(self) -> None:
        assert_claim_matches(
            {"webhook_url": "https://caller.example.com/hook"},
            "webhook_url",
            "https://caller.example.com/hook",
        )

    def test_raises_forbidden_error_when_supplied_value_does_not_match_the_registered_claim(self) -> None:
        with pytest.raises(ForbiddenError):
            assert_claim_matches(
                {"webhook_url": "https://caller.example.com/hook"},
                "webhook_url",
                "https://someone-else.example.com/hook",
            )

    def test_treats_an_explicit_none_as_a_real_asserted_value_not_a_noop(self) -> None:
        # An explicit None (JSON null) is checked like any other value, not skipped like UNSET --
        # otherwise a caller could bypass the ownership check by nulling the field.
        with pytest.raises(ForbiddenError):
            assert_claim_matches({"webhook_url": "https://caller.example.com/hook"}, "webhook_url", None)

    def test_an_explicit_none_matches_when_the_registered_claim_is_itself_none(self) -> None:
        assert_claim_matches({"webhook_url": None}, "webhook_url", None)
