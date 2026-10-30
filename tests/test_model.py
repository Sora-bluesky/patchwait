from __future__ import annotations

import datetime
import json
import unittest

from patchwait.model import (
    AwaitingDecision,
    Component,
    Done,
    Found,
    InProgress,
    LedgerItem,
    Match,
    NotFound,
    Reason,
    RuntimeKind,
    Undetermined,
    WaitingOnVendor,
    check_to_json,
    component_to_json,
    ledger_item_to_json,
    match_to_json,
)

LOCATION = "C:/Synthetic/App/resources/node.exe"


def _text(value: str) -> str:
    return value


def component() -> Component:
    return Component(RuntimeKind.NODE, LOCATION, Found("24.19.0"), "pe-version-resource")


class InvariantTests(unittest.TestCase):
    def test_undetermined_requires_detail(self) -> None:
        with self.assertRaises(ValueError):
            Undetermined(Reason.NOT_PE, "")
        with self.assertRaises(ValueError):
            Undetermined(Reason.NOT_PE, "   ")

    def test_undetermined_requires_reason(self) -> None:
        with self.assertRaises(TypeError):
            Undetermined("not_pe", "x")  # type: ignore[arg-type]

    def test_found_rejects_empty(self) -> None:
        for empty in ((), "", None, []):
            with self.assertRaises(ValueError):
                Found(empty)

    def test_match_rejects_empty_advisories(self) -> None:
        with self.assertRaises(ValueError):
            Match(component(), "osv", Found(()))
        with self.assertRaises(ValueError):
            Match(component(), "osv", Found(("GHSA-xxxx", "")))

    def test_ledger_statuses_reject_empty(self) -> None:
        for status in (WaitingOnVendor, InProgress, AwaitingDecision, Done):
            with self.assertRaises(ValueError):
                status("")

    def test_component_rejects_empty_fields(self) -> None:
        with self.assertRaises(ValueError):
            Component(RuntimeKind.NODE, "", Found("1.0.0"), "pe-version-resource")
        with self.assertRaises(ValueError):
            Component(RuntimeKind.NODE, LOCATION, Found("1.0.0"), "")
        with self.assertRaises(TypeError):
            Component(RuntimeKind.NODE, LOCATION, NotFound(), "e")  # type: ignore[arg-type]

    def test_frozen(self) -> None:
        with self.assertRaises(AttributeError):
            Found("x").value = "y"  # type: ignore[misc]


class JsonTests(unittest.TestCase):
    def test_check_shapes(self) -> None:
        self.assertEqual(check_to_json(Found("1.2.3"), _text), {"result": "found", "value": "1.2.3"})
        self.assertEqual(check_to_json(NotFound(), _text), {"result": "not_found"})
        self.assertEqual(
            check_to_json(Undetermined(Reason.SOURCE_RATE_LIMITED, "429"), _text),
            {"result": "undetermined", "reason": "source_rate_limited", "detail": "429"},
        )

    def test_match_and_ledger_round_trip_through_json(self) -> None:
        match = Match(component(), "osv", Found(("GHSA-aaaa-bbbb-cccc",)))
        encoded = json.loads(json.dumps(match_to_json(match)))
        self.assertEqual(encoded["advisories"], {"result": "found", "value": ["GHSA-aaaa-bbbb-cccc"]})
        self.assertEqual(encoded["component"]["version"], {"result": "found", "value": "24.19.0"})

        item = LedgerItem(
            id="L-1",
            title="Bundled runtime update",
            status=WaitingOnVendor("Example Vendor"),
            recheck_command="patchwait version-of node.exe --kind node",
            last_checked=datetime.date(2026, 10, 24),
            last_result=Undetermined(Reason.SOURCE_AUTH_EXPIRED, "sign-in expired"),
        )
        encoded = json.loads(json.dumps(ledger_item_to_json(item)))
        self.assertEqual(encoded["status"], {"state": "waiting_on_vendor", "vendor": "Example Vendor"})
        self.assertEqual(encoded["last_checked"], "2026-10-24")
        self.assertEqual(encoded["last_result"]["result"], "undetermined")

    def test_component_json(self) -> None:
        self.assertEqual(
            component_to_json(component()),
            {
                "kind": "node",
                "location": LOCATION,
                "version": {"result": "found", "value": "24.19.0"},
                "evidence": "pe-version-resource",
            },
        )


if __name__ == "__main__":
    unittest.main()
