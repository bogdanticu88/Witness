from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from conftest import HELLO
from witness.errors import SemanticError, SemanticRequestError, SemanticTimeout
from witness.semantic import client as client_module
from witness.semantic import protocol as p
from witness.semantic.client import SemanticClient, locate_helper
from witness.store import Store
from witness.triage.engine import Helper, run_triage

pytestmark = pytest.mark.integration

REPORTS = Path(__file__).resolve().parents[2] / "fixtures" / "reports"
Fake = Callable[[str], Path]


def test_missing_helper_is_reported_with_a_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WITNESS_SEMANTIC_HELPER", raising=False)
    monkeypatch.setattr(client_module.shutil, "which", lambda _: None)
    monkeypatch.setattr(client_module, "__file__", "/nonexistent/a/b/c/client.py")
    with pytest.raises(SemanticError) as caught:
        locate_helper(None)
    assert caught.value.hint and "Semantic analysis is required" in caught.value.hint


def test_configured_helper_is_never_swapped_for_another(helper_path: Path) -> None:
    # A dev build exists, but an explicit path that does not work is an error.
    with pytest.raises(SemanticError, match="not an executable file"):
        locate_helper("/nonexistent/witness-semantic")


def test_triage_refuses_to_run_without_a_helper(repo: Path, tmp_path: Path) -> None:
    def no_helper() -> Helper:
        raise SemanticError("the Roslyn semantic helper (witness-semantic) was not found")

    with Store.open(tmp_path / "w.db") as store:
        with pytest.raises(SemanticError):
            run_triage(
                [REPORTS / "codeql" / "acme-orders.sarif"],
                repo,
                store=store,
                helper_factory=no_helper,
            )
        rows = store._query("SELECT COUNT(*) FROM runs")
    assert rows[0][0] == 0


def test_incompatible_protocol_is_refused(fake_helper: Fake) -> None:
    helper = fake_helper(
        "reply({'id': request['id'], 'result': {'protocol': 'witness.semantic/2', "
        "'helper_version': '2.0.0', 'roslyn_version': 'x', 'strategy': 'x'}})"
    )
    with pytest.raises(SemanticError, match=r"witness\.semantic/2"):
        SemanticClient(helper, timeout_s=10)


def test_malformed_hello_is_refused(fake_helper: Fake) -> None:
    helper = fake_helper(
        "reply({'id': request['id'], 'result': {'protocol': 'witness.semantic/1'}})"
    )
    with pytest.raises(SemanticError, match="malformed hello"):
        SemanticClient(helper, timeout_s=10)


def test_invalid_json_is_an_error(fake_helper: Fake) -> None:
    helper = fake_helper(
        f"""
        if count == 1:
            reply({HELLO})
        else:
            sys.stdout.write('not json\\n'); sys.stdout.flush()
        """
    )
    with (
        SemanticClient(helper, timeout_s=10) as client,
        pytest.raises(SemanticError, match="invalid JSON"),
    ):
        client.call("load", {"root": "/x"}, p.LoadResult)


def test_answer_to_another_request_is_an_error(fake_helper: Fake) -> None:
    helper = fake_helper(
        f"""
        if count == 1:
            reply({HELLO})
        else:
            reply({{'id': request['id'] + 7, 'result': {{}}}})
        """
    )
    with (
        SemanticClient(helper, timeout_s=10) as client,
        pytest.raises(SemanticError, match="out of order"),
    ):
        client.call("load", {"root": "/x"}, p.LoadResult)


def test_malformed_error_object_is_an_error(fake_helper: Fake) -> None:
    helper = fake_helper(
        f"""
        if count == 1:
            reply({HELLO})
        else:
            reply({{'id': request['id'], 'error': 'boom'}})
        """
    )
    with (
        SemanticClient(helper, timeout_s=10) as client,
        pytest.raises(SemanticError, match="malformed error"),
    ):
        client.call("load", {"root": "/x"}, p.LoadResult)


def test_error_response_keeps_the_helper_usable(fake_helper: Fake) -> None:
    helper = fake_helper(
        f"""
        if count == 1:
            reply({HELLO})
        elif count == 2:
            error = {{'code': 'unknown_document', 'message': 'nope'}}
            reply({{'id': request['id'], 'error': error}})
        else:
            loaded = {{'root': '/x', 'projects': [], 'strategy': 's', 'load_ms': 1}}
            reply({{'id': request['id'], 'result': loaded}})
        """
    )
    with SemanticClient(helper, timeout_s=10) as client:
        with pytest.raises(SemanticRequestError) as caught:
            client.call("load", {"root": "/x"}, p.LoadResult)
        assert caught.value.code == "unknown_document"
        assert client.call("load", {"root": "/x"}, p.LoadResult).root == "/x"


def test_malformed_result_is_an_error(fake_helper: Fake) -> None:
    helper = fake_helper(
        f"""
        if count == 1:
            reply({HELLO})
        else:
            reply({{'id': request['id'], 'result': {{'sites': 'not a list'}}}})
        """
    )
    with (
        SemanticClient(helper, timeout_s=10) as client,
        pytest.raises(SemanticError, match="malformed"),
    ):
        client.call("sites_at", {"path": "a", "start_line": 1}, p.SitesAt)


def test_timeout_stops_the_helper(fake_helper: Fake) -> None:
    helper = fake_helper(
        f"""
        if count == 1:
            reply({HELLO})
        else:
            time.sleep(30)
        """
    )
    client = SemanticClient(helper, timeout_s=1)
    with pytest.raises(SemanticTimeout):
        client.call("load", {"root": "/x"}, p.LoadResult)
    assert client._proc.poll() is not None


def test_crash_is_reported_with_exit_code(fake_helper: Fake) -> None:
    helper = fake_helper(
        f"""
        if count == 1:
            reply({HELLO})
        else:
            sys.stderr.write('fatal: out of memory\\n'); sys.stderr.flush()
            sys.exit(3)
        """
    )
    with SemanticClient(helper, timeout_s=10) as client, pytest.raises(SemanticError) as caught:
        client.call("load", {"root": "/x"}, p.LoadResult)
    assert "exited" in caught.value.message
    assert not isinstance(caught.value, SemanticTimeout)


def test_helper_that_exits_at_start_is_refused(fake_helper: Fake) -> None:
    helper = fake_helper("sys.exit(1)")
    with pytest.raises(SemanticError, match="exited"):
        SemanticClient(helper, timeout_s=10)


def test_real_helper_reports_its_protocol(helper_path: Path) -> None:
    with SemanticClient(helper_path, timeout_s=120) as client:
        assert client.hello.protocol == p.PROTOCOL_VERSION
        assert client.hello.helper_version
        assert {pack["name"] for pack in client.hello.ref_packs} >= {"Microsoft.NETCore.App.Ref"}
