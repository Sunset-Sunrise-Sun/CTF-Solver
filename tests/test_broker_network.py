"""Broker network-scope, redirect and DNS revalidation tests.

All destinations are synthetic. No real DNS lookup, socket or target access is
performed: resolved addresses are injected test data, exactly as the policy
contract requires.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ctf_solver.core.errors import DenyReason
from ctf_solver.core.types import BrokerDecision, ExecutionTier, GrantStatus
from ctf_solver.policy.broker import Broker, BrokerConfig
from ctf_solver.policy.models import (
    GrantScope,
    grant_allows_private,
    is_loopback_host,
    is_loopback_ip,
    is_private_host,
    is_private_ip,
    normalize_path_prefix,
    path_prefix_matches,
)
from ctf_solver.runtime.catalog import RuntimeCatalog
from tests.test_runtime_support import (
    BASE_NOW_MS,
    LOOPBACK_HOST,
    PRIVATE_HOST,
    PUBLIC_HOST,
    TASK_ID,
    WORKER_TOKEN,
    BoundTask,
    bind_task,
    catalog_with,
    file_fixture,
    make_grant,
    make_network_target,
    network_stub_tool,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def network_broker(
    bound: BoundTask,
    *,
    tool: object | None = None,
    config: BrokerConfig | None = None,
) -> Broker:
    tool = tool or network_stub_tool()
    catalog = catalog_with(tool)  # type: ignore[arg-type]
    return Broker(
        bound.repository,
        catalog,
        bound.clock,
        config=config or BrokerConfig(network_enabled=True),
    )


def network_request(
    bound: BoundTask,
    *,
    tool_name: str = "synth.network_probe",
    host: str = PUBLIC_HOST,
    port: int = 443,
    protocol: str = "https",
    method: str = "GET",
    path: str = "/",
    grant_id: str | None = "grant-1",
    **overrides: object,
):
    return bound.request(
        tool_name=tool_name,
        argv=["probe"],
        network_target=make_network_target(
            host=host, port=port, protocol=protocol, method=method, path=path
        ),
        network_grant_id=grant_id,
        **overrides,
    )


def assert_denied(decision: BrokerDecision, reason: DenyReason) -> None:
    assert decision.allowed is False
    assert decision.reason_code == reason.value, (
        f"expected {reason.value!r}, got {decision.reason_code!r}: {decision.reason}"
    )


# ---------------------------------------------------------------------------
# Grant allow path and consumption
# ---------------------------------------------------------------------------


def test_allow_valid_grant_and_consume_call(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    bound.repository.add_grant(make_grant())
    broker = network_broker(bound)
    decision = broker.authorize(network_request(bound), WORKER_TOKEN)
    assert decision.allowed is True
    assert decision.reason_code == "allowed"
    assert decision.network_grant_id == "grant-1"
    assert decision.grant_call_consumed is True
    assert bound.repository.grants["grant-1"].calls_used == 1


def test_allow_host_is_case_insensitive(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    bound.repository.add_grant(make_grant(host="Example.COM."))
    broker = network_broker(bound)
    assert broker.authorize(network_request(bound, host="example.com"), WORKER_TOKEN).allowed


def test_allow_path_inside_granted_prefix(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    bound.repository.add_grant(make_grant(path_prefix="/api"))
    broker = network_broker(bound)
    assert broker.authorize(network_request(bound, path="/api/v1/items"), WORKER_TOKEN).allowed


def test_allow_exact_granted_path_prefix(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    bound.repository.add_grant(make_grant(path_prefix="/api"))
    broker = network_broker(bound)
    assert broker.authorize(network_request(bound, path="/api"), WORKER_TOKEN).allowed


def test_network_tool_without_target_is_denied(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = network_broker(bound)
    request = bound.request(tool_name="synth.network_probe", argv=["probe"])
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.NETWORK_TARGET_MISSING)


def test_grant_id_without_target_is_denied(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    file_fixture(bound.workspace, "input.txt", b"x")
    broker = network_broker(bound)
    request = bound.request(argv=["input.txt"], network_grant_id="grant-1")
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.NETWORK_TARGET_MISSING)


def test_file_tool_with_network_target_is_denied(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    bound.repository.add_grant(make_grant())
    broker = network_broker(bound)
    request = bound.request(
        tool_name="internal.file_hash",
        argv=["input.txt"],
        network_target=make_network_target(),
        network_grant_id="grant-1",
    )
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.INVALID_REQUEST)


# ---------------------------------------------------------------------------
# Grant denial matrix
# ---------------------------------------------------------------------------


def test_deny_target_without_grant_id(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = network_broker(bound)
    request = network_request(bound, grant_id=None)
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.GRANT_MISSING)


def test_deny_unknown_grant(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = network_broker(bound)
    assert_denied(
        broker.authorize(network_request(bound, grant_id="missing-grant"), WORKER_TOKEN),
        DenyReason.GRANT_MISSING,
    )


def test_deny_grant_for_other_task(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    bound.repository.add_grant(make_grant(task_id="task-2"))
    broker = network_broker(bound)
    assert_denied(
        broker.authorize(network_request(bound), WORKER_TOKEN), DenyReason.GRANT_TASK_MISMATCH
    )


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        (GrantStatus.REVOKED, DenyReason.GRANT_INVALID),
        (GrantStatus.EXPIRED, DenyReason.GRANT_EXPIRED),
        (GrantStatus.EXHAUSTED, DenyReason.GRANT_EXHAUSTED),
    ],
)
def test_deny_grant_status(
    tmp_path: Path, status: GrantStatus, reason: DenyReason
) -> None:
    bound = bind_task(tmp_path)
    bound.repository.add_grant(make_grant(status=status))
    broker = network_broker(bound)
    assert_denied(broker.authorize(network_request(bound), WORKER_TOKEN), reason)


def test_deny_grant_past_expiry(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    bound.repository.add_grant(make_grant(expires_at=BASE_NOW_MS - 1))
    broker = network_broker(bound)
    assert_denied(
        broker.authorize(network_request(bound), WORKER_TOKEN), DenyReason.GRANT_EXPIRED
    )


def test_deny_grant_call_budget_exhausted(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    bound.repository.add_grant(make_grant(max_calls=2, calls_used=2))
    broker = network_broker(bound)
    assert_denied(
        broker.authorize(network_request(bound), WORKER_TOKEN), DenyReason.GRANT_EXHAUSTED
    )


def test_deny_grant_without_call_budget(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    bound.repository.add_grant(make_grant(max_calls=0, calls_used=0))
    broker = network_broker(bound)
    assert_denied(
        broker.authorize(network_request(bound), WORKER_TOKEN), DenyReason.GRANT_INVALID
    )


def test_deny_grant_profile_mismatch(tmp_path: Path) -> None:
    bound = bind_task(tmp_path, scope_profile="competition-a")
    bound.repository.add_grant(make_grant(competition_profile="competition-b"))
    broker = network_broker(bound)
    assert_denied(
        broker.authorize(network_request(bound), WORKER_TOKEN), DenyReason.GRANT_PROFILE_MISMATCH
    )


def test_allow_matching_grant_profile(tmp_path: Path) -> None:
    bound = bind_task(tmp_path, scope_profile="competition-a")
    bound.repository.add_grant(make_grant(competition_profile="competition-a"))
    broker = network_broker(bound)
    assert broker.authorize(network_request(bound), WORKER_TOKEN).allowed is True


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"host": "1.1.1.1"}, DenyReason.GRANT_HOST_MISMATCH),
        ({"port": 8443}, DenyReason.GRANT_PORT_MISMATCH),
        ({"protocol": "http"}, DenyReason.GRANT_PROTOCOL_MISMATCH),
        ({"method": "POST"}, DenyReason.GRANT_ACTION_MISMATCH),
    ],
)
def test_deny_target_outside_grant(
    tmp_path: Path, overrides: dict[str, object], reason: DenyReason
) -> None:
    bound = bind_task(tmp_path)
    bound.repository.add_grant(make_grant())
    broker = network_broker(bound)
    assert_denied(broker.authorize(network_request(bound, **overrides), WORKER_TOKEN), reason)


def test_deny_target_path_outside_grant_prefix(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    bound.repository.add_grant(make_grant(path_prefix="/api"))
    broker = network_broker(bound)
    assert_denied(
        broker.authorize(network_request(bound, path="/admin"), WORKER_TOKEN),
        DenyReason.GRANT_PATH_MISMATCH,
    )


def test_deny_when_network_execution_disabled(tmp_path: Path) -> None:
    """The shipped default fails closed for target traffic in Round 1."""

    bound = bind_task(tmp_path)
    bound.repository.add_grant(make_grant())
    broker = network_broker(bound, config=BrokerConfig())  # network_enabled=False
    decision = broker.authorize(network_request(bound), WORKER_TOKEN)
    assert_denied(decision, DenyReason.TIER_NOT_AVAILABLE)
    assert bound.repository.grants["grant-1"].calls_used == 0


def test_grant_call_not_consumed_when_atomic_consumption_fails(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    bound.repository.add_grant(make_grant())

    class _RefusingRepository(type(bound.repository)):  # type: ignore[misc]
        pass

    repository = _RefusingRepository(clock=bound.clock)
    repository.add_task(bound.task)
    repository.add_worker(bound.worker)
    repository.add_grant(make_grant())
    repository.consume_grant_call = lambda grant_id, now_ms: False  # type: ignore[assignment]
    broker = Broker(
        repository,
        catalog_with(network_stub_tool()),
        bound.clock,
        config=BrokerConfig(network_enabled=True),
    )
    decision = broker.authorize(network_request(bound), WORKER_TOKEN)
    assert_denied(decision, DenyReason.GRANT_INVALID)


# ---------------------------------------------------------------------------
# Loopback / private destinations are not implicitly trusted
# ---------------------------------------------------------------------------


def test_allow_explicit_private_host_grant(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    bound.repository.add_grant(make_grant(host=PRIVATE_HOST))
    broker = network_broker(bound)
    decision = broker.authorize(network_request(bound, host=PRIVATE_HOST), WORKER_TOKEN)
    assert decision.allowed is True


def test_allow_explicit_loopback_host_grant(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    bound.repository.add_grant(make_grant(host=LOOPBACK_HOST))
    broker = network_broker(bound)
    decision = broker.authorize(network_request(bound, host=LOOPBACK_HOST), WORKER_TOKEN)
    assert decision.allowed is True


def test_deny_private_target_without_grant(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    broker = network_broker(bound)
    request = network_request(bound, host=PRIVATE_HOST, grant_id=None)
    assert_denied(broker.authorize(request, WORKER_TOKEN), DenyReason.GRANT_MISSING)


def test_deny_private_target_with_public_host_grant(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    bound.repository.add_grant(make_grant(host=PUBLIC_HOST))
    broker = network_broker(bound)
    assert_denied(
        broker.authorize(network_request(bound, host=PRIVATE_HOST), WORKER_TOKEN),
        DenyReason.GRANT_HOST_MISMATCH,
    )


def test_deny_loopback_target_with_public_host_grant(tmp_path: Path) -> None:
    bound = bind_task(tmp_path)
    bound.repository.add_grant(make_grant(host=PUBLIC_HOST))
    broker = network_broker(bound)
    assert_denied(
        broker.authorize(network_request(bound, host=LOOPBACK_HOST), WORKER_TOKEN),
        DenyReason.GRANT_HOST_MISMATCH,
    )


# ---------------------------------------------------------------------------
# Redirect revalidation
# ---------------------------------------------------------------------------


def redirect_broker(tmp_path: Path) -> tuple[BoundTask, Broker]:
    bound = bind_task(tmp_path)
    bound.repository.add_grant(make_grant())
    return bound, network_broker(bound)


def test_redirect_same_destination_allowed(tmp_path: Path) -> None:
    bound, broker = redirect_broker(tmp_path)
    target = make_network_target()
    decision = broker.validate_redirect(make_grant(), target, target)
    assert decision.allowed is True
    assert decision.network_grant_id == "grant-1"


@pytest.mark.parametrize(
    ("redirect", "grant"),
    [
        (make_network_target(host="1.1.1.1"), make_grant()),
        (make_network_target(port=8443), make_grant()),
        (make_network_target(protocol="http"), make_grant()),
        (make_network_target(method="POST"), make_grant()),
        (make_network_target(path="/admin"), make_grant(path_prefix="/api")),
    ],
)
def test_redirect_out_of_scope_denied(tmp_path: Path, redirect: object, grant: object) -> None:
    _, broker = redirect_broker(tmp_path)
    decision = broker.validate_redirect(
        grant, make_network_target(), redirect  # type: ignore[arg-type]
    )
    assert_denied(decision, DenyReason.REDIRECT_SCOPE_VIOLATION)


def test_redirect_private_destination_denied_without_flag(tmp_path: Path) -> None:
    bound, broker = redirect_broker(tmp_path)
    grant = make_grant(host=PRIVATE_HOST)
    decision = broker.validate_redirect(
        grant,
        make_network_target(host=PRIVATE_HOST),
        make_network_target(host=PRIVATE_HOST, path="/internal"),
    )
    assert_denied(decision, DenyReason.REDIRECT_SCOPE_VIOLATION)


def test_redirect_private_destination_allowed_with_flag(tmp_path: Path) -> None:
    bound, broker = redirect_broker(tmp_path)
    grant = make_grant(host=PRIVATE_HOST)
    scope = GrantScope.from_record(grant, allow_private=True)
    decision = broker.validate_redirect(
        scope,
        make_network_target(host=PRIVATE_HOST),
        make_network_target(host=PRIVATE_HOST, path="/internal"),
    )
    assert decision.allowed is True


def test_redirect_loopback_destination_denied_without_flag(tmp_path: Path) -> None:
    bound, broker = redirect_broker(tmp_path)
    grant = make_grant(host=LOOPBACK_HOST)
    decision = broker.validate_redirect(
        grant,
        make_network_target(host=LOOPBACK_HOST),
        make_network_target(host=LOOPBACK_HOST, path="/admin"),
    )
    assert_denied(decision, DenyReason.REDIRECT_SCOPE_VIOLATION)


def test_redirect_denied_when_grant_expired(tmp_path: Path) -> None:
    bound, broker = redirect_broker(tmp_path)
    grant = make_grant(expires_at=BASE_NOW_MS - 1)
    decision = broker.validate_redirect(
        grant, make_network_target(), make_network_target()
    )
    assert_denied(decision, DenyReason.GRANT_EXPIRED)


def test_redirect_invalid_target_denied(tmp_path: Path) -> None:
    bound, broker = redirect_broker(tmp_path)
    decision = broker.validate_redirect(
        make_grant(), make_network_target(), make_network_target(port=0)
    )
    assert_denied(decision, DenyReason.INVALID_REQUEST)


def test_redirect_requires_grant_scope(tmp_path: Path) -> None:
    bound, broker = redirect_broker(tmp_path)
    decision = broker.validate_redirect(object(), make_network_target(), make_network_target())
    assert_denied(decision, DenyReason.GRANT_INVALID)


def test_redirect_original_target_must_be_network_target(tmp_path: Path) -> None:
    bound, broker = redirect_broker(tmp_path)
    decision = broker.validate_redirect(make_grant(), {"host": "x"}, make_network_target())
    assert_denied(decision, DenyReason.INVALID_REQUEST)


def test_redirect_in_path_scope_allowed(tmp_path: Path) -> None:
    bound, broker = redirect_broker(tmp_path)
    grant = make_grant(path_prefix="/api")
    decision = broker.validate_redirect(
        grant, make_network_target(path="/api"), make_network_target(path="/api/v2")
    )
    assert decision.allowed is True


# ---------------------------------------------------------------------------
# DNS revalidation (injected synthetic answers only)
# ---------------------------------------------------------------------------


def dns_broker(tmp_path: Path) -> tuple[BoundTask, Broker]:
    bound = bind_task(tmp_path)
    bound.repository.add_grant(make_grant())
    return bound, network_broker(bound)


def test_dns_public_answers_allowed(tmp_path: Path) -> None:
    _, broker = dns_broker(tmp_path)
    decision = broker.validate_resolved_address(
        make_grant(), make_network_target(), [PUBLIC_HOST, "1.1.1.1"]
    )
    assert decision.allowed is True


def test_dns_hostname_grant_public_answers_allowed(tmp_path: Path) -> None:
    _, broker = dns_broker(tmp_path)
    grant = make_grant(host="example.com")
    decision = broker.validate_resolved_address(
        grant, make_network_target(host="example.com"), [PUBLIC_HOST]
    )
    assert decision.allowed is True


def test_dns_empty_answers_denied(tmp_path: Path) -> None:
    _, broker = dns_broker(tmp_path)
    decision = broker.validate_resolved_address(make_grant(), make_network_target(), [])
    assert_denied(decision, DenyReason.DNS_SCOPE_VIOLATION)


def test_dns_unparseable_answer_denied(tmp_path: Path) -> None:
    _, broker = dns_broker(tmp_path)
    decision = broker.validate_resolved_address(
        make_grant(), make_network_target(), ["not-an-ip-address"]
    )
    assert_denied(decision, DenyReason.DNS_SCOPE_VIOLATION)


def test_dns_private_answer_denied_without_flag(tmp_path: Path) -> None:
    _, broker = dns_broker(tmp_path)
    grant = make_grant(host="example.com")
    decision = broker.validate_resolved_address(
        grant, make_network_target(host="example.com"), [PUBLIC_HOST, PRIVATE_HOST]
    )
    assert_denied(decision, DenyReason.DNS_SCOPE_VIOLATION)


def test_dns_private_answer_allowed_with_flag(tmp_path: Path) -> None:
    _, broker = dns_broker(tmp_path)
    grant = make_grant(host="example.com")
    scope = GrantScope.from_record(grant, allow_private=True)
    decision = broker.validate_resolved_address(
        scope, make_network_target(host="example.com"), [PRIVATE_HOST]
    )
    assert decision.allowed is True


def test_dns_out_of_scope_target_denied(tmp_path: Path) -> None:
    _, broker = dns_broker(tmp_path)
    grant = make_grant(host="example.com")
    decision = broker.validate_resolved_address(
        grant, make_network_target(host="other.example.com"), [PUBLIC_HOST]
    )
    assert_denied(decision, DenyReason.DNS_SCOPE_VIOLATION)


def test_dns_expired_grant_denied(tmp_path: Path) -> None:
    _, broker = dns_broker(tmp_path)
    grant = make_grant(expires_at=BASE_NOW_MS - 1)
    decision = broker.validate_resolved_address(
        grant, make_network_target(), [PUBLIC_HOST]
    )
    assert_denied(decision, DenyReason.GRANT_EXPIRED)


def test_dns_literal_target_must_appear_in_answers(tmp_path: Path) -> None:
    _, broker = dns_broker(tmp_path)
    decision = broker.validate_resolved_address(
        make_grant(), make_network_target(host=PRIVATE_HOST), [PUBLIC_HOST]
    )
    # The literal private target is outside the granted public host scope.
    assert_denied(decision, DenyReason.DNS_SCOPE_VIOLATION)


def test_dns_private_literal_requires_explicit_private_flag(tmp_path: Path) -> None:
    _, broker = dns_broker(tmp_path)
    grant = make_grant(host=PRIVATE_HOST)
    decision = broker.validate_resolved_address(
        grant, make_network_target(host=PRIVATE_HOST), [PRIVATE_HOST]
    )
    assert_denied(decision, DenyReason.DNS_SCOPE_VIOLATION)


def test_dns_private_literal_allowed_with_flag(tmp_path: Path) -> None:
    _, broker = dns_broker(tmp_path)
    scope = GrantScope.from_record(make_grant(host=PRIVATE_HOST), allow_private=True)
    decision = broker.validate_resolved_address(
        scope, make_network_target(host=PRIVATE_HOST), [PRIVATE_HOST]
    )
    assert decision.allowed is True


def test_dns_resolved_value_must_be_list_like(tmp_path: Path) -> None:
    _, broker = dns_broker(tmp_path)
    decision = broker.validate_resolved_address(
        make_grant(), make_network_target(), "93.184.216.34"
    )
    assert_denied(decision, DenyReason.DNS_SCOPE_VIOLATION)


def test_dns_requires_grant_scope(tmp_path: Path) -> None:
    _, broker = dns_broker(tmp_path)
    decision = broker.validate_resolved_address(None, make_network_target(), [PUBLIC_HOST])
    assert_denied(decision, DenyReason.GRANT_INVALID)


# ---------------------------------------------------------------------------
# Pure scope helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "private", "loopback"),
    [
        ("127.0.0.1", True, True),
        ("127.255.255.254", True, True),
        ("::1", True, True),
        ("10.0.0.5", True, False),
        ("192.168.1.10", True, False),
        ("172.16.0.1", True, False),
        ("169.254.1.1", True, False),
        ("0.0.0.0", True, False),
        ("localhost", True, True),
        ("LOCALHOST.", True, True),
        ("service.localhost", True, True),
        ("printer.local", True, False),
        ("router.internal", True, False),
        ("example.com", False, False),
        ("93.184.216.34", False, False),
        ("8.8.8.8", False, False),
        ("", True, False),
    ],
)
def test_host_classification(host: str, private: bool, loopback: bool) -> None:
    assert is_private_host(host) is private
    assert is_loopback_host(host) is loopback


def test_ip_classification() -> None:
    assert is_private_ip("10.1.2.3") is True
    assert is_private_ip("93.184.216.34") is False
    assert is_loopback_ip("127.0.0.1") is True
    assert is_loopback_ip("10.1.2.3") is False
    assert is_private_ip("not-an-ip") is False


def test_path_prefix_matching() -> None:
    assert path_prefix_matches("/", "/") is True
    assert path_prefix_matches("/anything", "/") is True
    assert path_prefix_matches("/api", "/api") is True
    assert path_prefix_matches("/api/v1", "/api") is True
    assert path_prefix_matches("/apix", "/api") is False
    assert path_prefix_matches("/other", "/api") is False
    assert normalize_path_prefix("api/") == "/api"


def test_grant_allows_private_variants() -> None:
    record = make_grant(host=PRIVATE_HOST)
    assert grant_allows_private(record) is False
    assert grant_allows_private(GrantScope.from_record(record, allow_private=True)) is True
    assert grant_allows_private({"allow_private": True}) is True
    assert grant_allows_private({}) is False

    class PayloadGrant:
        payload = {"allow_private": True}

    assert grant_allows_private(PayloadGrant()) is True


def test_grant_scope_from_record_preserves_fields() -> None:
    record = make_grant(host="example.com", port=8443, protocol="http", method="POST")
    scope = GrantScope.from_record(record, allow_private=True)
    assert scope.host == "example.com"
    assert scope.port == 8443
    assert scope.protocol == "http"
    assert scope.method == "POST"
    assert scope.allow_private is True
    assert scope.task_id == TASK_ID
