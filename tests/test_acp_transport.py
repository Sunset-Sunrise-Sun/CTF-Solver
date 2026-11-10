"""Transport-level tests: ND-JSON framing, correlation, timeouts, EOF, exit.

These tests wrap the fake ACP server with :class:`JsonRpcStdioTransport`
directly (without the ``AcpClient`` state machine) so each transport guarantee
from docs/INTERFACES.md section 3.1 is exercised in isolation.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from ctf_solver.core.errors import AcpProcessExited, AcpRemoteError, AcpTimeout
from tests.test_acp_support import fake_processes, terminate, wait_until


def test_echo_round_trip_counts_and_diagnostics(fake_processes):
    process, transport = fake_processes("--scenario", "normal")

    assert transport.send_request("debug/echo", {"value": 42}) == {"echo": {"value": 42}}
    assert transport.send_request("debug/echo", {"value": "two"}) == {
        "echo": {"value": "two"}
    }

    diagnostics = transport.diagnostics()
    assert diagnostics["request_count"] == 2
    assert diagnostics["response_count"] == 2
    assert diagnostics["malformed_lines"] == 0
    assert diagnostics["pending_requests"] == 0
    assert diagnostics["pid"] == process.pid
    assert diagnostics["process_alive"] is True
    assert diagnostics["exit_code"] is None


def test_partial_reads_and_multiple_messages_per_chunk(fake_processes):
    # partial-flush writes every frame in 7-byte chunks: the reader must
    # reassemble a message from many partial reads.
    _, transport = fake_processes("--scenario", "partial-flush")

    assert transport.send_request("debug/echo", {"chunked": True}) == {
        "echo": {"chunked": True}
    }
    assert transport.send_request("debug/echo", {"chunked": 2}) == {
        "echo": {"chunked": 2}
    }

    # burst writes a notification and a response into the same pipe write:
    # the reader must split two messages out of one chunk.
    notifications: list[dict] = []
    transport.set_notification_handler("session/update", notifications.append)
    assert transport.send_request("debug/burst", {}) == {"burst": True}
    wait_until(lambda: len(notifications) == 1)
    assert notifications[0]["update"]["sessionUpdate"] == "agent_message_chunk"


def test_large_messages_at_least_one_mib_both_directions(fake_processes):
    _, transport = fake_processes("--scenario", "normal")

    large_request = "y" * (1200 * 1024)
    echoed = transport.send_request("debug/echo", {"blob": large_request}, timeout_s=30.0)
    assert echoed["echo"]["blob"] == large_request

    big = transport.send_request("debug/big", {"size": 1536 * 1024}, timeout_s=30.0)
    assert big["size"] == 1536 * 1024
    assert big["data"] == "x" * (1536 * 1024)


def test_crlf_terminated_response_is_accepted(fake_processes):
    _, transport = fake_processes("--scenario", "normal")

    assert transport.send_request("debug/crlf", {}) == {"crlf": True}
    # The reader is still healthy after a CRLF frame.
    assert transport.send_request("debug/echo", {"after": "crlf"}) == {
        "echo": {"after": "crlf"}
    }


def test_malformed_json_line_is_diagnostic_not_fatal(fake_processes):
    _, transport = fake_processes("--scenario", "normal")

    result = transport.send_request("debug/garbage", {})
    assert result == {"afterGarbage": True}
    wait_until(lambda: transport.diagnostics()["malformed_lines"] >= 1)
    samples = transport.malformed_samples()
    assert samples, "malformed sample diagnostics must be recorded"
    assert any("malformed JSON" in sample for sample in samples)

    # The reader thread is still alive and can serve later requests.
    assert transport.send_request("debug/echo", {"alive": True}) == {
        "echo": {"alive": True}
    }


def test_malformed_scenario_before_every_response(fake_processes):
    _, transport = fake_processes("--scenario", "malformed")

    assert transport.send_request("debug/echo", {"n": 1}) == {"echo": {"n": 1}}
    assert transport.send_request("debug/echo", {"n": 2}) == {"echo": {"n": 2}}
    wait_until(lambda: transport.diagnostics()["malformed_lines"] >= 2)


def test_timeout_raises_and_late_response_is_ignored(fake_processes):
    _, transport = fake_processes("--scenario", "normal")

    with pytest.raises(AcpTimeout) as excinfo:
        transport.send_request("debug/sleep", {"seconds": 0.5}, timeout_s=0.1)
    assert "timed out" in str(excinfo.value)
    assert transport.diagnostics()["timed_out_requests"] == 1

    # The late response arrives after the request was abandoned; it must be
    # counted as an unmatched/duplicate response, never crash the reader.
    wait_until(lambda: transport.diagnostics()["duplicate_responses"] >= 1, timeout=5.0)
    assert transport.send_request("debug/echo", {"after": "timeout"}) == {
        "echo": {"after": "timeout"}
    }


def test_duplicate_response_is_ignored_by_original_request(fake_processes):
    _, transport = fake_processes("--scenario", "normal")

    assert transport.send_request("debug/dup", {}) == {"duplicate": True}
    wait_until(lambda: transport.diagnostics()["duplicate_responses"] >= 1)
    assert transport.send_request("debug/echo", {"after": "dup"}) == {
        "echo": {"after": "dup"}
    }


def test_out_of_order_responses_correlate_by_request_id(fake_processes):
    _, transport = fake_processes("--scenario", "normal")
    barrier = threading.Barrier(2)
    results: dict[str, object] = {}
    order: list[str] = []
    lock = threading.Lock()

    def call(value: str, delay: float) -> None:
        barrier.wait(timeout=5.0)
        response = transport.send_request(
            "debug/delay_echo", {"delay": delay, "value": value}, timeout_s=10.0
        )
        with lock:
            results[value] = response["value"]
            order.append(value)

    with ThreadPoolExecutor(max_workers=2) as pool:
        slow = pool.submit(call, "slow", 0.4)
        fast = pool.submit(call, "fast", 0.02)
        slow.result(timeout=15.0)
        fast.result(timeout=15.0)

    # Each caller got its own result, and the fast request completed first even
    # though it was correlated to a later response ordering.
    assert results == {"slow": "slow", "fast": "fast"}
    assert order == ["fast", "slow"]


def test_process_exit_fails_pending_request_and_later_requests(fake_processes):
    process, transport = fake_processes("--scenario", "crash-on-request")

    with pytest.raises(AcpProcessExited):
        transport.send_request("session/list", {}, timeout_s=5.0)

    wait_until(lambda: transport.diagnostics()["eof"] is True)
    wait_until(lambda: transport.diagnostics()["exit_code"] is not None)
    assert transport.diagnostics()["exit_code"] == 9
    assert transport.is_process_alive() is False

    with pytest.raises(AcpProcessExited):
        transport.send_request("debug/echo", {"after": "crash"})
    terminate(process)


def test_eof_after_external_kill_fails_pending(fake_processes):
    process, transport = fake_processes("--scenario", "normal")

    process.kill()
    process.wait(timeout=10.0)
    wait_until(lambda: transport.diagnostics()["eof"] is True)

    with pytest.raises(AcpProcessExited):
        transport.send_request("debug/echo", {"after": "eof"})


def test_stderr_is_bounded_and_kept_out_of_stdout(fake_processes, tmp_path):
    stderr_path = tmp_path / "acp-stderr.log"
    _, transport = fake_processes(
        "--scenario", "normal", stderr_path=stderr_path
    )

    result = transport.send_request("debug/stderr", {"size": 20000})
    assert result == {"stderrBytes": 20000}

    wait_until(lambda: stderr_path.exists() and stderr_path.stat().st_size >= 20000)

    diagnostics = transport.diagnostics()
    # The in-memory tail is bounded; the on-disk file keeps the full stream.
    assert 0 < diagnostics["stderr_bytes"] <= 8192
    assert "stderr-marker" in diagnostics["stderr_tail"]
    assert "stderr-marker" in stderr_path.read_text(encoding="utf-8", errors="replace")

    # stdout framing was never polluted by stderr bytes.
    assert transport.send_request("debug/echo", {"clean": "stdout"}) == {
        "echo": {"clean": "stdout"}
    }
    assert diagnostics["malformed_lines"] == 0


def test_send_notification_does_not_wait_for_response(fake_processes):
    _, transport = fake_processes("--scenario", "normal")

    transport.send_notification("session/cancel", {"sessionId": "sess-synthetic"})
    transport.notify("debug/unknown-notification", {"x": 1})
    # No response is expected; a normal request still works afterwards.
    assert transport.send_request("debug/echo", {"after": "notify"}) == {
        "echo": {"after": "notify"}
    }
    assert transport.diagnostics()["notification_count"] == 0


def test_remote_error_raised_for_unknown_server_method(fake_processes):
    _, transport = fake_processes("--scenario", "normal")

    with pytest.raises(AcpRemoteError) as excinfo:
        transport.send_request("no/such/method", {})
    assert excinfo.value.code == -32601
    assert "method not found" in str(excinfo.value)


def test_shutdown_is_idempotent_and_rejects_later_sends(fake_processes):
    process, transport = fake_processes("--scenario", "normal")
    assert transport.send_request("debug/echo", {"before": "shutdown"}) == {
        "echo": {"before": "shutdown"}
    }

    transport.shutdown(timeout_s=1.0)
    transport.shutdown(timeout_s=1.0)  # idempotent
    assert transport.diagnostics()["closed"] is True

    with pytest.raises(AcpProcessExited):
        transport.send_request("debug/echo", {"after": "shutdown"})
    with pytest.raises(AcpProcessExited):
        transport.send_notification("session/cancel", {"sessionId": "sess-1"})
    terminate(process)


def test_concurrent_request_ids_never_mix_results(fake_processes):
    _, transport = fake_processes("--scenario", "normal")
    values = [f"value-{index}" for index in range(20)]
    barrier = threading.Barrier(len(values))
    received: list[str] = []
    lock = threading.Lock()

    def call(value: str, delay: float) -> None:
        barrier.wait(timeout=10.0)
        response = transport.send_request(
            "debug/delay_echo", {"delay": delay, "value": value}, timeout_s=15.0
        )
        with lock:
            received.append(response["value"])

    with ThreadPoolExecutor(max_workers=len(values)) as pool:
        futures = [
            pool.submit(call, value, 0.02 if index % 2 else 0.0)
            for index, value in enumerate(values)
        ]
        for future in futures:
            future.result(timeout=30.0)

    assert sorted(received) == sorted(values)
    assert transport.diagnostics()["pending_requests"] == 0
    assert transport.diagnostics()["duplicate_responses"] == 0


def test_pending_requests_are_reported_while_in_flight(fake_processes):
    _, transport = fake_processes("--scenario", "normal")

    def call() -> None:
        transport.send_request("debug/sleep", {"seconds": 0.4}, timeout_s=10.0)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(call)
        second = pool.submit(call)
        wait_until(lambda: transport.diagnostics()["pending_requests"] >= 1)
        assert transport.diagnostics()["pending_requests"] >= 1
        first.result(timeout=10.0)
        second.result(timeout=10.0)

    assert transport.diagnostics()["pending_requests"] == 0
