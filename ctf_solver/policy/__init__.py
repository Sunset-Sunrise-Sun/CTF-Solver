"""Broker policy: approvals, network grants, execution-tier and ownership checks.

Public surface: :class:`Broker` (fail-closed authorization) and
:class:`BrokerConfig`; the deterministic digest/scope helpers live in
:mod:`ctf_solver.policy.models`.
"""

from __future__ import annotations

from .broker import Broker, BrokerConfig
from .models import (
    GrantScope,
    action_digest,
    approval_action_digest,
    approval_details,
    grant_allows_private,
    grant_scope,
    hosts_match,
    is_loopback_host,
    is_loopback_ip,
    is_private_host,
    is_private_ip,
    target_digest,
)

__all__ = [
    "Broker",
    "BrokerConfig",
    "GrantScope",
    "action_digest",
    "approval_action_digest",
    "approval_details",
    "grant_allows_private",
    "grant_scope",
    "hosts_match",
    "is_loopback_host",
    "is_loopback_ip",
    "is_private_host",
    "is_private_ip",
    "target_digest",
]
