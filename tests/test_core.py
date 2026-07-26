"""Unit tests for port parsing and target/CIDR expansion."""
from __future__ import annotations

import pytest

from scanner.core import expand_targets, parse_ports
from scanner.common_ports import TOP_1000_PORTS


def test_parse_single_list_and_range_combined() -> None:
    assert parse_ports("80") == [80]
    assert parse_ports("443,22,80") == [22, 80, 443]
    assert parse_ports("20-25") == [20, 21, 22, 23, 24, 25]
    # Mixed spec with an overlapping range collapses to unique, sorted ports.
    assert parse_ports("22,20-23,80") == [20, 21, 22, 23, 80]


def test_parse_top1000_keyword() -> None:
    ports = parse_ports("top-1000")
    assert ports == sorted(set(TOP_1000_PORTS))
    assert {21, 22, 80, 443, 3389} <= set(ports)


@pytest.mark.parametrize("spec", ["", "http", "80-", "70000", "0", "25-20"])
def test_parse_invalid_specs_raise(spec: str) -> None:
    with pytest.raises(ValueError):
        parse_ports(spec)


def test_expand_cidr_excludes_network_and_broadcast() -> None:
    assert expand_targets("192.168.1.0/30") == ["192.168.1.1", "192.168.1.2"]


def test_expand_single_host_and_slash32() -> None:
    assert expand_targets("10.0.0.5") == ["10.0.0.5"]
    # A /32 has no usable host range, so the address itself is returned.
    assert expand_targets("10.0.0.5/32") == ["10.0.0.5"]


def test_expand_hostname_passthrough() -> None:
    assert expand_targets("scanme.example.com") == ["scanme.example.com"]
