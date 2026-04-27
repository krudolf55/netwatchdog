"""Tests for IP address utilities."""

from __future__ import annotations

import pytest

from periscan.utils.ip_utils import expand_target, validate_ip


def test_single_ip():
    assert expand_target("192.168.1.1") == ["192.168.1.1"]


def test_cidr_24():
    ips = expand_target("192.168.1.0/24")
    assert len(ips) == 254  # .1 through .254
    assert "192.168.1.1" in ips
    assert "192.168.1.254" in ips
    assert "192.168.1.0" not in ips  # network address excluded


def test_cidr_30():
    ips = expand_target("10.0.0.0/30")
    assert len(ips) == 2
    assert "10.0.0.1" in ips
    assert "10.0.0.2" in ips


def test_dash_range():
    ips = expand_target("10.0.0.1-10.0.0.5")
    assert ips == ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]


def test_dash_range_single():
    ips = expand_target("10.0.0.1-10.0.0.1")
    assert ips == ["10.0.0.1"]


def test_dash_range_reversed_raises():
    with pytest.raises(ValueError, match="end < start"):
        expand_target("10.0.0.5-10.0.0.1")


def test_invalid_ip_raises():
    with pytest.raises(ValueError):
        expand_target("999.999.999.999")


def test_validate_ip():
    assert validate_ip("  192.168.1.1  ") == "192.168.1.1"


def test_validate_ip_invalid():
    with pytest.raises(ValueError):
        validate_ip("not-an-ip")
