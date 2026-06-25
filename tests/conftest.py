"""Shared pytest configuration and fixtures."""

from __future__ import annotations

from hypothesis import HealthCheck, settings

# Register a CI profile with reduced max_examples for faster test runs
settings.register_profile(
    "ci",
    max_examples=10,
    suppress_health_check=[HealthCheck.too_slow],
    deadline=None,
)

# Use the ci profile by default in tests
settings.load_profile("ci")
