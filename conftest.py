import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "live: tests that call a real LLM (excluded by default; run with -m live)",
    )
