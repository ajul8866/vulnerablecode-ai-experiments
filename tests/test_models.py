import pytest
from pydantic import ValidationError

from agent.models import CVSSVector
from agent.robustness import UnsupportedCVSSVersionError


def test_cvss_vector_from_valid_v31():
    v = CVSSVector.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    assert v.version == "3.1"
    assert v.base_score == pytest.approx(7.5)
    assert v.severity_label.lower() == "high"


def test_cvss_vector_from_valid_v40():
    v = CVSSVector.from_vector(
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
    )
    assert v.version == "4.0"
    assert v.base_score == pytest.approx(8.7)
    assert v.severity_label.lower() == "high"


def test_cvss_vector_rejects_v2():
    with pytest.raises(UnsupportedCVSSVersionError):
        CVSSVector.from_vector("AV:N/AC:L/Au:N/C:N/I:N/A:P")


def test_cvss_vector_rejects_invalid_metric():
    with pytest.raises((ValidationError, ValueError)):
        CVSSVector.from_vector("CVSS:3.1/AV:BOGUS/AC:L")


def test_cvss_vector_validator_runs_on_field():
    # constructing directly also validates the vector field
    v = CVSSVector(
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        version="3.1",
        base_score=0.0,
        severity_label="low",
    )
    assert v.vector.startswith("CVSS:3.1")