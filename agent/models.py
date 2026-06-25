#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode.ai is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
#
"""Pydantic output models for vulnerability parsers."""

from enum import Enum
from typing import List, Literal

from cwe2.database import Database
from packageurl import PackageURL
from pydantic import BaseModel, field_validator

from agent.robustness import UnsupportedCVSSVersionError

CWE_DATABASE = Database()


class Purl(BaseModel):
    string: str

    @field_validator("string")
    def check_valid_purl(cls, purl: str) -> str:
        PackageURL.from_string(purl)
        return purl


class CWE(BaseModel):
    string: str

    @field_validator("string")
    def check_valid_cwe(cls, v: str) -> str:
        norm = v.strip().upper()
        if norm.startswith("CWE-"):
            norm = norm[4:].strip()
        if not norm.isdigit():
            raise ValueError("CWE must be a numeric identifier, e.g., 'CWE-79' or '79'")
        CWE_DATABASE.get(norm)
        return f"CWE-{norm}"


class CWEList(BaseModel):
    cwes: List[CWE]


class SeverityEnum(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Severity(BaseModel):
    severity: SeverityEnum


class Versions(BaseModel):
    affected_versions: List[str]
    fixed_versions: List[str]


def _cvss_class_for(prefix: str):
    from cvss import CVSS3, CVSS4

    if prefix in ("CVSS:3.0", "CVSS:3.1"):
        return CVSS3
    if prefix == "CVSS:4.0":
        return CVSS4
    return None


def _parse_cvss_or_raise(vector: str):
    """Construct the cvss parser object, re-raising any error as ValueError."""
    from cvss import CVSS3, CVSS4

    stripped = vector.strip()
    prefix = stripped.split("/", 1)[0]
    klass = _cvss_class_for(prefix)
    if klass is None:
        # Genuine v2 vectors (no CVSS:3./4. prefix) or "Au:" shape => unsupported.
        if not stripped.startswith(("CVSS:3.", "CVSS:4.")):
            raise UnsupportedCVSSVersionError(
                f"Unsupported CVSS version (only 3.1 and 4.0): {vector!r}"
            )
        raise ValueError(f"Invalid CVSS vector: {vector!r}")
    try:
        return klass(stripped)
    except UnsupportedCVSSVersionError:
        raise
    except Exception as exc:  # CVSS3MalformedError etc. -> ValueError for pydantic
        raise ValueError(f"Invalid CVSS vector: {vector!r}") from exc


class CVSSVector(BaseModel):
    vector: str
    version: Literal["3.1", "4.0"]
    base_score: float
    severity_label: str

    @field_validator("vector")
    @classmethod
    def check_valid_cvss(cls, v: str) -> str:
        _parse_cvss_or_raise(v)  # raises ValueError / UnsupportedCVSSVersionError
        return v.strip()

    @classmethod
    def from_vector(cls, vector_str: str) -> "CVSSVector":
        parsed = _parse_cvss_or_raise(vector_str)
        stripped = vector_str.strip()
        version = "4.0" if stripped.split("/", 1)[0] == "CVSS:4.0" else "3.1"
        # cvss 3.0 API differs between classes: base_score is an attribute on both;
        # CVSS3 exposes severities(), CVSS4 exposes a `severity` attribute instead.
        base_score = float(parsed.base_score)
        if version == "4.0":
            severity_label = str(parsed.severity).lower()
        else:
            severity_label = str(parsed.severities()[0]).lower()
        return cls(
            vector=stripped,
            version=version,
            base_score=base_score,
            severity_label=severity_label,
        )