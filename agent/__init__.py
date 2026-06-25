#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode.ai is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
#
"""Public API for the VulnerabilityAgent experiments package."""

from typing import Optional

from packageurl import PackageURL

from agent.config import DEFAULT_RETRY_POLICY, RetryPolicy
from agent.models import (
    CWE,
    CWEList,
    CVSSVector,
    Purl,
    Severity,
    SeverityEnum,
    Versions,
)
from agent.parsers.cwe import CWEFromSummaryParser
from agent.parsers.cvss import CVSSFromSummaryParser
from agent.parsers.purl_from_cpe import PurlFromCPEParser
from agent.parsers.purl_from_summary import PurlFromSummaryParser
from agent.parsers.severity import SeverityFromSummaryParser
from agent.parsers.versions import VersionsFromSummaryParser

__all__ = [
    "CWE",
    "CWEList",
    "CVSSVector",
    "Purl",
    "Severity",
    "SeverityEnum",
    "Versions",
    "VulnerabilityAgent",
    "RetryPolicy",
]


class VulnerabilityAgent:
    """Unified interface for parsing vulnerability information.

    Handles extraction of PURLs, version ranges, severities, CWEs, and CVSS
    vectors from vulnerability summaries and CPE identifiers.
    """

    def __init__(self, retry_policy: RetryPolicy = DEFAULT_RETRY_POLICY):
        self.purl_parser = PurlFromSummaryParser(retry_policy=retry_policy)
        self.versions_parser = VersionsFromSummaryParser(retry_policy=retry_policy)
        self.cpe_parser = PurlFromCPEParser(retry_policy=retry_policy)
        self.severity_parser = SeverityFromSummaryParser(retry_policy=retry_policy)
        self.cwe_parser = CWEFromSummaryParser(retry_policy=retry_policy)
        self.cvss_parser = CVSSFromSummaryParser(retry_policy=retry_policy)

    def get_purl_from_summary(self, summary: str):
        """Extract PURL from a vulnerability summary."""
        return self.purl_parser.get_purl(summary)

    def get_version_ranges(self, summary: str, ecosystem: str):
        """Extract affected/fixed version ranges from a summary."""
        return self.versions_parser.get_version_ranges(summary, ecosystem)

    def get_purl_from_cpe(self, cpe: str, pkg_type: str):
        """Convert a CPE string to a PURL."""
        return self.cpe_parser.get_purl(cpe, pkg_type)

    def get_severity_from_summary(self, summary: str):
        """Extract severity information from a summary."""
        return self.severity_parser.get_severity(summary)

    def get_cwe_from_summary(self, summary: str):
        """Extract CWE IDs from a summary."""
        return self.cwe_parser.get_cwes(summary)

    def get_cvss_from_summary(self, summary: str) -> Optional[CVSSVector]:
        """Extract a CVSS vector (and computed base score) from a summary."""
        return self.cvss_parser.get_cvss(summary)
