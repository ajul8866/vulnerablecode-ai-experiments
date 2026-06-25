#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode.ai is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
#
"""Regex-based extraction of CVSS vectors (the 'regex first' half of the hybrid)."""

import re
from typing import Optional

# Match CVSS:3.1 or CVSS:4.0 vector strings. Slashes are required to be present.
# 3.0 is intentionally excluded: it is unsupported and would otherwise be silently
# mislabeled as version 3.1 by CVSSVector.from_vector.
_CVSS_RE = re.compile(r"CVSS:(?:3\.1|4\.0)/[A-Za-z0-9:/_.\-]+")

# Hard cap on candidate length to avoid runaway matches.
_MAX_CANDIDATE_LEN = 512


def extract_cvss_vector(text: str) -> Optional[str]:
    """Return a validated, normalized CVSS 3.1/4.0 vector found in ``text``, or None."""
    if not text:
        return None
    for candidate in _CVSS_RE.findall(text):
        candidate = candidate[:_MAX_CANDIDATE_LEN]
        normalized = _validate(candidate)
        if normalized is not None:
            return normalized
    return None


def _validate(candidate: str) -> Optional[str]:
    from cvss import CVSS3, CVSS4

    prefix = candidate.split("/", 1)[0]
    klass = CVSS4 if prefix == "CVSS:4.0" else CVSS3
    try:
        parsed = klass(candidate)
    except Exception:
        return None
    return parsed.clean_vector()
