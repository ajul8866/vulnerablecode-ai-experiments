#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode.ai is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
#
"""Extract a Package URL from a vulnerability summary."""

from typing import Optional

from aboutcode.hashid import get_core_purl
from packageurl import PackageURL

from agent.config import DEFAULT_RETRY_POLICY, RetryPolicy
from agent.models import Purl
from agent.parsers.base import BaseParser
from prompts import PROMPT_PURL_FROM_SUMMARY


class PurlFromSummaryParser(BaseParser):
    def __init__(self, retry_policy: RetryPolicy = DEFAULT_RETRY_POLICY):
        super().__init__(PROMPT_PURL_FROM_SUMMARY, Purl, retry_policy=retry_policy)

    def get_purl(self, summary: str) -> Optional[PackageURL]:
        # run_agent returns the pydantic output model directly (Task 7 contract).
        output = self.run_agent(f"**Vulnerability Summary:**\n{summary}")
        purl = PackageURL.from_string(output.string)
        return get_core_purl(purl)