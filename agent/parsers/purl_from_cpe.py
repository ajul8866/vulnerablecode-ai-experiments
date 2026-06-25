# SPDX-License-Identifier: Apache-2.0
"""Extract a Package URL from a CPE identifier."""

from typing import Optional

from aboutcode.hashid import get_core_purl
from packageurl import PackageURL

from agent.config import DEFAULT_RETRY_POLICY, RetryPolicy
from agent.models import Purl
from agent.parsers.base import BaseParser
from prompts import PROMPT_PURL_FROM_CPE


class PurlFromCPEParser(BaseParser):
    def __init__(self, retry_policy: RetryPolicy = DEFAULT_RETRY_POLICY):
        super().__init__(PROMPT_PURL_FROM_CPE, Purl, retry_policy=retry_policy)

    def get_purl(self, cpe: str, pkg_type) -> Optional[PackageURL]:
        output = self.run_agent(
            f"**Vulnerability Known Affected Software Configurations CPE:**\n{cpe}\n"
            f"**Package Type:**\n{pkg_type}"
        )
        purl = PackageURL.from_string(output.string)
        return get_core_purl(purl)