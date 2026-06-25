# SPDX-License-Identifier: Apache-2.0
"""Extract affected/fixed version ranges from a summary."""

from univers.version_range import RANGE_CLASS_BY_SCHEMES

from agent.config import DEFAULT_RETRY_POLICY, RetryPolicy
from agent.models import Versions
from agent.parsers.base import BaseParser
from prompts import PROMPT_VERSION_FROM_SUMMARY


class VersionsFromSummaryParser(BaseParser):
    def __init__(self, retry_policy: RetryPolicy = DEFAULT_RETRY_POLICY):
        super().__init__(PROMPT_VERSION_FROM_SUMMARY, Versions, retry_policy=retry_policy)

    def get_version_ranges(self, summary: str, supported_ecosystem: str):
        output = self.run_agent(f"**Vulnerability Summary:**\n{summary}")
        affected_objs = [
            RANGE_CLASS_BY_SCHEMES[supported_ecosystem].from_string(
                f"vers:{supported_ecosystem}/{v}"
            )
            for v in output.affected_versions
        ]
        fixed_objs = [
            RANGE_CLASS_BY_SCHEMES[supported_ecosystem].from_string(
                f"vers:{supported_ecosystem}/{v}"
            )
            for v in output.fixed_versions
        ]
        return affected_objs, fixed_objs
