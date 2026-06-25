# SPDX-License-Identifier: Apache-2.0
"""Extract CWE IDs from a summary."""

from agent.config import DEFAULT_RETRY_POLICY, RetryPolicy
from agent.models import CWEList
from agent.parsers.base import BaseParser
from prompts import PROMPT_CWE_FROM_SUMMARY


class CWEFromSummaryParser(BaseParser):
    def __init__(self, retry_policy: RetryPolicy = DEFAULT_RETRY_POLICY):
        super().__init__(PROMPT_CWE_FROM_SUMMARY, CWEList, retry_policy=retry_policy)

    def get_cwes(self, summary: str) -> list[str]:
        output = self.run_agent(f"**Vulnerability Description:**\n{summary}")
        return [cwe.string for cwe in output.cwes]