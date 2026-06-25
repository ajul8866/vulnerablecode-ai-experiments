# SPDX-License-Identifier: Apache-2.0
"""Extract severity from a summary."""

from typing import Optional

from agent.config import DEFAULT_RETRY_POLICY, RetryPolicy
from agent.models import Severity
from agent.parsers.base import BaseParser
from prompts import PROMPT_SEVERITY_FROM_SUMMARY


class SeverityFromSummaryParser(BaseParser):
    def __init__(self, retry_policy: RetryPolicy = DEFAULT_RETRY_POLICY):
        super().__init__(PROMPT_SEVERITY_FROM_SUMMARY, Severity, retry_policy=retry_policy)

    def get_severity(self, summary: str) -> Optional[Severity]:
        output = self.run_agent(f"**Vulnerability Description:**\n{summary}")
        return output.severity.value