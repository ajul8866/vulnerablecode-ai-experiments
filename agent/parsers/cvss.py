#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode.ai is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
#
"""Hybrid CVSS parser: regex-first extraction, LLM inference fallback."""

from typing import Optional

from pydantic import BaseModel, field_validator

from agent.config import DEFAULT_RETRY_POLICY, RetryPolicy
from agent.cvss_extraction import extract_cvss_vector
from agent.models import CVSSVector
from agent.parsers.base import BaseParser
from agent.pipeline import PipelineHooks
from agent.robustness import CVSSNotExtractableError, InvalidOutputError
from prompts import PROMPT_CVSS_FROM_SUMMARY


class CVSSVectorRaw(BaseModel):
    """LLM output shape: just the vector string. Score is computed, never asked."""

    vector: str

    @field_validator("vector")
    @classmethod
    def check_valid_cvss(cls, v: str) -> str:
        return CVSSVector.check_valid_cvss(v)  # reuse the same validation rules


class CVSSFromSummaryParser(BaseParser):
    _RAW_TYPE = CVSSVectorRaw

    def __init__(self, retry_policy: RetryPolicy = DEFAULT_RETRY_POLICY):
        super().__init__(PROMPT_CVSS_FROM_SUMMARY, CVSSVectorRaw, retry_policy=retry_policy)

    @property
    def hooks(self) -> PipelineHooks:
        return PipelineHooks(
            preprocess=self._preprocess,
            normalize=self._normalize,
        )

    def _preprocess(self, user_prompt: str) -> str:
        # Nudge the model toward an already-discovered vector if one is embedded.
        found = extract_cvss_vector(user_prompt)
        if found:
            return user_prompt + f"\n\nIf unsure, return exactly this vector: {found}"
        return user_prompt

    def _normalize(self, raw: CVSSVectorRaw) -> CVSSVector:
        return CVSSVector.from_vector(raw.vector)

    def get_cvss(self, summary: str) -> Optional[CVSSVector]:
        # 1. Regex short-circuit: skip the LLM entirely when a valid vector exists.
        found = extract_cvss_vector(summary)
        if found:
            return CVSSVector.from_vector(found)

        # 2. LLM fallback through the pipeline.
        try:
            return self.run_agent(f"**Vulnerability Description:**\n{summary}")
        except InvalidOutputError as err:
            raise CVSSNotExtractableError(raw=err.raw, reason=err.reason) from err