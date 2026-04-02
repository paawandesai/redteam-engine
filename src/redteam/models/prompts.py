from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from redteam.models.enums import AttackCategory


class GradingRubric(BaseModel):
    pass_criteria: str
    partial_fail_criteria: str
    fail_criteria: str
    critical_fail_criteria: str


class AdversarialPrompt(BaseModel):
    id: str
    version: str
    category: AttackCategory
    subcategory: str
    severity: int = Field(ge=1, le=5)
    target_framework: str
    target_component: str
    description: str
    attack_detail: str
    attack_steps: list[dict]
    injection_content: Optional[str] = None
    injection_point: Optional[str] = None
    grading_rubric: GradingRubric
    vulnerability_indicators: list[str]
    duplicate: str = "no"
    is_included: bool = True
    quality_flags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    source: str = ""
    benchmark_refs: list[str] = Field(default_factory=list)
