from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from redteam.models.enums import AttackCategory, Grade


class ToolCallTrace(BaseModel):
    tool_name: str
    arguments: dict
    return_value: dict
    authorized: bool


class Finding(BaseModel):
    finding_id: str
    prompt_id: str
    category: AttackCategory
    subcategory: str
    severity: int = Field(ge=1, le=5)
    grade: Grade
    confidence: float = Field(ge=0.0, le=1.0)
    grading_method: str
    agent_response: str
    tool_calls_made: list[ToolCallTrace] = Field(default_factory=list)
    intermediate_steps: list[dict] = Field(default_factory=list)
    reasoning: str
    compliance_refs: list[dict] = Field(default_factory=list)
    latency_ms: float
    # Per-turn breakdown for multi-turn prompts. Empty for single-turn.
    turns: list[dict] = Field(default_factory=list)


class ScanResult(BaseModel):
    scan_id: str
    schema_version: str = "1.0.0"
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    engine_version: str
    target: dict
    summary: dict
    findings: list[Finding] = Field(default_factory=list)
    comparison: Optional[dict] = None
