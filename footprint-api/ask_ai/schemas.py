"""Request/response contracts for Ask AI and Risk Intelligence."""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class AskMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str


class AskRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=4000)
    history: List[AskMessage] = Field(default_factory=list)
    # Optional focus entities from the UI (deep-link context)
    cve_id: Optional[str] = None
    host: Optional[str] = None


class PriorityItem(BaseModel):
    asset: str
    reason: str


class AskResponse(BaseModel):
    summary: str
    riskScore: Optional[float] = None
    priority: List[PriorityItem] = Field(default_factory=list)
    remediation: List[str] = Field(default_factory=list)
    threatIntel: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    intent: str = "general"
    mode: Literal["bedrock", "deterministic", "lambda"] = "deterministic"
    markdown: Optional[str] = None


class RiskIntelligenceResponse(BaseModel):
    summary: str
    riskScore: float
    highestRiskAssets: List[Dict[str, Any]] = Field(default_factory=list)
    topCriticalFindings: List[Dict[str, Any]] = Field(default_factory=list)
    threatIntel: List[str] = Field(default_factory=list)
    prioritizedRemediation: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    mode: Literal["bedrock", "deterministic", "lambda"] = "deterministic"
