"""Ask AI — cybersecurity analyst orchestration for the Digital Footprint Dashboard.

Flow (in-process or via Lambda):
  question → intent/context retrieval → Bedrock (or deterministic analyst) → structured JSON
"""

from ask_ai.handler import handle_ask, handle_risk_intelligence

__all__ = ["handle_ask", "handle_risk_intelligence"]
