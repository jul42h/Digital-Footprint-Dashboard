"""CVE AI analysis for the Digital Footprint Dashboard.

Flow: POST /api/cve-analysis with findings (+ cve_ids) + intent → Lambda → ai_summary.

Intents (Lambda prompt headings):
  brief      — Risk Posture, What Stands Out, Priority Action (prose; top 5 findings)
  analyze    — Summary, Top Risks, Why It Matters, Confidence and Gaps
  remediate  — Priority Order, Recommended Actions, Validation, Limitations
  next_steps — Immediate, This Week, Owners, Data Needed
"""

from ask_ai.cve_dashboard_api import router as cve_analysis_router

__all__ = ["cve_analysis_router"]
