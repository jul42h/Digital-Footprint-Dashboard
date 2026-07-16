"""CVE AI analysis for the Digital Footprint Dashboard.

Flow: POST /api/cve-analysis with findings (+ cve_ids) + intent → Lambda → ai_summary.

Intents (one per dashboard surface):
  brief              — home/insights AI summary (prose)
  insights           — AI Insights panel (sections)
  risk_score         — risk score rationale (prose; score computed in Lambda)
  threat_intel       — threat intelligence panel (sections)
  critical_findings  — top critical findings (sections)
  risk_assets        — highest-risk assets (sections)
  remediate          — prioritized remediation (sections)
  ask_ai             — Ask AI answers (prose; requires question)

Legacy aliases accepted by the Lambda (not by this API's request model):
  analyze → insights, next_steps → remediate
"""

from ask_ai.cve_dashboard_api import router as cve_analysis_router

__all__ = ["cve_analysis_router"]
