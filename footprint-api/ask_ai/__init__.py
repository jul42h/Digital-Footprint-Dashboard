"""CVE AI analysis for the Digital Footprint Dashboard.

Flow: POST /api/cve-analysis with cve_ids + mode → Lambda → ai_summary.
"""

from ask_ai.cve_dashboard_api import router as cve_analysis_router

__all__ = ["cve_analysis_router"]
