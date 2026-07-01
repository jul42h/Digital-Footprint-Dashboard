from fastapi import APIRouter, Depends

from app.config import Settings, get_settings
from app.models import DashboardData, HealthResponse, RefreshResponse
from app.services.data_service import get_dashboard, query_analytics, refresh_dashboard

router = APIRouter(prefix="/api/v1", tags=["dashboard"])


@router.get("/health", response_model=HealthResponse)
def health(settings: Settings = Depends(get_settings)) -> HealthResponse:
    source = "lambda+dynamodb" if settings.environment == "aws" else "local"
    return HealthResponse(status="ok", environment=settings.environment, data_source=source)


@router.get("/dashboard", response_model=DashboardData)
def read_dashboard(settings: Settings = Depends(get_settings)) -> DashboardData:
    return get_dashboard(settings)


@router.post("/dashboard/refresh", response_model=RefreshResponse)
def refresh(settings: Settings = Depends(get_settings)) -> RefreshResponse:
    result = refresh_dashboard(settings)
    return RefreshResponse(
        status=result.get("status", "ok"),
        message=result.get("message", "Refresh triggered"),
        lastUpdated=result.get("lastUpdated"),
        details=result if result.get("status") == "error" else None,
    )


@router.get("/analytics/athena")
def analytics(query_type: str = "severity_summary", settings: Settings = Depends(get_settings)) -> dict:
    return query_analytics(settings, query_type=query_type)
