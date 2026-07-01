from typing import Any, Literal

from pydantic import BaseModel, Field


class SourceCVE(BaseModel):
    id: str
    score: float = 0
    severity: str = "Informational"
    publishedDate: str = ""
    lastUpdated: str | None = None
    summary: str | None = None
    kev: bool | None = None


class SourceIPRecord(BaseModel):
    ip: str
    organization: str = ""
    country: str = ""
    city: str | None = None
    asn: str | None = None
    hostnames: list[str] = Field(default_factory=list)
    operatingSystem: str | None = None
    ports: list[int] = Field(default_factory=list)
    transport: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    products: list[str] = Field(default_factory=list)
    versions: list[str] = Field(default_factory=list)
    cves: list[SourceCVE] = Field(default_factory=list)
    riskLevel: str = "Informational"
    tags: list[str] = Field(default_factory=list)
    vulnerabilities: list[str] = Field(default_factory=list)
    openPorts: list[int] = Field(default_factory=list)
    isp: str | None = None
    timestamp: str | None = None
    summary: str | None = None
    lastSeen: str | None = None


class DashboardStats(BaseModel):
    totalIPs: int = 0
    totalCVEs: int = 0
    criticalCVEs: int = 0
    highCVEs: int = 0
    mediumCVEs: int = 0
    lowCVEs: int = 0
    informationalCVEs: int = 0
    averageCVSS: float = 0
    highestCVSS: float = 0
    newestVulnerability: str | None = None
    oldestVulnerability: str | None = None
    uniqueOrganizations: int = 0
    uniqueCountries: int = 0


class CVEFlatRecord(BaseModel):
    cve: SourceCVE
    ip: str
    organization: str = ""
    country: str = ""
    operatingSystem: str | None = None
    port: int | None = None


class DashboardData(BaseModel):
    ips: list[SourceIPRecord]
    stats: DashboardStats
    cveRecords: list[CVEFlatRecord]
    lastUpdated: str
    source: Literal["api", "excel", "empty", "dynamodb", "athena"] = "api"


class HealthResponse(BaseModel):
    status: str
    environment: str
    data_source: str


class RefreshResponse(BaseModel):
    status: str
    message: str
    lastUpdated: str | None = None
    details: dict[str, Any] | None = None
