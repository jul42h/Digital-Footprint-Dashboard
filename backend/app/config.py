from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Digital Footprint API"
    environment: str = "local"  # local | aws
    cors_origins: str = "http://localhost:5173,http://localhost:4173"

    # Lambda invocation (aws mode)
    data_access_lambda_name: str = "cve-dashboard-data-access"
    aws_region: str = "us-east-1"

    # DynamoDB
    dynamodb_table_name: str = "cve-dashboard-data"

    # Athena
    athena_database: str = "cve_dashboard"
    athena_workgroup: str = "primary"
    athena_output_bucket: str = ""

    # Local fallback
    local_data_json: str = "data/dashboard_snapshot.json"
    local_excel_path: str = "data/shodan_data.xlsx"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
