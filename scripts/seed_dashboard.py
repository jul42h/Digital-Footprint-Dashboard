#!/usr/bin/env python3
"""Build dashboard JSON from Excel and optionally seed DynamoDB via the data-access Lambda."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow importing backend modules
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.services.local_loader import load_local_dashboard  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed dashboard data")
    parser.add_argument(
        "--excel",
        default=str(ROOT / "backend" / "data" / "shodan_data.xlsx"),
        help="Path to Shodan Excel export",
    )
    parser.add_argument(
        "--out",
        default=str(ROOT / "backend" / "data" / "dashboard_snapshot.json"),
        help="Output JSON snapshot path",
    )
    parser.add_argument("--invoke-lambda", action="store_true", help="Push snapshot to DynamoDB via Lambda")
    parser.add_argument("--lambda-name", default="cve-dashboard-data-access-dev")
    args = parser.parse_args()

    excel = Path(args.excel)
    if not excel.exists():
        print(f"Excel not found: {excel}", file=sys.stderr)
        sys.exit(1)

    data = load_local_dashboard(excel)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        json.dump(data.model_dump(), f, indent=2)
    print(f"Wrote {out} ({len(data.ips)} IPs, {len(data.cveRecords)} CVE records)")

    if args.invoke_lambda:
        import boto3

        client = boto3.client("lambda")
        payload = {
            "action": "put_snapshot",
            "data": data.model_dump(),
            "ips": [ip.model_dump() for ip in data.ips],
        }
        response = client.invoke(
            FunctionName=args.lambda_name,
            InvocationType="RequestResponse",
            Payload=json.dumps(payload).encode("utf-8"),
        )
        body = json.loads(response["Payload"].read().decode("utf-8"))
        print("Lambda response:", body)


if __name__ == "__main__":
    main()
