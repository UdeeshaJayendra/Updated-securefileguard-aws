import json
import os
from decimal import Decimal

import boto3

dynamodb = boto3.resource("dynamodb")

TABLE_NAME = os.environ["TABLE_NAME"]
table = dynamodb.Table(TABLE_NAME)


def decimal_to_number(obj):
    if isinstance(obj, Decimal):
        if obj % 1 == 0:
            return int(obj)
        return float(obj)

    raise TypeError(
        f"Object of type {type(obj).__name__} is not JSON serializable"
    )


def get_all_scans():
    items = []

    response = table.scan()
    items.extend(response.get("Items", []))

    # Handle pagination
    while "LastEvaluatedKey" in response:
        response = table.scan(
            ExclusiveStartKey=response["LastEvaluatedKey"]
        )
        items.extend(response.get("Items", []))

    return items


def lambda_handler(event, context):

    try:
        path = event.get("rawPath", "")

        if not path:
               path = event.get("requestContext", {}).get("http", {}).get("path", "")

        if not path:
              path = event.get("path", "/scans")
        items = get_all_scans()

        # GET /statistics
        if path == "/statistics":

            total = len(items)

            clean = sum(
                1 for item in items
                if item.get("status") == "CLEAN"
            )

            suspicious = sum(
                1 for item in items
                if item.get("status") == "SUSPICIOUS"
            )

            quarantined = sum(
                1 for item in items
                if item.get("status") == "QUARANTINED"
            )

            threat_scores = [
                float(item.get("threat_score", 0))
                for item in items
            ]

            average_threat_score = (
                sum(threat_scores) / len(threat_scores)
                if threat_scores
                else 0
            )

            return {
                "statusCode": 200,
                "headers": {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*"
                },
                "body": json.dumps({
                    "total_files": total,
                    "clean": clean,
                    "suspicious": suspicious,
                    "quarantined": quarantined,
                    "average_threat_score": round(
                        average_threat_score, 2
                    )
                })
            }

        # GET /scans
        items.sort(
            key=lambda x: x.get("timestamp", ""),
            reverse=True
        )

        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
            },
            "body": json.dumps(
                items,
                default=decimal_to_number
            )
        }

    except Exception as error:

        print(f"Dashboard API error: {error}")

        return {
            "statusCode": 500,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
            },
            "body": json.dumps({
                "error": "Unable to retrieve scan results"
            })
        }