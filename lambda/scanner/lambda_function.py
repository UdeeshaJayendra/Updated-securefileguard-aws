import json
import os
import hashlib
import uuid
import math
import mimetypes
from datetime import datetime, timezone

import boto3


s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")


TABLE_NAME = os.environ["TABLE_NAME"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]

table = dynamodb.Table(TABLE_NAME)


SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".dll",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".jar",
    ".scr",
    ".msi",
}


MAGIC_SIGNATURES = {
    b"MZ": "PE/Windows executable",
    b"\x7fELF": "ELF executable",
    b"PK\x03\x04": "ZIP-based file",
    b"%PDF": "PDF document",
    b"\x89PNG": "PNG image",
    b"\xff\xd8\xff": "JPEG image",
}


def calculate_entropy(data):
    if not data:
        return 0.0

    frequency = [0] * 256

    for byte in data:
        frequency[byte] += 1

    entropy = 0.0
    length = len(data)

    for count in frequency:
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def detect_magic(data):
    for signature, file_type in MAGIC_SIGNATURES.items():
        if data.startswith(signature):
            return file_type

    return "Unknown"


def calculate_hash(data):
    return hashlib.sha256(data).hexdigest()


def get_extension(key):
    filename = key.split("/")[-1]
    _, extension = os.path.splitext(filename)

    return extension.lower()


def analyze_file(data, key):
    extension = get_extension(key)
    entropy = calculate_entropy(data)
    sha256 = calculate_hash(data)
    detected_type = detect_magic(data)

    suspicious_indicators = []
    score = 0

    if extension in SUSPICIOUS_EXTENSIONS:
        suspicious_indicators.append(
            f"Suspicious executable/script extension: {extension}"
        )
        score += 40

    if detected_type in {
        "PE/Windows executable",
        "ELF executable",
    }:
        suspicious_indicators.append(
            f"Executable file signature detected: {detected_type}"
        )
        score += 50

    if entropy >= 7.5:
        suspicious_indicators.append(
            f"High entropy detected: {entropy}"
        )
        score += 20

    mime_type, _ = mimetypes.guess_type(key)

    if mime_type is None:
        mime_type = "application/octet-stream"

    if score >= 70:
        status = "QUARANTINED"
    elif score >= 40:
        status = "SUSPICIOUS"
    else:
        status = "CLEAN"

    return {
        "sha256": sha256,
        "file_size": len(data),
        "extension": extension,
        "mime_type": mime_type,
        "detected_type": detected_type,
        "entropy": entropy,
        "threat_score": score,
        "status": status,
        "suspicious_indicators": suspicious_indicators,
    }


def process_record(record):
    body = json.loads(record["body"])

    for s3_record in body.get("Records", []):
        bucket = s3_record["s3"]["bucket"]["name"]
        key = s3_record["s3"]["object"]["key"]

        response = s3.get_object(
            Bucket=bucket,
            Key=key,
        )

        data = response["Body"].read()

        analysis = analyze_file(data, key)

        timestamp = datetime.now(timezone.utc).isoformat()

        scan_id = str(uuid.uuid4())

        if analysis["status"] == "CLEAN":
            destination = "clean/" + key.split("/")[-1]
        else:
            destination = "quarantine/" + key.split("/")[-1]

        s3.put_object(
            Bucket=bucket,
            Key=destination,
            Body=data,
            ServerSideEncryption="AES256",
        )

        table.put_item(
            Item={
                "scan_id": scan_id,
                "file_name": key.split("/")[-1],
                "original_key": key,
                "processed_key": destination,
                "status": analysis["status"],
                "sha256": analysis["sha256"],
                "file_size": analysis["file_size"],
                "extension": analysis["extension"],
                "mime_type": analysis["mime_type"],
                "detected_type": analysis["detected_type"],
                "entropy": str(analysis["entropy"]),
                "threat_score": analysis["threat_score"],
                "suspicious_indicators": analysis[
                    "suspicious_indicators"
                ],
                "timestamp": timestamp,
            }
        )

        if analysis["status"] != "CLEAN":
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject="SecureFileGuard Security Alert",
                Message=json.dumps(
                    {
                        "file": key,
                        "status": analysis["status"],
                        "threat_score": analysis["threat_score"],
                        "sha256": analysis["sha256"],
                        "indicators": analysis[
                            "suspicious_indicators"
                        ],
                    },
                    indent=2,
                ),
            )

        print(
            json.dumps(
                {
                    "file": key,
                    "status": analysis["status"],
                    "threat_score": analysis["threat_score"],
                    "sha256": analysis["sha256"],
                }
            )
        )


def lambda_handler(event, context):
    print("SecureFileGuard scanner started")

    batch_item_failures = []

    for record in event.get("Records", []):
        try:
            process_record(record)

        except Exception as error:
            print(
                json.dumps(
                    {
                        "error": str(error),
                        "message_id": record.get("messageId"),
                    }
                )
            )

            batch_item_failures.append(
                {
                    "itemIdentifier": record["messageId"]
                }
            )

    print(
        json.dumps(
            {
                "failed_records": len(batch_item_failures)
            }
        )
    )

    return {
        "batchItemFailures": batch_item_failures
    }