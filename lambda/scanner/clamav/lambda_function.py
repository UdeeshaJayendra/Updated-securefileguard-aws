import json
import os
import hashlib
import uuid
import math
import mimetypes
import subprocess
import tempfile

from datetime import datetime, timezone

import boto3


s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")


TABLE_NAME = os.environ["TABLE_NAME"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]

table = dynamodb.Table(TABLE_NAME)


# ============================================================
# ClamAV configuration
# ============================================================

CLAMSCAN_PATH = "/opt/clamav/bin/clamscan"
CLAMAV_DATABASE = "/var/lib/clamav"

CLAMAV_TIMEOUT = 90


# ============================================================
# Heuristic detection configuration
# ============================================================

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


# ============================================================
# Entropy
# ============================================================

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


# ============================================================
# Magic signature detection
# ============================================================

def detect_magic(data):
    for signature, file_type in MAGIC_SIGNATURES.items():
        if data.startswith(signature):
            return file_type

    return "Unknown"


# ============================================================
# SHA-256
# ============================================================

def calculate_hash(data):
    return hashlib.sha256(data).hexdigest()


# ============================================================
# File extension
# ============================================================

def get_extension(key):
    filename = key.split("/")[-1]
    _, extension = os.path.splitext(filename)

    return extension.lower()


# ============================================================
# ClamAV scan
# ============================================================

def scan_with_clamav(data):
    temp_path = None

    try:
        # Create temporary file in Lambda /tmp
        with tempfile.NamedTemporaryFile(
            dir="/tmp",
            delete=False,
            prefix="securefileguard-",
            suffix=".scan"
        ) as temp_file:

            temp_file.write(data)
            temp_file.flush()

            temp_path = temp_file.name

        command = [
            CLAMSCAN_PATH,
            "--database",
            CLAMAV_DATABASE,
            "--infected",
            "--no-summary",
            temp_path,
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=CLAMAV_TIMEOUT,
        )

        output = (
            result.stdout.strip()
            + "\n"
            + result.stderr.strip()
        ).strip()

        # ClamAV exit code 0 = clean
        if result.returncode == 0:
            return {
                "status": "CLEAN",
                "signature": None,
                "output": output,
            }

        # ClamAV exit code 1 = malware detected
        if result.returncode == 1:

            signature = None

            for line in output.splitlines():

                if " FOUND" in line:

                    detected_part = line.rsplit(": ", 1)[-1]

                    if detected_part.endswith(" FOUND"):
                        signature = detected_part[:-6].strip()

                    break

            return {
                "status": "INFECTED",
                "signature": signature,
                "output": output,
            }

        # Any other exit code means ClamAV encountered an error.
        raise RuntimeError(
            f"ClamAV scan failed with exit code "
            f"{result.returncode}: {output}"
        )

    except subprocess.TimeoutExpired as error:

        raise RuntimeError(
            f"ClamAV scan timed out after "
            f"{CLAMAV_TIMEOUT} seconds"
        ) from error

    finally:

        if temp_path and os.path.exists(temp_path):

            try:
                os.remove(temp_path)

            except OSError:
                pass


# ============================================================
# Heuristic analysis
# ============================================================

def analyze_file(data, key):

    extension = get_extension(key)

    entropy = calculate_entropy(data)

    sha256 = calculate_hash(data)

    detected_type = detect_magic(data)

    suspicious_indicators = []

    score = 0

    # --------------------------------------------------------
    # Extension analysis
    # --------------------------------------------------------

    if extension in SUSPICIOUS_EXTENSIONS:

        suspicious_indicators.append(
            f"Suspicious executable/script extension: {extension}"
        )

        score += 40

    # --------------------------------------------------------
    # Magic signature analysis
    # --------------------------------------------------------

    if detected_type in {
        "PE/Windows executable",
        "ELF executable",
    }:

        suspicious_indicators.append(
            f"Executable file signature detected: {detected_type}"
        )

        score += 50

    # --------------------------------------------------------
    # Entropy analysis
    # --------------------------------------------------------

    if entropy >= 7.5:

        suspicious_indicators.append(
            f"High entropy detected: {entropy}"
        )

        score += 20

    # --------------------------------------------------------
    # MIME type
    # --------------------------------------------------------

    mime_type, _ = mimetypes.guess_type(key)

    if mime_type is None:
        mime_type = "application/octet-stream"

    # --------------------------------------------------------
    # Initial heuristic status
    # --------------------------------------------------------

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


# ============================================================
# Process SQS record
# ============================================================

def process_record(record):

    body = json.loads(record["body"])

    for s3_record in body.get("Records", []):

        bucket = s3_record["s3"]["bucket"]["name"]

        key = s3_record["s3"]["object"]["key"]

        print(
            json.dumps(
                {
                    "message": "Processing file",
                    "bucket": bucket,
                    "key": key,
                }
            )
        )

        # ----------------------------------------------------
        # Download file from S3
        # ----------------------------------------------------

        response = s3.get_object(
            Bucket=bucket,
            Key=key,
        )

        data = response["Body"].read()

        # ----------------------------------------------------
        # Heuristic analysis
        # ----------------------------------------------------

        analysis = analyze_file(
            data,
            key,
        )

        # ----------------------------------------------------
        # ClamAV analysis
        # ----------------------------------------------------

        clamav = scan_with_clamav(data)

        analysis["clamav_status"] = clamav["status"]

        analysis["clamav_signature"] = clamav["signature"]

        analysis["clamav_output"] = clamav["output"]

        # ----------------------------------------------------
        # Malware detected
        # ----------------------------------------------------

        if clamav["status"] == "INFECTED":

            analysis["status"] = "QUARANTINED"

            analysis["threat_score"] = max(
                analysis["threat_score"],
                100,
            )

            indicator = (
                "ClamAV malware detection"
            )

            if clamav["signature"]:

                indicator += (
                    f": {clamav['signature']}"
                )

            analysis["suspicious_indicators"].append(
                indicator
            )

        # ----------------------------------------------------
        # Heuristic quarantine
        # ----------------------------------------------------

        elif analysis["status"] == "QUARANTINED":

            analysis["status"] = "QUARANTINED"

        # ----------------------------------------------------
        # Suspicious heuristic result
        # ----------------------------------------------------

        elif analysis["status"] == "SUSPICIOUS":

            analysis["status"] = "SUSPICIOUS"

        # ----------------------------------------------------
        # Clean
        # ----------------------------------------------------

        else:

            analysis["status"] = "CLEAN"

        # ----------------------------------------------------
        # Timestamp and scan ID
        # ----------------------------------------------------

        timestamp = datetime.now(
            timezone.utc
        ).isoformat()

        scan_id = str(uuid.uuid4())

        filename = key.split("/")[-1]

        # ----------------------------------------------------
        # Destination
        # ----------------------------------------------------

        if analysis["status"] == "CLEAN":

            destination = (
                "clean/" + filename
            )

        else:

            destination = (
                "quarantine/" + filename
            )

        # ----------------------------------------------------
        # Copy result
        # ----------------------------------------------------

        s3.put_object(
            Bucket=bucket,
            Key=destination,
            Body=data,
            ServerSideEncryption="AES256",
        )

        # ----------------------------------------------------
        # DynamoDB audit record
        # ----------------------------------------------------

        table.put_item(
            Item={
                "scan_id": scan_id,

                "file_name": filename,

                "original_key": key,

                "processed_key": destination,

                "status": analysis["status"],

                "sha256": analysis["sha256"],

                "file_size": analysis["file_size"],

                "extension": analysis["extension"],

                "mime_type": analysis["mime_type"],

                "detected_type": analysis["detected_type"],

                "entropy": str(
                    analysis["entropy"]
                ),

                "threat_score": analysis[
                    "threat_score"
                ],

                "suspicious_indicators": analysis[
                    "suspicious_indicators"
                ],

                "clamav_status": analysis[
                    "clamav_status"
                ],

                "clamav_signature": (
                    analysis["clamav_signature"]
                    or ""
                ),

                "timestamp": timestamp,
            }
        )

        # ----------------------------------------------------
        # SNS security alert
        # ----------------------------------------------------

        if analysis["status"] != "CLEAN":

            sns.publish(
                TopicArn=SNS_TOPIC_ARN,

                Subject=(
                    "SecureFileGuard Security Alert"
                ),

                Message=json.dumps(
                    {
                        "file": key,

                        "status": analysis[
                            "status"
                        ],

                        "threat_score": analysis[
                            "threat_score"
                        ],

                        "sha256": analysis[
                            "sha256"
                        ],

                        "clamav_status": analysis[
                            "clamav_status"
                        ],

                        "clamav_signature": (
                            analysis[
                                "clamav_signature"
                            ]
                        ),

                        "indicators": analysis[
                            "suspicious_indicators"
                        ],
                    },
                    indent=2,
                ),
            )

        # ----------------------------------------------------
        # Logging
        # ----------------------------------------------------

        print(
            json.dumps(
                {
                    "file": key,

                    "status": analysis[
                        "status"
                    ],

                    "threat_score": analysis[
                        "threat_score"
                    ],

                    "sha256": analysis[
                        "sha256"
                    ],

                    "clamav_status": analysis[
                        "clamav_status"
                    ],

                    "clamav_signature": (
                        analysis[
                            "clamav_signature"
                        ]
                    ),
                }
            )
        )


# ============================================================
# Lambda handler
# ============================================================

def lambda_handler(event, context):

    print(
        "SecureFileGuard scanner started"
    )

    batch_item_failures = []

    for record in event.get(
        "Records",
        []
    ):

        try:

            process_record(record)

        except Exception as error:

            print(
                json.dumps(
                    {
                        "error": str(error),

                        "message_id": record.get(
                            "messageId"
                        ),
                    }
                )
            )

            batch_item_failures.append(
                {
                    "itemIdentifier": record[
                        "messageId"
                    ]
                }
            )

    print(
        json.dumps(
            {
                "failed_records": len(
                    batch_item_failures
                )
            }
        )
    )

    return {
        "batchItemFailures":
            batch_item_failures
    }