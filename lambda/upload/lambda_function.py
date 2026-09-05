import json
import os
import uuid
import re
import boto3


s3 = boto3.client("s3")

BUCKET_NAME = os.environ["BUCKET_NAME"]

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB


def lambda_handler(event, context):
    try:
        body = json.loads(event.get("body", "{}"))

        file_name = body.get("file_name")
        content = body.get("content")

        if not file_name or content is None:
            return {
                "statusCode": 400,
                "body": json.dumps({
                    "error": "file_name and content are required"
                })
            }

        # Prevent path traversal and unsafe filenames
        safe_name = os.path.basename(file_name)

        if safe_name != file_name or not re.match(
            r"^[A-Za-z0-9._-]+$",
            file_name
        ):
            return {
                "statusCode": 400,
                "body": json.dumps({
                    "error": "Invalid file name"
                })
            }

        content_bytes = content.encode("utf-8")

        if len(content_bytes) > MAX_FILE_SIZE:
            return {
                "statusCode": 413,
                "body": json.dumps({
                    "error": "File exceeds maximum allowed size of 5 MB"
                })
            }

        file_id = str(uuid.uuid4())

        key = f"uploads/{file_id}-{safe_name}"

        s3.put_object(
            Bucket=BUCKET_NAME,
            Key=key,
            Body=content_bytes,
            ServerSideEncryption="AES256"
        )

        print(
            json.dumps({
                "file_name": safe_name,
                "s3_key": key,
                "size": len(content_bytes)
            })
        )

        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "File uploaded successfully",
                "file_name": safe_name,
                "s3_key": key,
                "status": "QUEUED"
            })
        }

    except Exception as error:
        print(f"Upload error: {error}")

        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": "Internal server error"
            })
        }