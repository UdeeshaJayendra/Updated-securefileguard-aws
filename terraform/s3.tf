resource "aws_s3_bucket" "securefileguard" {
  bucket = "${var.project_name}-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name        = "SecureFileGuard Storage"
    Project     = var.project_name
    Environment = "dev"
  }
}

resource "aws_s3_bucket_public_access_block" "securefileguard" {
  bucket = aws_s3_bucket.securefileguard.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "securefileguard" {
  bucket = aws_s3_bucket.securefileguard.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "securefileguard" {
  bucket = aws_s3_bucket.securefileguard.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "securefileguard" {
  bucket = aws_s3_bucket.securefileguard.id

  rule {
    id     = "cleanup-old-files"
    status = "Enabled"

    filter {
      prefix = "uploads/"
    }

    expiration {
      days = 1
    }
  }
}

resource "aws_s3_object" "uploads_folder" {
  bucket = aws_s3_bucket.securefileguard.id
  key    = "uploads/"
}

resource "aws_s3_object" "clean_folder" {
  bucket = aws_s3_bucket.securefileguard.id
  key    = "clean/"
}

resource "aws_s3_object" "quarantine_folder" {
  bucket = aws_s3_bucket.securefileguard.id
  key    = "quarantine/"
}

resource "aws_s3_bucket_notification" "securefileguard" {
  bucket = aws_s3_bucket.securefileguard.id

  queue {
    queue_arn = aws_sqs_queue.security_queue.arn

    events = [
      "s3:ObjectCreated:*"
    ]

    filter_prefix = "uploads/"
  }

  depends_on = [
    aws_sqs_queue_policy.security_queue_policy
  ]
}