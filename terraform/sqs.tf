resource "aws_sqs_queue" "security_dlq" {
  name = "${var.project_name}-security-dlq"

  message_retention_seconds = 1209600

  tags = {
    Name    = "SecureFileGuard Security DLQ"
    Project = var.project_name
  }
}

resource "aws_sqs_queue" "security_queue" {
  name = "${var.project_name}-security-queue"

  visibility_timeout_seconds = 720
  message_retention_seconds  = 345600

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.security_dlq.arn
    maxReceiveCount     = 3
  })

  tags = {
    Name    = "SecureFileGuard Security Queue"
    Project = var.project_name
  }
}

resource "aws_sqs_queue_policy" "security_queue_policy" {
  queue_url = aws_sqs_queue.security_queue.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid    = "AllowS3ToSendMessages"
        Effect = "Allow"

        Principal = {
          Service = "s3.amazonaws.com"
        }

        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.security_queue.arn

        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_s3_bucket.securefileguard.arn
          }

          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}