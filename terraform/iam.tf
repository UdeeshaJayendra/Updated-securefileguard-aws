resource "aws_iam_role" "scanner_lambda_role" {
  name = "${var.project_name}-scanner-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Principal = {
          Service = "lambda.amazonaws.com"
        }

        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name        = "SecureFileGuard Scanner Lambda Role"
    Project     = var.project_name
    Environment = "dev"
  }
}

resource "aws_iam_policy" "scanner_lambda_policy" {
  name = "${var.project_name}-scanner-lambda-policy"

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [

      # S3 access
      {
        Effect = "Allow"

        Action = [
          "s3:GetObject"
        ]

        Resource = "${aws_s3_bucket.securefileguard.arn}/uploads/*"
      },

      {
        Effect = "Allow"

        Action = [
          "s3:PutObject"
        ]

        Resource = [
          "${aws_s3_bucket.securefileguard.arn}/clean/*",
          "${aws_s3_bucket.securefileguard.arn}/quarantine/*"
        ]
      },

      # SQS access
      {
        Effect = "Allow"

        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]

        Resource = aws_sqs_queue.security_queue.arn
      },

      # DynamoDB access
      {
        Effect = "Allow"

        Action = [
          "dynamodb:PutItem"
        ]

        Resource = aws_dynamodb_table.scan_results.arn
      },

      # SNS access
      {
        Effect = "Allow"

        Action = [
          "sns:Publish"
        ]

        Resource = aws_sns_topic.security_alerts.arn
      },

      # CloudWatch Logs
      {
        Effect = "Allow"

        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]

        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "SecureFileGuard Scanner Lambda Policy"
    Project     = var.project_name
    Environment = "dev"
  }
}

resource "aws_iam_role_policy_attachment" "scanner_lambda_policy" {
  role       = aws_iam_role.scanner_lambda_role.name
  policy_arn = aws_iam_policy.scanner_lambda_policy.arn
}

resource "aws_iam_role" "upload_lambda_role" {
  name = "${var.project_name}-upload-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Principal = {
          Service = "lambda.amazonaws.com"
        }

        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name        = "SecureFileGuard Upload Lambda Role"
    Project     = var.project_name
    Environment = "dev"
  }
}


resource "aws_iam_policy" "upload_lambda_policy" {
  name = "${var.project_name}-upload-lambda-policy"

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [

      {
        Effect = "Allow"

        Action = [
          "s3:PutObject"
        ]

        Resource = "${aws_s3_bucket.securefileguard.arn}/uploads/*"
      },

      {
        Effect = "Allow"

        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]

        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "SecureFileGuard Upload Lambda Policy"
    Project     = var.project_name
    Environment = "dev"
  }
}


resource "aws_iam_role_policy_attachment" "upload_lambda_policy" {
  role       = aws_iam_role.upload_lambda_role.name
  policy_arn = aws_iam_policy.upload_lambda_policy.arn
}