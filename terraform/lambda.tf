# ============================================================
# SecureFileGuard Scanner Lambda
# ============================================================

resource "aws_lambda_function" "scanner" {
  function_name = "${var.project_name}-scanner"

  role = aws_iam_role.scanner_lambda_role.arn

  # Container image deployment
  package_type = "Image"

  image_uri     = "216453078762.dkr.ecr.ap-south-1.amazonaws.com/securefileguard-scanner@sha256:054b72cf04b8b0cc22231b8b3b652c38d3ee791deced2ef2cecbaee7fc3ea5f5"
  architectures = ["x86_64"]

  timeout     = 120
  memory_size = 2048
  environment {
    variables = {
      TABLE_NAME    = aws_dynamodb_table.scan_results.name
      SNS_TOPIC_ARN = aws_sns_topic.security_alerts.arn
    }
  }

  tags = {
    Name        = "SecureFileGuard Scanner Lambda"
    Project     = var.project_name
    Environment = "dev"
  }

  depends_on = [
    aws_iam_role_policy_attachment.scanner_lambda_policy
  ]
}


# ============================================================
# SQS → Scanner Lambda
# ============================================================

resource "aws_lambda_event_source_mapping" "scanner_sqs" {
  event_source_arn = aws_sqs_queue.security_queue.arn
  function_name    = aws_lambda_function.scanner.arn

  batch_size                         = 1
  maximum_batching_window_in_seconds = 0

  function_response_types = [
    "ReportBatchItemFailures"
  ]

  enabled = true
}


# ============================================================
# Upload Lambda
# ============================================================

data "archive_file" "upload_lambda" {
  type        = "zip"
  source_file = "${path.module}/../lambda/upload/lambda_function.py"
  output_path = "${path.module}/upload_lambda.zip"
}

resource "aws_lambda_function" "upload" {
  function_name = "${var.project_name}-upload"

  role = aws_iam_role.upload_lambda_role.arn

  handler = "lambda_function.lambda_handler"
  runtime = "python3.12"

  filename         = data.archive_file.upload_lambda.output_path
  source_code_hash = data.archive_file.upload_lambda.output_base64sha256

  timeout     = 30
  memory_size = 256

  environment {
    variables = {
      BUCKET_NAME = aws_s3_bucket.securefileguard.bucket
    }
  }

  tags = {
    Name        = "SecureFileGuard Upload Lambda"
    Project     = var.project_name
    Environment = "dev"
  }

  depends_on = [
    aws_iam_role_policy_attachment.upload_lambda_policy
  ]
}


# ============================================================
# Dashboard API Lambda
# ============================================================

data "archive_file" "dashboard_lambda" {
  type        = "zip"
  source_file = "${path.module}/../dashboard/api/lambda_function.py"
  output_path = "${path.module}/dashboard_lambda.zip"
}

resource "aws_iam_role_policy" "dashboard_lambda_policy" {
  name = "${var.project_name}-dashboard-lambda-policy"
  role = aws_iam_role.dashboard_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [

      {
        Effect = "Allow"

        Action = [
          "dynamodb:Scan",
          "dynamodb:GetItem"
        ]

        Resource = aws_dynamodb_table.scan_results.arn
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
}

resource "aws_lambda_function" "dashboard_api" {
  function_name = "${var.project_name}-dashboard-api"

  role = aws_iam_role.dashboard_lambda_role.arn

  runtime = "python3.12"
  handler = "lambda_function.lambda_handler"

  filename         = data.archive_file.dashboard_lambda.output_path
  source_code_hash = data.archive_file.dashboard_lambda.output_base64sha256

  timeout     = 30
  memory_size = 256

  environment {
    variables = {
      TABLE_NAME = aws_dynamodb_table.scan_results.name
    }
  }

  tags = {
    Name        = "SecureFileGuard Dashboard API"
    Project     = var.project_name
    Environment = "dev"
  }

  depends_on = [
    aws_iam_role_policy.dashboard_lambda_policy
  ]
}


# ============================================================
# CloudWatch Log Group - Scanner
# ============================================================

resource "aws_cloudwatch_log_group" "scanner" {
  name              = "/aws/lambda/${aws_lambda_function.scanner.function_name}"
  retention_in_days = 7

  tags = {
    Name        = "SecureFileGuard Scanner Logs"
    Project     = var.project_name
    Environment = "dev"
  }

  depends_on = [
    aws_lambda_function.scanner
  ]
}


# ============================================================
# CloudWatch Log Group - Upload
# ============================================================

resource "aws_cloudwatch_log_group" "upload" {
  name              = "/aws/lambda/${aws_lambda_function.upload.function_name}"
  retention_in_days = 7

  tags = {
    Name        = "SecureFileGuard Upload Logs"
    Project     = var.project_name
    Environment = "dev"
  }

  depends_on = [
    aws_lambda_function.upload
  ]
}


# ============================================================
# CloudWatch Log Group - Dashboard API
# ============================================================

resource "aws_cloudwatch_log_group" "dashboard_api" {
  name              = "/aws/lambda/${aws_lambda_function.dashboard_api.function_name}"
  retention_in_days = 7

  tags = {
    Name        = "SecureFileGuard Dashboard API Logs"
    Project     = var.project_name
    Environment = "dev"
  }

  depends_on = [
    aws_lambda_function.dashboard_api
  ]
}