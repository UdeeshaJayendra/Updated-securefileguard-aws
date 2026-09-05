data "archive_file" "scanner_lambda" {
  type        = "zip"
  source_file = "${path.module}/../lambda/scanner/lambda_function.py"
  output_path = "${path.module}/scanner_lambda.zip"
}

resource "aws_lambda_function" "scanner" {
  function_name = "${var.project_name}-scanner"

  role = aws_iam_role.scanner_lambda_role.arn

  handler = "lambda_function.lambda_handler"
  runtime = "python3.12"

  filename         = data.archive_file.scanner_lambda.output_path
  source_code_hash = data.archive_file.scanner_lambda.output_base64sha256

  timeout     = 120
  memory_size = 512

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
}
resource "aws_lambda_event_source_mapping" "scanner_sqs" {
  event_source_arn = aws_sqs_queue.security_queue.arn
  function_name    = aws_lambda_function.scanner.arn

  batch_size                         = 1
  maximum_batching_window_in_seconds = 0
  function_response_types            = ["ReportBatchItemFailures"]

  enabled = true
}

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