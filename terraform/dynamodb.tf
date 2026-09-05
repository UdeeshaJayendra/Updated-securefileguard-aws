resource "aws_dynamodb_table" "scan_results" {
  name         = "${var.project_name}-scan-results"
  billing_mode = "PAY_PER_REQUEST"

  hash_key = "scan_id"

  attribute {
    name = "scan_id"
    type = "S"
  }

  tags = {
    Name        = "SecureFileGuard Scan Results"
    Project     = var.project_name
    Environment = "dev"
  }
}