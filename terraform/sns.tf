resource "aws_sns_topic" "security_alerts" {
  name = "${var.project_name}-security-alerts"

  tags = {
    Name        = "SecureFileGuard Security Alerts"
    Project     = var.project_name
    Environment = "dev"
  }
}