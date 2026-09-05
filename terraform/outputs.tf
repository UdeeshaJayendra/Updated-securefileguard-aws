output "s3_bucket_name" {
  description = "SecureFileGuard S3 bucket name"
  value       = aws_s3_bucket.securefileguard.bucket
}

output "s3_bucket_arn" {
  description = "SecureFileGuard S3 bucket ARN"
  value       = aws_s3_bucket.securefileguard.arn
}

output "security_queue_url" {
  description = "Security processing SQS queue URL"
  value       = aws_sqs_queue.security_queue.url
}

output "security_queue_arn" {
  description = "Security processing SQS queue ARN"
  value       = aws_sqs_queue.security_queue.arn
}

output "security_dlq_url" {
  description = "Security DLQ URL"
  value       = aws_sqs_queue.security_dlq.url
}

output "security_dlq_arn" {
  description = "Security DLQ ARN"
  value       = aws_sqs_queue.security_dlq.arn
}