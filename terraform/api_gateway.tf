resource "aws_apigatewayv2_api" "upload_api" {
  name          = "${var.project_name}-upload-api"
  protocol_type = "HTTP"

  cors_configuration {
    allow_origins = ["*"]
    allow_methods = ["POST", "OPTIONS"]
    allow_headers = ["content-type"]
  }

  tags = {
    Name        = "SecureFileGuard Upload API"
    Project     = var.project_name
    Environment = "dev"
  }
}


resource "aws_apigatewayv2_integration" "upload_lambda" {
  api_id = aws_apigatewayv2_api.upload_api.id

  integration_type   = "AWS_PROXY"
  integration_uri    = aws_lambda_function.upload.invoke_arn
  integration_method = "POST"
}


resource "aws_apigatewayv2_route" "upload" {
  api_id = aws_apigatewayv2_api.upload_api.id

  route_key = "POST /upload"
  target    = "integrations/${aws_apigatewayv2_integration.upload_lambda.id}"
}


resource "aws_apigatewayv2_stage" "default" {
  api_id = aws_apigatewayv2_api.upload_api.id

  name = "$default"

  auto_deploy = true
}


resource "aws_lambda_permission" "api_gateway" {
  statement_id = "AllowAPIGatewayInvoke"

  action = "lambda:InvokeFunction"

  function_name = aws_lambda_function.upload.function_name

  principal = "apigateway.amazonaws.com"

  source_arn = "${aws_apigatewayv2_api.upload_api.execution_arn}/*/*"
}


output "upload_api_url" {
  description = "SecureFileGuard Upload API URL"
  value       = aws_apigatewayv2_api.upload_api.api_endpoint
}