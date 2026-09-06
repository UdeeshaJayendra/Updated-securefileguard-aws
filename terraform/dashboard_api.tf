# ============================================================
# SecureFileGuard Dashboard API Gateway
# ============================================================

resource "aws_apigatewayv2_api" "dashboard_api" {
  name          = "${var.project_name}-dashboard-api"
  protocol_type = "HTTP"

  cors_configuration {
    allow_origins = ["*"]
    allow_methods = ["GET", "OPTIONS"]
    allow_headers = ["content-type"]
  }

  tags = {
    Name        = "SecureFileGuard Dashboard API"
    Project     = var.project_name
    Environment = "dev"
  }
}

resource "aws_apigatewayv2_integration" "dashboard_lambda" {
  api_id = aws_apigatewayv2_api.dashboard_api.id

  integration_type   = "AWS_PROXY"
  integration_uri    = aws_lambda_function.dashboard_api.invoke_arn
  integration_method = "POST"
}

resource "aws_apigatewayv2_route" "dashboard_scans" {
  api_id = aws_apigatewayv2_api.dashboard_api.id

  route_key = "GET /scans"
  target    = "integrations/${aws_apigatewayv2_integration.dashboard_lambda.id}"
}


resource "aws_apigatewayv2_route" "dashboard_statistics" {
  api_id = aws_apigatewayv2_api.dashboard_api.id

  route_key = "GET /statistics"
  target    = "integrations/${aws_apigatewayv2_integration.dashboard_lambda.id}"
}

resource "aws_apigatewayv2_stage" "dashboard_default" {
  api_id = aws_apigatewayv2_api.dashboard_api.id

  name        = "$default"
  auto_deploy = true
}

resource "aws_lambda_permission" "dashboard_api_gateway" {
  statement_id = "AllowDashboardAPIGatewayInvoke"

  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.dashboard_api.function_name
  principal     = "apigateway.amazonaws.com"

  source_arn = "${aws_apigatewayv2_api.dashboard_api.execution_arn}/*/*"
}

output "dashboard_api_url" {
  description = "SecureFileGuard Dashboard API URL"
  value       = aws_apigatewayv2_api.dashboard_api.api_endpoint
}