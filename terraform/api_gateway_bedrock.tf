# -----------------------------------------------------------------------------
# Tamper-Evident AI Safety Audit Bucket (S3)
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "audit_logs" {
  bucket        = "${local.name_prefix}-audit-manifests-${local.account_id}"
  force_destroy = false
}

resource "aws_s3_bucket_versioning" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# -----------------------------------------------------------------------------
# Tenant Token Budget State Table (DynamoDB)
# -----------------------------------------------------------------------------
resource "aws_dynamodb_table" "tenant_quotas" {
  name         = "${local.name_prefix}-tenant-quotas"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "tenant_id"

  attribute {
    name = "tenant_id"
    type = "S"
  }

  ttl {
    attribute_name = "ttl_timestamp"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }
}

# -----------------------------------------------------------------------------
# Lambda Execution Role & Least Privilege Policies
# -----------------------------------------------------------------------------
resource "aws_iam_role" "lambda_exec" {
  name = "${local.name_prefix}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "lambda_bedrock_access" {
  name        = "${local.name_prefix}-bedrock-policy"
  description = "Allows GenAI Gateway to invoke Amazon Bedrock foundation models."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream"
        ]
        Resource = [
          "arn:aws:bedrock:${local.region_name}::foundation-model/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem"
        ]
        Resource = aws_dynamodb_table.tenant_quotas.arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.audit_logs.arn}/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_bedrock_attach" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = aws_iam_policy.lambda_bedrock_access.arn
}

resource "aws_iam_role_policy_attachment" "lambda_basic_logs" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# -----------------------------------------------------------------------------
# Lambda Deployment Package & Function
# -----------------------------------------------------------------------------
data "archive_file" "lambda_dummy_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda_payload.zip"

  source {
    content  = "def lambda_handler(event, context): return {'statusCode': 200, 'body': 'ok'}"
    filename = "index.py"
  }
}

resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${local.name_prefix}-proxy"
  retention_in_days = 30
}

resource "aws_lambda_function" "gateway_proxy" {
  function_name    = "${local.name_prefix}-proxy"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "src.lambda_gateway_handler.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.lambda_dummy_zip.output_path
  source_code_hash = data.archive_file.lambda_dummy_zip.output_base64sha256
  timeout          = 30
  memory_size      = 512

  environment {
    variables = {
      ENVIRONMENT        = var.environment
      BEDROCK_MODEL_ID   = var.bedrock_model_id
      AUDIT_BUCKET_NAME  = aws_s3_bucket.audit_logs.bucket
      QUOTA_DYNAMO_TABLE = aws_dynamodb_table.tenant_quotas.name
    }
  }

  depends_on = [aws_cloudwatch_log_group.lambda_logs]
}

# -----------------------------------------------------------------------------
# Amazon API Gateway (HTTP v2)
# -----------------------------------------------------------------------------
resource "aws_apigatewayv2_api" "http_api" {
  name          = "${local.name_prefix}-http-api"
  protocol_type = "HTTP"

  cors_configuration {
    allow_origins = ["*"]
    allow_methods = ["POST", "OPTIONS"]
    allow_headers = ["content-type", "authorization", "x-tenant-id"]
    max_age       = 300
  }
}

resource "aws_apigatewayv2_integration" "lambda_int" {
  api_id                 = aws_apigatewayv2_api.http_api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.gateway_proxy.arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "inference_route" {
  api_id    = aws_apigatewayv2_api.http_api.id
  route_key = "POST /v1/chat/completions"
  target    = "integrations/${aws_apigatewayv2_integration.lambda_int.id}"
}

resource "aws_cloudwatch_log_group" "api_access_logs" {
  name              = "/aws/apigateway/${local.name_prefix}-access-logs"
  retention_in_days = 30
}

resource "aws_apigatewayv2_stage" "default_stage" {
  api_id      = aws_apigatewayv2_api.http_api.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_access_logs.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
    })
  }

  default_route_settings {
    throttling_burst_limit = var.burst_limit
    throttling_rate_limit  = var.rate_limit_per_second
  }
}

resource "aws_lambda_permission" "api_gateway_invoke" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.gateway_proxy.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.http_api.execution_arn}/*/*"
}

# -----------------------------------------------------------------------------
# AWS WAFv2 Web ACL for L7 Ingress Protection
# -----------------------------------------------------------------------------
resource "aws_wafv2_web_acl" "api_waf" {
  name        = "${local.name_prefix}-waf"
  description = "WAF protection for GenAI API Gateway with rate limiting & OWASP rules."
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 10

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CommonRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "TenantRateLimit"
    priority = 20

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "TenantRateLimitMetric"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name_prefix}-waf-metric"
    sampled_requests_enabled   = true
  }
}
