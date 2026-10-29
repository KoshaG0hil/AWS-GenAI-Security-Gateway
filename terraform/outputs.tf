output "api_endpoint" {
  description = "Invocation URL for the GenAI Security Gateway HTTP API."
  value       = aws_apigatewayv2_api.http_api.api_endpoint
}

output "lambda_arn" {
  description = "ARN of the GenAI Gateway Lambda reverse proxy."
  value       = aws_lambda_function.gateway_proxy.arn
}

output "waf_acl_arn" {
  description = "ARN of the AWS WAFv2 Web ACL protecting the gateway."
  value       = aws_wafv2_web_acl.api_waf.arn
}

output "audit_s3_bucket" {
  description = "S3 bucket name where tamper-evident AI safety audit trails are stored."
  value       = aws_s3_bucket.audit_logs.bucket
}

output "dynamodb_table_quotas" {
  description = "DynamoDB table storing sliding window token quotas per tenant."
  value       = aws_dynamodb_table.tenant_quotas.name
}

output "bedrock_model_id" {
  description = "Configured foundation model identifier."
  value       = var.bedrock_model_id
}
