variable "aws_region" {
  description = "AWS region for deploying the GenAI Security Gateway."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment (e.g. dev, staging, prod)."
  type        = string
  default     = "prod"
}

variable "project_name" {
  description = "Base name for provisioned cloud security resources."
  type        = string
  default     = "genai-sec-gateway"
}

variable "bedrock_model_id" {
  description = "Primary Amazon Bedrock model ARN/ID targeted by the gateway."
  type        = string
  default     = "anthropic.claude-3-sonnet-20240229-v1:0"
}

variable "rate_limit_per_second" {
  description = "Max steady-state requests per second per tenant."
  type        = number
  default     = 50
}

variable "burst_limit" {
  description = "Max burst capacity for the gateway API."
  type        = number
  default     = 100
}
