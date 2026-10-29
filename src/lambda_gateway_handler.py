"""AWS Lambda Handler: API Gateway Proxy for GenAI Security Mesh."""

import json
import logging
from typing import Any, Dict

from src.core.config import InferenceRequest
from src.gateway.bedrock_proxy import BedrockSecurityProxy

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Processes inbound inference requests through the Zero-Trust GenAI inspection gateway."""
    logger.info("Received request payload: %s", json.dumps(event))

    body = event.get("body", "{}")
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            body = {}

    prompt = body.get("prompt", "")
    if not prompt:
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "Missing required 'prompt' in request body."}),
        }

    request = InferenceRequest(
        tenant_id=body.get("tenant_id", "default-tenant"),
        model_id=body.get("model_id", "anthropic.claude-3-sonnet-20240229-v1:0"),
        prompt=prompt,
        max_tokens=body.get("max_tokens", 1000),
    )

    proxy = BedrockSecurityProxy(dry_run=event.get("dry_run", True))
    response = proxy.process(request)

    status_code = 403 if response.verdict.value == "BLOCK" else 200

    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "X-Security-Verdict": response.verdict.value,
            "X-Audit-ID": response.audit_id,
        },
        "body": json.dumps(response.model_dump()),
    }
