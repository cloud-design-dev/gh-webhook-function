"""helper functions for __main.py__"""
import json
import hashlib
import hmac
from ibm_cloud_sdk_core.authenticators import IAMAuthenticator
from ibm_code_engine_sdk.code_engine_v2 import CodeEngineV2


HEADERS = {"Content-Type": "text/plain;charset=utf-8"}


def verify_payload(params):
    """Verify X-Hub-Signature-256, commits, & head_commit.id exist."""
    if (
        "__ce_headers" not in params
        or "X-Hub-Signature-256" not in params["__ce_headers"]
    ):
        return {
            "headers": HEADERS,
            "body": "Missing params.headers.X-Hub-Signature-256",
        }

    if "workflow_run" not in params:
        return {
            "headers": HEADERS,
            "body": "Missing params.workflow_run",
        }

    return None

def verify_signature(payload_body, secret_token, signature_header):
    """Verify that the payload was sent from GitHub by validating SHA256.

    Raise and return 403 if not authorized.

    Args:
        payload_body: original request body to verify (request.body())
        secret_token: GitHub app webhook token (WEBHOOK_SECRET)
        signature_header: header received from GitHub (x-hub-signature-256)
    """
    for value in payload_body:
        value: str
        if value.startswith("__"):
            del value
    payload_body_bytes = json.dumps(payload_body).encode('utf-8')

    hash_object = hmac.new(secret_token.encode('utf-8'), msg=payload_body_bytes, digestmod=hashlib.sha256)
    expected_signature = "sha256=" + hash_object.hexdigest()

    if not hmac.compare_digest(expected_signature, signature_header):
        return {
            "statusCode": 403,
            "headers": HEADERS,
            "body": "Request signatures didn't match!",
        }

    return None

def create_code_engine_client(ibmcloud_api_key, code_engine_region):
    """Create Code Engine client using IAM token."""
    authenticator = IAMAuthenticator(apikey=ibmcloud_api_key)
    service = CodeEngineV2(authenticator=authenticator)
    service.set_service_url('https://api.'+ code_engine_region +'.codeengine.cloud.ibm.com/v2')
    return service
