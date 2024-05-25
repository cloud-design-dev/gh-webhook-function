"""main entry point to webhook function"""
import logging
import os
import json
from ibm_cloud_sdk_core import ApiException
from helpers import verify_payload, verify_signature, create_code_engine_client



HEADERS = {"Content-Type": "text/plain;charset=utf-8"}

logger = logging.getLogger()


def main(params):
    ibmcloud_api_key = os.environ.get('IBMCLOUD_API_KEY')
    if not ibmcloud_api_key:
        raise ValueError("IBMCLOUD_API_KEY environment variable not found")

    secret_token = os.environ.get("WEBHOOK_SECRET")
    if not secret_token:
        raise ValueError("WEBHOOK_SECRET environment variable not found")

  
    payload_body = params
    headers = payload_body["__ce_headers"]
    signature_header = headers.get("X-Hub-Signature-256", None)
    image_tag = payload_body.get('workflow_run', {}).get('head_sha', None)
    if not image_tag:
        return {
            "headers": {"Content-Type": "application/json"},
            "statusCode": 400,
            "body": "Missing image tag"
        }
    
    verify_payload(payload_body)
    verify_signature(payload_body, secret_token, signature_header)

    try:
        code_engine_app = os.environ.get('CE_APP')
        code_engine_region = os.environ.get('CE_REGION')
        project_id = os.environ.get('CE_PROJECT_ID')
        icr_namespace = os.environ.get("ICR_NAMESPACE")
        icr_image= os.environ.get("ICR_IMAGE")
        icr_endpoint = code_engine_region.split('-')[0]

        code_engine_client = create_code_engine_client(ibmcloud_api_key, code_engine_region)

        get_app = code_engine_client.get_app(
            project_id=project_id,
            name=code_engine_app,
        ).get_result()

        etag = get_app.get('entity_tag')
        short_tag = image_tag[:8]
        app_patch_model = {
            "image_reference": f"private.{icr_endpoint}.icr.io/{icr_namespace}/{icr_image}:{short_tag}"
        }
        
        update_app = code_engine_client.update_app(
            project_id=project_id,
            name=code_engine_app,
            if_match=etag,
            app=app_patch_model,
        ).get_result()

        latest_ready_revision = update_app.get('latest_ready_revision')


        data = {
            "headers": {"Content-Type": "application/json"},
            "statusCode": 200,
            "latest_ready_revision": latest_ready_revision,
            "body": "App updated successfully"
        }
 
        return {
                "headers": {"Content-Type": "application/json"},
                "statusCode": 200,
                "body": json.dumps(data)
                }
    except ApiException as e:
        # Define results here to avoid the error
        results = {"error": str(e)}
        return {
                "headers": {"Content-Type": "application/json"},
                "statusCode": 500,
                "body": json.dumps(results)
        }
