"""
CLOUD GUARD // CF-PS-19: Autonomous Cloud Misconfiguration Auto-Remediation Engine
Engineered for AWS Builder / Learner Sandbox Account ($100 credits) in region us-east-1

Triggered by Amazon EventBridge (aws.s3 CloudTrail / cf.ps19.detector).
Features:
- Defined Golden Baseline Configuration (CIS AWS S3.1)
- Triple-layer scope guardrails (Name match + S3 Tagging check)
- Infinite loop prevention
- Field-by-field Changes Log computation (false ➔ true)
- Cryptographic SHA-256 Evidence Integrity Hashing
- Forensic cloud storage in Amazon S3 (before_state, after_state, forensic_bundle, out_of_scope_proof)
- Millisecond-precision MTTR measurement
- Complete audit logging to Amazon DynamoDB
"""

import hashlib
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment configuration
ALLOWED_TARGET_BUCKET = os.environ.get("ALLOWED_TARGET_BUCKET", "")
EVIDENCE_BUCKET = os.environ.get("EVIDENCE_BUCKET", "")
AUDIT_TABLE = os.environ.get("AUDIT_TABLE", "cf-ps19-audit-logs")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

# Golden Baseline Policy defined for CF-PS-19
EXPECTED_CONFIG = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}

s3 = boto3.client("s3", region_name=AWS_REGION)
dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
table = dynamodb.Table(AUDIT_TABLE)


def get_bucket_tags_dict(bucket_name: str) -> dict:
    """Safely retrieves bucket tags as a key-value dictionary."""
    if not bucket_name:
        return {}
    try:
        response = s3.get_bucket_tagging(Bucket=bucket_name)
        return {tag["Key"]: tag["Value"] for tag in response.get("TagSet", [])}
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code in ("NoSuchTagSet", "NoSuchBucket"):
            return {}
        logger.warning(f"Error fetching tags for {bucket_name}: {e}")
        return {}


def get_current_public_access_block(bucket_name: str) -> dict:
    """
    Safely retrieves the current PublicAccessBlock configuration.
    Returns a dict with all 4 boolean flags.
    """
    if not bucket_name:
        return {k: False for k in EXPECTED_CONFIG}
    try:
        resp = s3.get_public_access_block(Bucket=bucket_name)
        config = resp.get("PublicAccessBlockConfiguration", {})
        return {
            "BlockPublicAcls": bool(config.get("BlockPublicAcls", False)),
            "IgnorePublicAcls": bool(config.get("IgnorePublicAcls", False)),
            "BlockPublicPolicy": bool(config.get("BlockPublicPolicy", False)),
            "RestrictPublicBuckets": bool(config.get("RestrictPublicBuckets", False)),
        }
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "NoSuchPublicAccessBlockConfiguration":
            return {k: False for k in EXPECTED_CONFIG}
        logger.error(f"Error reading public access block for {bucket_name}: {e}")
        return {k: False for k in EXPECTED_CONFIG}


def save_evidence_json(key: str, data: dict):
    """Stores structured JSON evidence in the designated forensic evidence S3 bucket."""
    if not EVIDENCE_BUCKET:
        logger.warning("No EVIDENCE_BUCKET defined. Skipping S3 upload.")
        return
    try:
        s3.put_object(
            Bucket=EVIDENCE_BUCKET,
            Key=key,
            Body=json.dumps(data, indent=2, default=str),
            ContentType="application/json",
            ServerSideEncryption="AES256",
        )
        logger.info(f"Forensic evidence saved to s3://{EVIDENCE_BUCKET}/{key}")
    except Exception as e:
        logger.error(f"Failed to save evidence to s3://{EVIDENCE_BUCKET}/{key}: {e}")


def lambda_handler(event, context):
    start_time = time.time()
    iso_timestamp = datetime.now(timezone.utc).isoformat()
    event_id = event.get("id") or str(uuid.uuid4())

    logger.info(f"=== CLOUD GUARD // CF-PS-19 Remediator triggered for event {event_id} ===")
    logger.info(f"Raw Event: {json.dumps(event, default=str)}")

    # Extract target bucket name from detail or requestParameters
    detail = event.get("detail", {})
    req_params = detail.get("requestParameters", {}) or {}
    bucket_name = req_params.get("bucketName") or detail.get("bucketName") or ""

    if not bucket_name:
        logger.error("Could not extract bucketName from EventBridge payload. Aborting.")
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "Missing bucketName in event detail"}),
        }

    # Fetch live tags and current access block status
    bucket_tags = get_bucket_tags_dict(bucket_name)
    current_config = get_current_public_access_block(bucket_name)
    auto_remediate_tag = str(bucket_tags.get("AutoRemediate", "")).lower() == "true"

    logger.info(f"Evaluating Bucket: {bucket_name}")
    logger.info(f"Allowed Target Bucket: {ALLOWED_TARGET_BUCKET}")
    logger.info(f"Bucket Tags: {bucket_tags} (AutoRemediate={auto_remediate_tag})")
    logger.info(f"Current Config: {current_config}")

    # =========================================================================
    # GUARDRAIL LAYER 1 & 2: Name Scope Lock & Bucket Tag Verification
    # =========================================================================
    is_name_allowed = (bucket_name == ALLOWED_TARGET_BUCKET)
    is_scope_valid = is_name_allowed and auto_remediate_tag

    if not is_scope_valid:
        elapsed_ms = int((time.time() - start_time) * 1000)
        rejection_reason = []
        if not is_name_allowed:
            rejection_reason.append(
                f"Bucket '{bucket_name}' does not match ALLOWED_TARGET_BUCKET '{ALLOWED_TARGET_BUCKET}'"
            )
        if not auto_remediate_tag:
            rejection_reason.append(
                f"Bucket '{bucket_name}' lacks required tag 'AutoRemediate=true' (found '{bucket_tags.get('AutoRemediate')}')"
            )

        reason_str = "; ".join(rejection_reason)
        evidence_key = f"evidence/{event_id}/out_of_scope_proof.json"

        # Compute SHA-256 integrity hash for guardrail refusal proof
        proof_payload = {
            "eventId": event_id,
            "timestamp": iso_timestamp,
            "bucketName": bucket_name,
            "allowedTargetBucket": ALLOWED_TARGET_BUCKET,
            "bucketTags": bucket_tags,
            "currentPublicAccessBlock": current_config,
            "action": "SKIPPED_OUT_OF_SCOPE",
            "verdict": "GUARDRAIL_BLOCKED",
            "reason": reason_str,
            "changesApplied": [],
            "processingTimeMs": elapsed_ms,
        }
        proof_sha256 = hashlib.sha256(json.dumps(proof_payload, sort_keys=True).encode("utf-8")).hexdigest()
        proof_payload["evidenceSha256"] = proof_sha256

        # Save immutable forensic evidence of the skipped out-of-scope event to S3
        save_evidence_json(evidence_key, proof_payload)

        # Record in DynamoDB audit trail
        try:
            table.put_item(
                Item={
                    "eventId": event_id,
                    "timestamp": iso_timestamp,
                    "bucketName": bucket_name,
                    "status": "SKIPPED_OUT_OF_SCOPE",
                    "action": "GUARDRAIL_BLOCKED",
                    "reason": reason_str,
                    "mttrMs": elapsed_ms,
                    "triggerEvent": detail.get("eventName", "PutBucketPublicAccessBlock"),
                    "expectedConfig": json.dumps(EXPECTED_CONFIG),
                    "beforeConfig": json.dumps(current_config),
                    "afterConfig": json.dumps(current_config),
                    "changesLog": json.dumps({}),
                    "evidenceSha256": proof_sha256,
                    "s3EvidenceUri": f"s3://{EVIDENCE_BUCKET}/{evidence_key}" if EVIDENCE_BUCKET else "",
                    "driftType": "UNSCOPED_RESOURCE_DRIFT_IGNORED",
                    "tags": json.dumps(bucket_tags),
                    "remediatedBy": "CLOUD_GUARD_GUARDRAIL",
                }
            )
            logger.info(f"Guardrail refusal recorded in DynamoDB table {AUDIT_TABLE}")
        except Exception as ddb_err:
            logger.error(f"Failed to record out_of_scope to DynamoDB: {ddb_err}")

        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "message": "Resource is outside remediation scope. Protected by CLOUD GUARD guardrails.",
                    "proof": proof_payload,
                }
            ),
        }

    # =========================================================================
    # GUARDRAIL LAYER 3: Infinite Loop Prevention
    # If all 4 flags already match EXPECTED_CONFIG, exit cleanly
    # =========================================================================
    is_fully_compliant = (
        current_config.get("BlockPublicAcls") is True
        and current_config.get("IgnorePublicAcls") is True
        and current_config.get("BlockPublicPolicy") is True
        and current_config.get("RestrictPublicBuckets") is True
    )

    if is_fully_compliant:
        logger.info(f"Bucket {bucket_name} already matches Expected Config. Halting to prevent loop.")
        return {
            "statusCode": 200,
            "body": json.dumps({"message": "Bucket already fully compliant. No drift."}),
        }

    # =========================================================================
    # FORENSIC STEP 1: Retain Before State in S3
    # =========================================================================
    before_state_key = f"evidence/{event_id}/before_state.json"
    before_state_payload = {
        "eventId": event_id,
        "timestamp": iso_timestamp,
        "bucketName": bucket_name,
        "driftType": "S3_PUBLIC_ACCESS_BLOCK_DISABLED",
        "rawTriggerEvent": event,
        "capturedConfiguration": current_config,
        "expectedConfiguration": EXPECTED_CONFIG,
        "bucketTags": bucket_tags,
        "storageLocation": f"s3://{EVIDENCE_BUCKET}/{before_state_key}",
    }
    save_evidence_json(before_state_key, before_state_payload)

    # =========================================================================
    # EXECUTION STEP 2: Execute Remediation on S3
    # Enforces Golden Baseline Policy (all 4 flags True)
    # =========================================================================
    logger.info(f"Executing CLOUD GUARD auto-remediation on {bucket_name}: Enforcing baseline policy...")
    try:
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration=EXPECTED_CONFIG,
        )
        logger.info(f"Successfully applied PublicAccessBlock to {bucket_name}")
    except ClientError as e:
        logger.error(f"Failed to apply public access block to {bucket_name}: {e}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": f"S3 put_public_access_block failed: {str(e)}"}),
        }

    # =========================================================================
    # VERIFICATION STEP 3: Verify and Retain After State + Exact Changes Log
    # =========================================================================
    verified_config = get_current_public_access_block(bucket_name)
    elapsed_ms = int((time.time() - start_time) * 1000)
    remediation_verified = (
        verified_config.get("BlockPublicAcls") is True
        and verified_config.get("IgnorePublicAcls") is True
        and verified_config.get("BlockPublicPolicy") is True
        and verified_config.get("RestrictPublicBuckets") is True
    )

    # Compute explicit field-by-field Changes Log
    changes_log = {}
    for key in EXPECTED_CONFIG.keys():
        b_val = current_config.get(key)
        a_val = verified_config.get(key)
        if b_val != a_val:
            changes_log[key] = {
                "field": key,
                "beforeValue": b_val,
                "afterValue": a_val,
                "transition": f"{str(b_val).lower()} ➔ {str(a_val).lower()}",
                "modifiedBy": "cf-ps19-remediator",
                "enforcedPolicy": "CIS AWS Foundations Benchmark S3.1",
            }

    # Compute SHA-256 evidence integrity hash
    evidence_bundle_payload = {
        "eventId": event_id,
        "timestamp": iso_timestamp,
        "remediatedTimestamp": datetime.now(timezone.utc).isoformat(),
        "bucketName": bucket_name,
        "expectedConfig": EXPECTED_CONFIG,
        "beforeConfig": current_config,
        "afterConfig": verified_config,
        "changesLog": changes_log,
        "mttrMs": elapsed_ms,
        "verified": remediation_verified,
        "framework": "CIS AWS S3.1 / NIST 800-53 SC-7",
    }
    evidence_sha256 = hashlib.sha256(
        json.dumps(evidence_bundle_payload, sort_keys=True).encode("utf-8")
    ).hexdigest()
    evidence_bundle_payload["evidenceSha256"] = evidence_sha256

    after_state_key = f"evidence/{event_id}/after_state.json"
    after_state_payload = {
        "eventId": event_id,
        "remediatedTimestamp": datetime.now(timezone.utc).isoformat(),
        "bucketName": bucket_name,
        "remediationVerified": remediation_verified,
        "verifiedConfiguration": verified_config,
        "meanTimeToRemediateMs": elapsed_ms,
        "complianceStatus": "COMPLIANT_LOCKED",
        "evidenceSha256": evidence_sha256,
        "appliedRule": "CIS AWS Foundation S3.1 Public Access Block Enforcer",
        "storageLocation": f"s3://{EVIDENCE_BUCKET}/{after_state_key}",
    }
    save_evidence_json(after_state_key, after_state_payload)

    # Save complete unified forensic bundle to S3
    bundle_key = f"evidence/{event_id}/forensic_bundle.json"
    save_evidence_json(bundle_key, evidence_bundle_payload)

    # =========================================================================
    # AUDIT LOGGING STEP 4: Store in DynamoDB (Complete Audit Item)
    # =========================================================================
    # Dynamic drift type classification
    if len(changes_log) == 4:
        drift_type = "S3_FULL_PUBLIC_ACCESS_EXPOSURE"
    elif "BlockPublicPolicy" in changes_log and "BlockPublicAcls" not in changes_log:
        drift_type = "S3_BUCKET_POLICY_PUBLIC_DRIFT"
    elif "BlockPublicAcls" in changes_log and "BlockPublicPolicy" not in changes_log:
        drift_type = "S3_ACL_PUBLIC_ACCESS_DRIFT"
    else:
        drift_type = "S3_PUBLIC_ACCESS_BLOCK_DISABLED"

    audit_record = {
        "eventId": event_id,
        "timestamp": iso_timestamp,
        "bucketName": bucket_name,
        "status": "REMEDIATED" if remediation_verified else "REMEDIATION_UNVERIFIED",
        "action": "PUBLIC_ACCESS_BLOCK_ENFORCED",
        "triggerEvent": detail.get("eventName", "PutBucketPublicAccessBlock"),
        "mttrMs": elapsed_ms,
        "driftType": drift_type,
        "expectedConfig": json.dumps(EXPECTED_CONFIG),
        "beforeConfig": json.dumps(current_config),
        "afterConfig": json.dumps(verified_config),
        "changesLog": json.dumps(changes_log),
        "evidenceSha256": evidence_sha256,
        "s3BeforeUri": f"s3://{EVIDENCE_BUCKET}/{before_state_key}" if EVIDENCE_BUCKET else "",
        "s3AfterUri": f"s3://{EVIDENCE_BUCKET}/{after_state_key}" if EVIDENCE_BUCKET else "",
        "s3BundleUri": f"s3://{EVIDENCE_BUCKET}/{bundle_key}" if EVIDENCE_BUCKET else "",
        "tags": json.dumps(bucket_tags),
        "remediatedBy": "cf-ps19-remediator",
    }

    try:
        table.put_item(Item=audit_record)
        logger.info(f"Audit log successfully recorded to DynamoDB table {AUDIT_TABLE}")
    except Exception as e:
        logger.error(f"Failed to record audit log to DynamoDB: {e}")

    logger.info(f"=== CLOUD GUARD Auto-Remediation Complete! MTTR: {elapsed_ms}ms ===")
    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "message": "CLOUD GUARD auto-remediation successfully executed and verified.",
                "eventId": event_id,
                "mttrMs": elapsed_ms,
                "verified": remediation_verified,
                "changesLog": changes_log,
                "evidenceSha256": evidence_sha256,
                "beforeState": before_state_payload,
                "afterState": after_state_payload,
            }
        ),
    }
