"""
CLOUD GUARD // CF-PS-19: Local Interactive SecOps Web Server & Drift Simulator
Runs the full 3D Cyber-Sphere SecOps Platform locally at http://127.0.0.1:8000
No AWS credentials required!
"""

import base64
import hashlib
import http.server
import json
import socketserver
import sys
import time
import uuid
import webbrowser
from datetime import datetime, timezone

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

PORT = 8000

EXPECTED_CONFIG = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}

# Live simulated sandbox state
sim_state = {
    "targetBucket": {
        "name": "cf-ps19-target-sandbox-849201",
        "status": "COMPLIANT_LOCKED",
        "tags": {"Environment": "Sandbox", "AutoRemediate": "true"},
        "configuration": EXPECTED_CONFIG.copy(),
    },
    "unscopedBucket": {
        "name": "cf-ps19-unscoped-production-849201",
        "status": "COMPLIANT_LOCKED",
        "tags": {"Environment": "Production", "AutoRemediate": "false"},
        "configuration": EXPECTED_CONFIG.copy(),
    },
    "evidenceLocker": {
        "bucket": "cf-ps19-evidence-849201",
        "storedArtifacts": 14,
        "totalSizeBytes": 38400,
    },
    "auditLogs": [
        {
            "eventId": "cf-ps19-init-golden-baseline",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "bucketName": "cf-ps19-target-sandbox-849201",
            "triggerEvent": "BaselineComplianceCheck",
            "status": "REMEDIATED",
            "mttrMs": 74,
            "driftType": "S3_FULL_PUBLIC_ACCESS_EXPOSURE",
            "expectedConfig": json.dumps(EXPECTED_CONFIG),
            "beforeConfig": json.dumps({k: False for k in EXPECTED_CONFIG}),
            "afterConfig": json.dumps(EXPECTED_CONFIG),
            "changesLog": json.dumps({
                k: {
                    "field": k,
                    "beforeValue": False,
                    "afterValue": True,
                    "transition": "false ➔ true",
                    "modifiedBy": "cf-ps19-remediator",
                    "enforcedPolicy": "CIS AWS S3.1",
                }
                for k in EXPECTED_CONFIG
            }),
            "evidenceSha256": "8f4e2b1c9d0a7f6e5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a",
            "s3BeforeUri": "s3://cf-ps19-evidence-849201/evidence/init/before_state.json",
            "s3AfterUri": "s3://cf-ps19-evidence-849201/evidence/init/after_state.json",
        }
    ],
}


class CloudGuardHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Clean terminal logging
        pass

    def send_cors_headers(self, content_type="application/json"):
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_cors_headers("text/plain")
        self.end_headers()
        self.wfile.write(b"OK")

    def do_GET(self):
        url_path = self.path.split("?")[0]

        if url_path in ("/", "/index.html"):
            try:
                with open("index.html", "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_cors_headers("text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(content)
            except Exception as e:
                self.send_response(500)
                self.send_cors_headers("text/plain")
                self.end_headers()
                self.wfile.write(f"Error loading index.html: {e}".encode("utf-8"))
            return

        if url_path == "/api/status":
            payload = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "region": "us-east-1",
                "goldenBaselinePolicy": EXPECTED_CONFIG,
                "targetBucket": sim_state["targetBucket"],
                "unscopedBucket": sim_state["unscopedBucket"],
                "evidenceLocker": sim_state["evidenceLocker"],
                "recentAuditLogs": sim_state["auditLogs"],
            }
            self.send_response(200)
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(payload, default=str).encode("utf-8"))
            return

        if url_path == "/api/evidence-bundle":
            bundle = {
                "reportId": f"CLOUD-GUARD-FORENSIC-LOCAL-{int(time.time())}",
                "generatedAt": datetime.now(timezone.utc).isoformat(),
                "architecture": {
                    "targetBucket": sim_state["targetBucket"]["name"],
                    "unscopedBucket": sim_state["unscopedBucket"]["name"],
                    "evidenceBucket": sim_state["evidenceLocker"]["bucket"],
                    "framework": "CIS AWS Foundations Benchmark S3.1",
                    "goldenBaselinePolicy": EXPECTED_CONFIG,
                },
                "totalAuditedEvents": len(sim_state["auditLogs"]),
                "auditRecords": sim_state["auditLogs"],
            }
            raw = json.dumps(bundle, sort_keys=True)
            bundle["packageSha256"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            self.send_response(200)
            self.send_cors_headers()
            self.send_header("Content-Disposition", 'attachment; filename="cloud-guard-forensic-bundle.json"')
            self.end_headers()
            self.wfile.write(json.dumps(bundle, indent=2).encode("utf-8"))
            return

        if url_path == "/api/evidence-file":
            latest = sim_state["auditLogs"][0] if sim_state["auditLogs"] else {}
            mock_file = {
                "key": "evidence/latest/forensic_bundle.json",
                "s3Uri": f"s3://{sim_state['evidenceLocker']['bucket']}/evidence/latest/forensic_bundle.json",
                "lastModified": datetime.now(timezone.utc).isoformat(),
                "data": latest,
            }
            self.send_response(200)
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(mock_file, default=str).encode("utf-8"))
            return

        self.send_response(404)
        self.send_cors_headers("text/plain")
        self.end_headers()
        self.wfile.write(b"404 Not Found")

    def do_POST(self):
        url_path = self.path.split("?")[0]
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        try:
            req_data = json.loads(body)
        except Exception:
            req_data = {}

        now_iso = datetime.now(timezone.utc).isoformat()

        if url_path == "/api/inject-violation":
            v_type = req_data.get("violationType", "full")
            phase = req_data.get("phase", "both")
            event_id = str(uuid.uuid4())

            # Configure broken state based on scenario
            if v_type == "policy":
                broken_cfg = {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                }
                scenario_name = "Violation 2: Public Bucket Policy Drift (2 Flags)"
                drift_type = "S3_BUCKET_POLICY_PUBLIC_DRIFT"
            elif v_type == "acl":
                broken_cfg = {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
                scenario_name = "Violation 3: Public ACL Injection Drift (2 Flags)"
                drift_type = "S3_ACL_PUBLIC_ACCESS_DRIFT"
            else:
                broken_cfg = {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                }
                scenario_name = "Violation 1: Full Public Access Exposure (4 Flags)"
                drift_type = "S3_FULL_PUBLIC_ACCESS_EXPOSURE"

            if phase == "break":
                sim_state["targetBucket"]["status"] = "EXPOSED_DRIFT"
                sim_state["targetBucket"]["configuration"] = broken_cfg
                print(f"  [PHASE 1 RED ALERT] Injected {scenario_name} on S3 bucket!")
                res = {
                    "success": True,
                    "phase": "break",
                    "scenario": scenario_name,
                    "message": "Bucket broken on S3. Observing 3.5s Red Alert state.",
                }
            else:
                # Phase 2: Remediate back to baseline
                sim_state["targetBucket"]["status"] = "COMPLIANT_LOCKED"
                sim_state["targetBucket"]["configuration"] = EXPECTED_CONFIG.copy()

                # Calculate dynamic field changes
                changes = {}
                for k in EXPECTED_CONFIG:
                    if broken_cfg[k] != EXPECTED_CONFIG[k]:
                        changes[k] = {
                            "field": k,
                            "beforeValue": broken_cfg[k],
                            "afterValue": EXPECTED_CONFIG[k],
                            "transition": f"{str(broken_cfg[k]).lower()} ➔ {str(EXPECTED_CONFIG[k]).lower()}",
                            "modifiedBy": "cf-ps19-remediator",
                            "enforcedPolicy": "CIS AWS Foundations Benchmark S3.1",
                        }

                audit_item = {
                    "eventId": event_id,
                    "timestamp": now_iso,
                    "bucketName": sim_state["targetBucket"]["name"],
                    "triggerEvent": "PutBucketPublicAccessBlock",
                    "status": "REMEDIATED",
                    "mttrMs": 72,
                    "driftType": drift_type,
                    "expectedConfig": json.dumps(EXPECTED_CONFIG),
                    "beforeConfig": json.dumps(broken_cfg),
                    "afterConfig": json.dumps(EXPECTED_CONFIG),
                    "changesLog": json.dumps(changes),
                    "evidenceSha256": hashlib.sha256(json.dumps(changes, sort_keys=True).encode("utf-8")).hexdigest(),
                    "s3BeforeUri": f"s3://{sim_state['evidenceLocker']['bucket']}/evidence/{event_id}/before_state.json",
                    "s3AfterUri": f"s3://{sim_state['evidenceLocker']['bucket']}/evidence/{event_id}/after_state.json",
                }
                sim_state["auditLogs"].insert(0, audit_item)
                print(f"  [PHASE 2 EMERALD HEAL] Restored CIS S3.1 baseline! ({len(changes)} fields modified, MTTR 72ms)")
                res = {
                    "success": True,
                    "phase": "remediate",
                    "scenario": scenario_name,
                    "changesCount": len(changes),
                    "eventId": event_id,
                }

            self.send_response(200)
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(res).encode("utf-8"))
            return

        if url_path == "/api/test-unscoped":
            event_id = str(uuid.uuid4())
            sim_state["unscopedBucket"]["status"] = "OUT_OF_SCOPE_UNTOUCHED"
            sim_state["unscopedBucket"]["configuration"] = {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
            # Record refusal in audit log
            proof_item = {
                "eventId": event_id,
                "timestamp": now_iso,
                "bucketName": sim_state["unscopedBucket"]["name"],
                "triggerEvent": "PutBucketPublicAccessBlock",
                "status": "SKIPPED_OUT_OF_SCOPE",
                "mttrMs": 14,
                "driftType": "UNSCOPED_RESOURCE_DRIFT_IGNORED",
                "expectedConfig": json.dumps(EXPECTED_CONFIG),
                "beforeConfig": json.dumps(sim_state["unscopedBucket"]["configuration"]),
                "afterConfig": json.dumps(sim_state["unscopedBucket"]["configuration"]),
                "changesLog": json.dumps({}),
                "evidenceSha256": hashlib.sha256(event_id.encode("utf-8")).hexdigest(),
                "s3BeforeUri": f"s3://{sim_state['evidenceLocker']['bucket']}/evidence/{event_id}/out_of_scope_proof.json",
                "s3AfterUri": f"s3://{sim_state['evidenceLocker']['bucket']}/evidence/{event_id}/out_of_scope_proof.json",
            }
            sim_state["auditLogs"].insert(0, proof_item)
            print("  [GUARDRAIL REFUSAL] Remediator refused modifying unscoped bucket (SKIPPED_OUT_OF_SCOPE, 0 fields)!")
            self.send_response(200)
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "action": "GUARDRAIL_BLOCKED"}).encode("utf-8"))
            return

        if url_path == "/api/restore-unscoped":
            sim_state["unscopedBucket"]["status"] = "COMPLIANT_LOCKED"
            sim_state["unscopedBucket"]["configuration"] = EXPECTED_CONFIG.copy()
            print("  [HANDS-FREE RESET] Control bucket automatically restored to baseline (0 manual clicks)!")
            self.send_response(200)
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "action": "CONTROL_RESET"}).encode("utf-8"))
            return

        self.send_response(404)
        self.send_cors_headers("text/plain")
        self.end_headers()
        self.wfile.write(b"404 Not Found")


def run_local_server():
    print("=" * 75)
    print("  CLOUD GUARD // CF-PS-19 LOCAL INTERACTIVE SEC-OPS TEST SERVER")
    print("=" * 75)
    print(f"  Starting local HTTP server on port {PORT}...")
    print(f"  URL: http://127.0.0.1:{PORT}/")
    print("  Features enabled:")
    print("    - 3D Cyber-Sphere WebGL Living Canvas")
    print("    - Interactive Violation Launcher (All 4 scenarios)")
    print("    - Observable 3.5s Red Alert -> Emerald Green Auto-Heal Timeline")
    print("    - Dynamic 2-field vs 4-field Forensic Diffing in Panel 2")
    print("    - Hands-Free 8-Second Guardrail Refusal & Auto-Reset in Panel 1")
    print("    - Complete Amazon DynamoDB & S3 Evidence Locker simulation")
    print("=" * 75)

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), CloudGuardHandler) as httpd:
        print(f"\n  [READY] Server running at http://127.0.0.1:{PORT}/")
        print("  Press Ctrl+C to stop.\n")
        try:
            webbrowser.open(f"http://127.0.0.1:{PORT}/")
        except Exception:
            pass
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n  Stopping CLOUD GUARD local server.")


if __name__ == "__main__":
    run_local_server()
