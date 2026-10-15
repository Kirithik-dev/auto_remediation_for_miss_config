# CLOUD GUARD // CF-PS-19
## Autonomous Cloud Misconfiguration Auto-Remediation Engine & 3D Cyber-Sphere SecOps Platform

[![AWS Region](https://img.shields.io/badge/AWS%20Region-us--east--1-FF9900?logo=amazon-aws)](https://aws.amazon.com/)
[![Target Environment](https://img.shields.io/badge/Sandbox-AWS%20Builder%20%2F%20Learner%20Lab-232F3E?logo=amazon-aws)](https://aws.amazon.com/)
[![Architecture](https://img.shields.io/badge/Architecture-Serverless%20Event--Driven-00f2fe)](https://aws.amazon.com/)
[![Compliance Standard](https://img.shields.io/badge/Compliance-CIS%20AWS%20S3.1%20%2F%20NIST%20800--53-00ff87)](https://www.cisecurity.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

An enterprise-grade, 100% AWS-deployed solution for hackathon problem statement **CF-PS-19: Auto-Remediation for Misconfiguration**, branded as **CLOUD GUARD** and engineered specifically to run inside an **AWS Builder / Learner Sandbox Account ($100 credits)** in region `us-east-1`.

Both the event-driven auto-remediation backend and the **CLOUD GUARD** interactive 3D web platform deploy directly to AWS using an **AWS Lambda Function URL** (`AuthType='NONE'`), requiring **zero localhost** or external server infrastructure.

---

## 1. Visual Design & 3D Cyber-Sphere Aesthetics ("CLOUD GUARD")

The web console replicates the futuristic cybersecurity reference design:
* **Midnight-Sapphire Theme:** Deep radial & linear sapphire backdrop (`#020817` → `#04153b` → `#072a6c`).
* **Architectural Outer Frame:** A crisp `1px solid rgba(255, 255, 255, 0.28)` rectangular frame inset `24px` from the viewport edges with glowing cyan corner accents.
* **Display Typography:** Geometric display headers in `Space Grotesk` / `Montserrat` with wide letter-spacing (`tracking-widest`), paired with `JetBrains Mono` for configs, diffs, and logs.
* **Interactive 3D Flowing Contour-Line Sphere (Three.js WebGL):**
  * **COMPLIANT [SECURE]:** 36 swirling neon contour ribbons rotate smoothly in electric cyan, aqua, and deep royal blue (`#00f2fe`, `#4facfe`, `#0061ff`).
  * **VIOLATION INTRODUCED:** Lines dynamically surge in rotation speed (6x velocity) and shift to fiery neon crimson (`#ff0844`) while the live AWS breach is observed.
  * **AUTO-REMEDIATED:** Pulses bright cyber-emerald (`#00ff87`) upon verified remediation before transitioning smoothly back to electric cyan.
* **Interactive Violation Launcher & SecOps Controls:**
  * **`⚡ Introduce Test Violation ▾`**: Dropdown popover allowing operators to launch 4 distinct real-world breach scenarios.
  * **`🛡️ Test Unscoped Resource`**: Direct shortcut to test guardrail refusal against production resources.
  * **`⬇ Export Cloud Evidence Bundle`**: Downloads cryptographic JSON forensic package with SHA-256 hash.
  * **ZERO MANUAL RESTORE BUTTONS**: 100% hands-free autonomous healing with automated background sandbox resetting.

---

## 2. Interactive Violation Launcher (4 Real-World Breach Scenarios)

CLOUD GUARD features an interactive Cloud Breach & Drift Simulator that tests granular AWS S3 drift patterns and validates dynamic forensic diffing:

| Scenario | Target Resource | Misconfiguration Injected | Expected Forensic Outcome |
| :--- | :--- | :--- | :--- |
| **Violation 1: Full Public Access Exposure** | `cf-ps19-target-*` | Sets all 4 flags to `false` (`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`) | **4 FIELDS MODIFIED** (`false ➔ true`). Engine restores CIS S3.1 golden baseline. |
| **Violation 2: Public Bucket Policy Drift** | `cf-ps19-target-*` | Sets only `BlockPublicPolicy: false` and `RestrictPublicBuckets: false` (keeps ACL flags `true`) | **2 FIELDS MODIFIED** (`false ➔ true`). Proves dynamic forensic diffing only logs fields that actually changed! |
| **Violation 3: Public ACL Injection Drift** | `cf-ps19-target-*` | Sets only `BlockPublicAcls: false` and `IgnorePublicAcls: false` (keeps Policy flags `true`) | **2 FIELDS MODIFIED** (`false ➔ true`). Dynamically classifies drift as `S3_ACL_PUBLIC_ACCESS_DRIFT`. |
| **Violation 4: Unscoped Production Resource Drift** | `cf-ps19-unscoped-*` (`Environment=Production`, `AutoRemediate=false`) | Sets `BlockPublicAcls: false` on control bucket | **0 fields (Untouched)**. Remediator halts with `SKIPPED_OUT_OF_SCOPE`. Control card turns AMBER/RED for 8s, then auto-resets hands-free. |

---

## 3. Real-World "Red Alert ➔ Auto-Heal Green" Visual Timeline

To provide visible, observable proof of detection and remediation (rather than sub-second invisible jumps), CLOUD GUARD executes a 2-phase lifecycle:

```
[0.0s] S3 Breach Injected Live on AWS
   │
   ├─► 3D Cyber-Sphere turns pulsing Crimson Red (#ff0844) with turbulent rotation
   ├─► Target Card border glows red with flashing "🚨 VIOLATION DETECTED (EXPOSED)" badge
   ├─► Live JSON viewer highlights "false" values in radiant glowing red
   │
[0.0s - 3.5s] SecOps Telemetry Pipeline Bar steps through live stages:
   │  [1] S3 Misconfiguration Injected (Live on AWS)
   │  ➔ [2] EventBridge Drift Rule Triggered
   │  ➔ [3] Capturing S3 Before-State Snapshot
   │  ➔ [4] Enforcing CIS S3.1 Baseline...
   │
[3.5s] Auto-Remediation Triggered & Verified
   │
   ├─► cf-ps19-remediator applies EXPECTED_CONFIG to S3
   ├─► Captures after_state.json, verifies all 4 flags = true, calculates MTTR
   ├─► Computes dynamic SHA-256 cryptographic evidence hash
   ├─► Records audit trail in Amazon DynamoDB and uploads forensic bundle to S3
   │
[4.7s] Emerald Auto-Heal & Visual Convergence
   │
   ├─► 3D Cyber-Sphere pulses cyber-emerald green (#00ff87) before returning to electric cyan
   ├─► Target Card flips back to "COMPLIANT" with all "true" values
   └─► Panels 2, 3, and 4 refresh dynamically with exact field counts (2 or 4 fields modified)
```

---

## 4. Four Mandatory Dashboard Panels

1. **Panel 1: Defined Expected Configuration ("Golden Baseline Policy") vs. Live Resource State**
   * **Expected Config Card:** Mandatory baseline defined for CF-PS-19 (`BlockPublicAcls: true`, `IgnorePublicAcls: true`, `BlockPublicPolicy: true`, `RestrictPublicBuckets: true`, tag `AutoRemediate: "true"`).
   * **Isolated Target Resource Card (`cf-ps19-target-{suffix}`):** Shows live S3 state, tags (`Environment=Sandbox`, `AutoRemediate=true`), and glowing status badge.
   * **Unrelated Control Resource Card (`cf-ps19-unscoped-{suffix}`):** Shows live S3 state, tags (`Environment=Production`, `AutoRemediate=false`), and automated sandbox reset countdown (zero manual buttons!).

2. **Panel 2: Before & After Configuration Details + Exact Changes Log (Stored in Cloud)**
   * **Left Pane (`BEFORE STATE`):** Exact JSON snapshot captured prior to remediation (`s3://cf-ps19-evidence-{suffix}/evidence/{id}/before_state.json`).
   * **Middle Pane (`RECORDED CHANGES LOG`):** Dynamic field-by-field log accurately reporting **4 FIELDS MODIFIED** or **2 FIELDS MODIFIED** depending on injected scenario (`false ➔ true`).
   * **Right Pane (`AFTER STATE`):** Verified compliant JSON snapshot queried from S3 (`s3://cf-ps19-evidence-{suffix}/evidence/{id}/after_state.json`).

3. **Panel 3: Evidence Processing & Cloud Storage Inspector**
   * Displays the **SHA-256 Evidence Integrity Hash** computed in the cloud.
   * Displays measured **MTTR (Mean Time to Remediate in ms)**.
   * Includes an interactive **"View Raw S3 Cloud Evidence File"** modal that fetches live JSON objects directly from the `cf-ps19-evidence-{suffix}` S3 bucket.

4. **Panel 4: Complete Event History & Audit Action Log (From Amazon DynamoDB)**
   * Chronological audit trail stored in DynamoDB (`cf-ps19-audit-logs`):
     * `Event ID`, `UTC Timestamp`, `Target Resource`, `Trigger Event` (`PutBucketPublicAccessBlock`), `Verdict / Status` (`REMEDIATED` vs `SKIPPED_OUT_OF_SCOPE`), `Changes Applied`, `MTTR (ms)`.
     * Interactive **"Load Diff"** button to load any past event's Before/After state into Panel 2.

---

## 5. Architecture Overview (5 Native AWS Services)

```
                           +----------------------------------------+
                           |   SecOps Cloud Operator / Evaluator    |
                           +-------------------+--------------------+
                                               |
                                     (HTTPS via Function URL)
                                               v
+-------------------------------------------------------------------------------------------------+
|                               AWS Lambda (Dashboard & SecOps Host)                             |
|  - GET /                 -> Serves CLOUD GUARD 3D Web Platform (Single Binary HTML5/WebGL)     |
|  - GET /api/status       -> Live AWS Resource Telemetry & DynamoDB Audit Logs                  |
|  - POST /api/inject      -> Chaos Drift Injection on Target Sandbox Bucket (phase: break/remed) |
|  - POST /api/test-scope  -> Tests Unscoped Control Bucket Guardrail Protection                 |
|  - GET /api/evidence-file-> Fetches Raw S3 Evidence Objects from Bucket                        |
|  - GET /api/evidence     -> Cryptographic Forensic Bundle Download                             |
+----------------------+--------------------------------------------------+-----------------------+
                       |                                                  |
           (Direct Cloud Event)                               (Direct Cloud Event)
                       v                                                  v
+------------------------------------+                  +-----------------------------------------+
|     Isolated Target Bucket         |                  |        Unrelated Control Bucket         |
|  - cf-ps19-target-{suffix}         |                  |  - cf-ps19-unscoped-{suffix}            |
|  - Tags: Environment=Sandbox       |                  |  - Tags: Environment=Production         |
|          AutoRemediate=true        |                  |          AutoRemediate=false            |
+------------------+-----------------+                  +--------------------+--------------------+
                   |                                                         |
                   | (S3 Drift Event)                                        | (S3 Drift Event)
                   v                                                         v
+-------------------------------------------------------------------------------------------------+
|                                  Amazon EventBridge Bus                                         |
|  - Rule: cf-ps19-s3-drift-rule                                                                  |
|  - Dual Filter: CloudTrail (aws.s3) AND Instant Detector (cf.ps19.detector)                     |
+--------------------------------------------------+----------------------------------------------+
                                                   |
                                            (Invokes Remediator)
                                                   v
+-------------------------------------------------------------------------------------------------+
|                             AWS Lambda (Auto-Remediation Engine)                                |
|  - Triple-Layer Guardrail:                                                                      |
|      1. Environment Variable Match (bucketName == ALLOWED_TARGET_BUCKET)                         |
|      2. S3 Tag Verification (AutoRemediate == 'true')                                           |
|      3. Scoped IAM Policy (auto-discovers LabRole in Sandbox accounts)                          |
|  - Infinite Loop Prevention: Halts if all 4 PublicAccessBlock flags match EXPECTED_CONFIG       |
|  - Forensic Evidence Capture: Retains before_state.json prior to remediation                   |
|  - Enforcement: Calls s3.put_public_access_block(BlockPublicAcls=True, ...)                     |
|  - Verification: Confirms compliant state, calculates MTTR in milliseconds                      |
|  - Dynamic Diff: Only logs keys that actually changed between before and after states           |
|  - Archival: Saves after_state.json and forensic_bundle.json with SHA-256 integrity hash       |
|  - Audit Log: Stores complete record to DynamoDB table cf-ps19-audit-logs                      |
+----------------------+--------------------------------------------------+-----------------------+
                       |                                                  |
                       v                                                  v
+------------------------------------+                  +-----------------------------------------+
|     Forensic Evidence Bucket       |                  |            Amazon DynamoDB              |
|  - cf-ps19-evidence-{suffix}       |                  |  - Table: cf-ps19-audit-logs            |
|  - /evidence/{id}/before_state.json|                  |  - Partition Key: eventId (String)      |
|  - /evidence/{id}/after_state.json |                  |  - Billing: PAY_PER_REQUEST ($0 idle)   |
|  - /evidence/{id}/forensic_bundle  |                  |  - Records: MTTR, Diffs, Verification   |
+------------------------------------+                  +-----------------------------------------+
```

---

## 6. Multi-Tenant Scope Guardrails

Automated cloud remediation engines must guarantee they cannot inadvertently alter production workloads:
1. **Scope Environment Lock:** Remediator Lambda enforces `bucket_name == os.environ["ALLOWED_TARGET_BUCKET"]`.
2. **Live S3 Tag Verification:** Dynamically inspects bucket tags to verify `AutoRemediate == 'true'`.
3. **Guardrail Refusal Verdict (`SKIPPED_OUT_OF_SCOPE`):** When `cf-ps19-unscoped-*` is tested, the engine refuses action, leaves the bucket untouched (`0 fields (Untouched)`), saves `out_of_scope_proof.json` to S3, and logs `SKIPPED_OUT_OF_SCOPE` to DynamoDB.
4. **Hands-Free Control Reset:** The test harness provides an automated 8-second visual countdown verifying refusal, then resets the sandbox control state automatically with **zero manual button clicks**.

---

## 7. AWS Builder / Learner Account Compatibility

AWS Learner Labs and Sandbox accounts often enforce strict IAM boundaries:
* `iam:CreateRole` and `iam:AttachRolePolicy` typically fail with `AccessDeniedException`.
* S3 bucket creation in `us-east-1` fails if `LocationConstraint` is specified.
* Complex container builds cannot run.

**How `deploy_aws.py` solves this:**
* **Dynamic Role Resolution:** Attempts to create a dedicated role; on `AccessDenied`, it automatically detects and binds to the pre-existing `LabRole` or `WSParticipantRole`.
* **Pure In-Memory Packaging:** Both Lambda functions are packaged directly in memory using Python's standard `zipfile` module. No external tools or Docker needed.
* **Pay-Per-Request Serverless:** DynamoDB uses on-demand billing, and Lambda uses microsecond execution billing. Total evaluation cost is **< $0.05** of the $100 credit budget.

---

## 8. Quickstart & Deployment

### 1. Configure Credentials
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Populate your credentials in `.env`:
```env
AWS_ACCESS_KEY_ID=ASIAXXXXXXXXXXXXXXXX
AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
AWS_SESSION_TOKEN=IQoJb3JpZ2luX2VjE...[REQUIRED_FOR_SANDBOX]...
AWS_DEFAULT_REGION=us-east-1
```

### 2. Run Offline Local Verification Tests (No AWS Credentials Needed)
```bash
python test_local_sim.py
```
Validates all 4 breach scenarios, dynamic diffing (2 vs 4 vs 0 fields), SHA-256 evidence hashing, and loop prevention offline.

### 3. Deploy Everything in 1 Command
```bash
python deploy_aws.py --deploy
```

The script will:
1. Authenticate with STS and generate a deterministic account suffix.
2. Create 3 S3 buckets (`target`, `unscoped`, `evidence`) in `us-east-1`.
3. Create the DynamoDB table `cf-ps19-audit-logs`.
4. Resolve IAM roles (with automated sandbox `LabRole` fallback).
5. Deploy `cf-ps19-remediator` and `cf-ps19-dashboard-api`.
6. Configure the public **Lambda Function URL** with CORS.
7. Configure the EventBridge drift rule.
8. Run a self-verification smoke test.
9. Output the live web URL:
   ```
   🚀 LIVE CLOUD GUARD WEB CONSOLE: https://xxxxxxxxxxxx.lambda-url.us-east-1.on.aws/
   ```

---

## 9. Evaluator Walkthrough Guide

Open the live URL in Google Chrome, Microsoft Edge, or Safari:

### Test 1: Full Public Access Breach (Scenario 1)
1. Click **`⚡ Introduce Test Violation ▾`** and select **`Violation 1: Full Public Access Exposure`**.
2. **Phase 1 (Red Alert - 0.0s to 3.5s):**
   * Target bucket's 4 public access flags are disabled live on AWS.
   * 3D Cyber-Sphere accelerates to turbulent speed and turns **fiery crimson red (`#ff0844`)**.
   * Target Card glows red with flashing badge `🚨 VIOLATION DETECTED (EXPOSED)`.
   * Floating SecOps Telemetry Pipeline steps through stages 1 ➔ 2 ➔ 3 ➔ 4.
3. **Phase 2 (Auto-Heal Green - at 3.5s):**
   * EventBridge triggers `cf-ps19-remediator`.
   * Remediator enforces baseline, computes diff, hashes SHA-256 evidence, and writes to DynamoDB.
   * 3D Cyber-Sphere pulses **cyber-emerald (`#00ff87`)** before returning to electric cyan.
   * Target Card returns to `COMPLIANT`.
   * Panel 2 displays **`4 FIELDS MODIFIED`** with transitions `false ➔ true`.

### Test 2: Partial Drift - Policy Only (Scenario 2 - Dynamic Forensic Diffing)
1. Click **`⚡ Introduce Test Violation ▾`** and select **`Violation 2: Public Bucket Policy Drift`**.
2. Observe the 3.5s Red Alert phase.
3. Upon auto-healing:
   * Panel 2 dynamically displays **`2 FIELDS MODIFIED`** (`BlockPublicPolicy` and `RestrictPublicBuckets`).
   * Proves CLOUD GUARD does not hardcode diffs, but dynamically computes field-level deltas!

### Test 3: Partial Drift - ACL Only (Scenario 3 - Dynamic Forensic Diffing)
1. Click **`⚡ Introduce Test Violation ▾`** and select **`Violation 3: Public ACL Injection`**.
2. Upon auto-healing, Panel 2 records only the 2 ACL fields changing (`false ➔ true`) and classifies drift as `S3_ACL_PUBLIC_ACCESS_DRIFT`.

### Test 4: Out-of-Scope Production Guardrail (Scenario 4 - Zero Manual Buttons)
1. Click **`⚡ Introduce Test Violation ▾`** and select **`Violation 4: Unscoped Production Resource Drift`** (or click `🛡️ Test Unscoped Resource`).
2. **What happens:**
   * Control bucket `cf-ps19-unscoped-...` is modified.
   * `cf-ps19-remediator` inspects tags (`AutoRemediate=false`), evaluates scope lock, and immediately refuses intervention (`SKIPPED_OUT_OF_SCOPE`).
   * Saves `out_of_scope_proof.json` with SHA-256 hash to S3.
   * The Unrelated Control Resource card flags AMBER/RED (`🚨 OUT-OF-SCOPE DRIFT — IGNORED BY REMEDIATOR`).
   * An 8-second countdown proves to judges that the remediator refused to touch the production resource.
   * At 0s, the sandbox test harness automatically resets the control bucket back to compliant state with **ZERO manual button clicks**.

### Test 5: Raw S3 Cloud Evidence Inspector & Bundle Export
1. Click **`🔎 View Raw S3 Cloud Evidence File`** in Panel 3.
   * Inspect the live JSON object fetched directly from the S3 evidence bucket, including the SHA-256 evidence integrity hash and full event payload.
2. Click **`⬇ Export Cloud Evidence Bundle`**.
   * A cryptographic JSON report (`cloud-guard-forensic-bundle.json`) downloads directly, containing all audit records and before/after states.

---

## 10. Teardown & Zero-Dollar Assurance

When evaluation is complete, run:
```bash
python deploy_aws.py --teardown
```

This command:
* Empties all object versions and delete markers from all 3 S3 buckets and deletes the buckets.
* Deletes the DynamoDB audit table.
* Deletes both Lambda functions and their Function URLs.
* Deletes the EventBridge drift rules.
* Generates `TEARDOWN_REPORT.md` confirming $0 continuing charges and 100% credit safety.

---

## File Manifest

| File | Purpose |
| :--- | :--- |
| `lambda_remediator.py` | EventBridge-triggered auto-remediation engine with Golden Baseline policy, dynamic field-by-field Changes Log computation, triple guardrails, and SHA-256 evidence integrity hashing. |
| `lambda_dashboard_api.py` | Full-stack serverless host serving the CLOUD GUARD 3D Cyber-Sphere UI with all 4 panels + SecOps REST API, 4-scenario interactive launcher, and S3 evidence inspector. |
| `deploy_aws.py` | Automated deployer and teardown manager with LabRole fallback for AWS Builder accounts. |
| `test_local_sim.py` | Comprehensive offline verification test suite validating all 4 scenarios, dynamic diffing, SHA-256 hashing, and loop prevention. |
| `index.html` | Standalone client copy for local offline preview and visual testing. |
| `.env.example` | Template for AWS Learner / Builder Sandbox credentials. |
| `requirements.txt` | Minimal dependencies (`boto3`, `python-dotenv`) for deployment. |
| `README.md` | Comprehensive architectural documentation and hackathon submission dossier. |

---
*Built with precision for the AWS Builder / Learner Sandbox Account Hackathon Evaluation.*
