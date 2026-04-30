# Keeper Records Lambda (Config + Password Fallback)

This Lambda function logs in to Keeper and lists user's vault records.

It is designed to:
- use `config.json` from Keeper first (stored in AWS Secrets Manager as `keeper-secret-1`)
- automatically fall back to a password secret (`keeper-secret-2`) when config-based login is not valid for that run

This makes the Lambda non-interactive and suitable for AWS execution.

## What is in GitHub, and what you must build

This repository (and the `keeper-sdk-python` project on GitHub) includes **source only**: `lambda_function.py`, `requirements.txt`, and this guide. **Third-party dependencies are not checked in**—on purpose, so the repo stays small and maintainable (a `.gitignore` in this folder is meant to keep the `pip install -t` output from being re-committed). **The Lambda will not work** until you install those dependencies into the same directory as the handler, then **zip** that full tree, then **upload** the zip to AWS Lambda. See [Build the deployment package](#build-the-deployment-package) below for the exact commands.

## What This Function Does

1. Reads Keeper config from AWS Secrets Manager (`keeper-secret-1`)
2. Attempts non-interactive login using persisted config/session data
3. If Keeper requests password (`LoginStepPassword`), reads password from `keeper-secret-2`
4. Completes login, syncs the vault, and returns records

## Prerequisites

- AWS account with permissions to create and run Lambda + Secrets Manager secrets
- Keeper account credentials
- A machine with Python **3.11+** and `pip` (or a CI image) to run `pip install` for the deployment package
- Local machine with Keeper SDK workflow that generates `~/.keeper/config.json`
- For the Lambda **runtime** in AWS: set **Python 3.11** to match a typical build (see the packaging section below for matching Linux vs macOS/Windows when building the zip)

## Build the deployment package

Do this **before** you upload code to Lambda. The handler file alone is not enough: Lambda needs `boto3`, `keepersdk`, and all transitive dependencies installed next to `lambda_function.py` inside the zip.

1. Open a shell and go to the directory that contains `lambda_function.py` and `requirements.txt` (this folder).

2. Install dependencies into the **same directory** (typical for Lambda function packages):

   ```text
   pip install -r requirements.txt -t .
   ```

3. If `requirements.txt` points at `../../../../keepersdk-package`, that path only works from a full clone of `keeper-sdk-python` at the expected path. If you are using a standalone copy of the example, edit `requirements.txt` and use the `keepersdk` line from [PyPI](https://pypi.org/project/keepersdk/) instead, then run the `pip` command again.

4. **Build the zip for Lambda (Linux).** The runtime is Amazon Linux; if you run `pip` on **macOS or Windows**, the wheels you get may not run on Lambda. For production packages, use a **Linux** environment with **Python 3.11** (for example a container image or Amazon Linux 2) and run the same `pip install` there before zipping.

5. From *inside* this directory (so paths at the root of the zip are correct for Lambda), create a zip of **everything** needed, including the installed site-packages. For example:

   ```text
   zip -r ../list_records_lambda_function.zip .
   ```

   (Adjust the name or parent path as you like; the important part is that the archive contains `lambda_function.py` and the top-level import packages, e.g. `boto3/`, `keepersdk/`, and their dependencies, at the **root** of the zip.)

6. You will **upload** this zip in the Lambda console (or via CLI/API) as the function code. **Without this step, the function will fail** at import time because dependencies are not present in GitHub and are not on Lambda by default.

## Step 1: Prepare Keeper Config Locally

Login to Keeper locally with your email and password, then:

- register device
- enable persistent login
- set a long timeout (for example, 30 days)

This creates/updates your local Keeper config at:

- `~/.keeper/config.json`

## Step 2: Create Secret `keeper-secret-1` (Config Secret)

In AWS Secrets Manager, create a secret named:

- `keeper-secret-1`

Paste the contents of `~/.keeper/config.json` as plaintext JSON.

### Optional safety note (base64)

If you are not comfortable pasting raw JSON, you can base64-encode it first and store that value.  
In that case, `lambda_function.py` can be updated to decode the base64 payload before parsing JSON.

> Current implementation expects JSON config content as the secret payload.

## Step 3: Create Secret `keeper-secret-2` (Password Fallback)

Create another secret named:

- `keeper-secret-2`

Store password as JSON, for example:

```json
{"password":"Pass@123"}
```

Why this exists:

- Normally, Lambda will authenticate from `keeper-secret-1` config.
- If config/session data is stale or invalid for a run, Keeper may require password verification.
- Lambda is non-interactive, so it uses `keeper-secret-2` automatically as fallback.

## Step 4: Configure Lambda Function

Create/update your Lambda with `lambda_function.py`.

Use these settings and paths in AWS Lambda console:

- **Memory**: Go to `Configuration` -> `General configuration` -> `Edit`, set to `512 MB`.
- **Timeout**: In `Configuration` -> `General configuration` -> `Edit`, set at least `15-30 seconds` (30 seconds recommended).
- **Runtime**: Under code section, open `Runtime settings` (Code properties) and set to `Python 3.11`.

### Lambda Execution Role Permissions

Make sure the Lambda execution role has at least:

- `secretsmanager:GetSecretValue`
- `secretsmanager:DescribeSecret` (recommended)
- `logs:CreateLogGroup`
- `logs:CreateLogStream`
- `logs:PutLogEvents`

If secrets use a customer-managed KMS key, also allow:

- `kms:Decrypt` for that key

Scope secret access to:

- `keeper-secret-1`
- `keeper-secret-2`

## Step 5: Upload Deployment Package

In Lambda code source:

1. Click **Upload from**
2. Select **.zip file**
3. Upload the **zip you built** in [Build the deployment package](#build-the-deployment-package) (for example `list_records_lambda_function.zip`). Do not expect a pre-built zip to be present in the GitHub tree; you must build it locally or in CI.

That package must include dependencies installed with `pip install -r requirements.txt -t .`, so that components such as `boto3` and `keepersdk` are importable in Lambda.

## Step 6: Set Environment Variables (Optional/Recommended)

The function supports these environment variables:

- `KEEPER_SECRET_ID` (default: `keeper-secret-1`)
- `KEEPER_PASSWORD_SECRET_ID` (default: `keeper-secret-2`)
- `AWS_REGION` or `KEEPER_AWS_REGION`
- `KEEPER_USERNAME` (optional fallback if config lacks username)
- `KEEPER_SERVER` (optional fallback if config lacks server)

If you keep the default secret names, you can skip the first two.

## Step 7: Test the Function

1. Create a default test event (any name is fine)
2. Click the blue **Test** button (under Deploy)

Expected result:

- `statusCode: 200`
- response body with `ok: true`
- `record_count` and `records` list returned

If fallback is used, logs include a message similar to:

- `Config-based resume login is not valid for this run; falling back to master password from secret 'keeper-secret-2'.`

## Troubleshooting

- **`Missing username in config secret`**
  - Ensure `last_login` exists in `keeper-secret-1`, or set `KEEPER_USERNAME`.

- **Password fallback verification fails**
  - Validate `keeper-secret-2` format and correct password value.

- **Secrets Manager access errors**
  - Check Lambda role IAM permissions and KMS decrypt permissions.

- **Timeout or slow execution**
  - Increase lambda timeout to 30 seconds or more and retry.

- **Non-interactive step errors (2FA/SSO/device approval loops)**
  - Re-run local Keeper login, confirm persistent login/device registration, and refresh `keeper-secret-1` from latest `~/.keeper/config.json`.

## Security Recommendations

- Do not print secrets or passwords in logs.
- Restrict IAM permissions to only required secret ARNs.
- Rotate password in `keeper-secret-2` as needed.
- Prefer AWS-managed encryption/KMS and audit secret access with CloudTrail.
