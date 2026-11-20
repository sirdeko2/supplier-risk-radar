# AWS deployment

This runs the exact same `supplier_radar` pipeline on AWS. The only new code is
`lambda_handler.py` (S3 in/out) — the model, matching and scoring are unchanged.

```
EventBridge (schedule)
      │
      ▼
   Lambda ──fetch──▶ CISA KEV (live)
      │
      ├─ reads  s3://<bucket>/inputs/*.csv          (supplier inventory)
      ├─ writes s3://<bucket>/warehouse/<table>/*.parquet   ◀── Athena reads these
      └─ writes s3://<bucket>/reports/{findings.json,report.html}
      │
      ▼
   Athena ── standard SQL over the star schema in S3
```

## Why this shape

The local tool already builds the star schema in DuckDB. Here the same tables
are written as **Parquet in S3** and exposed to **Athena** as external tables, so
the dimensional model becomes a queryable warehouse without rewriting the logic.
That is the honest version of "it ports to a warehouse."

## One-time setup

### 1. IAM user (never deploy as root)
In the AWS console, create an IAM user with programmatic access, attach a policy
that allows the deploy actions (S3, Lambda, Athena, and `iam:PassRole` for the
Lambda role), then `aws configure` with its access keys. Create the keys for the
IAM user, not the root account.

### 2. Lambda execution role
Create a role the Lambda assumes at runtime, with least privilege — read the
inputs, write the outputs, and send logs:

```bash
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
DATA_BUCKET=my-supplier-risk-$ACCOUNT

aws iam create-role --role-name supplier-risk-lambda \
  --assume-role-policy-document file://aws/iam/lambda-trust-policy.json

sed "s/REPLACE_WITH_DATA_BUCKET/$DATA_BUCKET/" aws/iam/lambda-permissions-policy.json > /tmp/perms.json
aws iam put-role-policy --role-name supplier-risk-lambda \
  --policy-name supplier-risk-lambda-perms --policy-document file:///tmp/perms.json
```

The role ARN is `arn:aws:iam::$ACCOUNT:role/supplier-risk-lambda`.

## Deploy

```bash
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
DATA_BUCKET=my-supplier-risk-$ACCOUNT \
ROLE_ARN=arn:aws:iam::$ACCOUNT:role/supplier-risk-lambda \
  bash aws/deploy.sh
```

`deploy.sh` creates the bucket, uploads the inputs, packages the function with a
Linux build of DuckDB, creates/updates the Lambda, and submits the Athena table
definitions.

## Run it

```bash
aws lambda invoke --function-name supplier-risk-radar /dev/stdout
```

Then either query in Athena (`aws/athena/example_queries.sql`) or open
`s3://<bucket>/reports/report.html`.

## Schedule it (optional)

Run every morning with EventBridge:

```bash
aws events put-rule --name supplier-risk-daily --schedule-expression "cron(0 13 * * ? *)"
aws lambda add-permission --function-name supplier-risk-radar \
  --statement-id eventbridge --action lambda:InvokeFunction \
  --principal events.amazonaws.com \
  --source-arn "$(aws events describe-rule --name supplier-risk-daily --query Arn --output text)"
aws events put-targets --rule supplier-risk-daily \
  --targets "Id=1,Arn=$(aws lambda get-function --function-name supplier-risk-radar --query Configuration.FunctionArn --output text)"
```

## Teardown

Delete the function, the EventBridge rule, the role policy/role, and empty+delete
the bucket to avoid any charges. All of it stays comfortably within typical free
usage, but clean up when you're done demoing.
