#!/usr/bin/env bash
# Deploy Supplier Risk Radar to AWS: S3 bucket + Lambda + Athena tables.
#
# Prerequisites:
#   - AWS CLI v2 configured with your IAM user's access keys (`aws configure`)
#   - An IAM role for the Lambda (see aws/README.md "IAM role"); pass its ARN below
#
# Usage:
#   DATA_BUCKET=my-supplier-risk-<youracct> ROLE_ARN=arn:aws:iam::<acct>:role/supplier-risk-lambda \
#     bash aws/deploy.sh
set -euo pipefail

: "${DATA_BUCKET:?set DATA_BUCKET to a globally-unique bucket name}"
: "${ROLE_ARN:?set ROLE_ARN to your Lambda execution role ARN (see aws/README.md)}"
REGION="${REGION:-us-east-1}"
FUNCTION_NAME="${FUNCTION_NAME:-supplier-risk-radar}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo ">> Region $REGION  Bucket $DATA_BUCKET  Function $FUNCTION_NAME"

# 1. Bucket (ignore error if it already exists / you own it)
if ! aws s3api head-bucket --bucket "$DATA_BUCKET" 2>/dev/null; then
  if [ "$REGION" = "us-east-1" ]; then
    aws s3api create-bucket --bucket "$DATA_BUCKET" --region "$REGION"
  else
    aws s3api create-bucket --bucket "$DATA_BUCKET" --region "$REGION" \
      --create-bucket-configuration LocationConstraint="$REGION"
  fi
fi

# 2. Inputs
aws s3 cp "$ROOT/data/suppliers.csv"         "s3://$DATA_BUCKET/inputs/suppliers.csv"
aws s3 cp "$ROOT/data/supplier_products.csv" "s3://$DATA_BUCKET/inputs/supplier_products.csv"

# 3. Build the Lambda package (Linux x86_64 wheels so duckdb's binary matches the runtime)
BUILD="$(mktemp -d)"
python3 -m pip install --quiet \
  --platform manylinux2014_x86_64 --implementation cp --python-version 3.12 \
  --only-binary=:all: --target "$BUILD" duckdb
cp -r "$ROOT/supplier_radar" "$BUILD/"
cp "$ROOT/aws/lambda_handler.py" "$BUILD/"
( cd "$BUILD" && zip -qr9 "$BUILD/function.zip" . -x '*.pyc' )
aws s3 cp "$BUILD/function.zip" "s3://$DATA_BUCKET/build/function.zip"

# 4. Create or update the function
if aws lambda get-function --function-name "$FUNCTION_NAME" --region "$REGION" >/dev/null 2>&1; then
  aws lambda update-function-code --function-name "$FUNCTION_NAME" --region "$REGION" \
    --s3-bucket "$DATA_BUCKET" --s3-key build/function.zip >/dev/null
else
  aws lambda create-function --function-name "$FUNCTION_NAME" --region "$REGION" \
    --runtime python3.12 --architectures x86_64 --handler lambda_handler.handler \
    --role "$ROLE_ARN" --timeout 120 --memory-size 512 \
    --code "S3Bucket=$DATA_BUCKET,S3Key=build/function.zip" \
    --environment "Variables={DATA_BUCKET=$DATA_BUCKET,STRICT=false}" >/dev/null
fi
aws lambda wait function-updated --function-name "$FUNCTION_NAME" --region "$REGION"

# 5. Athena tables (results go to a dedicated prefix)
SQL="$(sed "s/{{DATA_BUCKET}}/$DATA_BUCKET/g" "$ROOT/aws/athena/create_tables.sql")"
aws athena start-query-execution --region "$REGION" \
  --query-string "$SQL" \
  --result-configuration "OutputLocation=s3://$DATA_BUCKET/athena-results/" >/dev/null || \
  echo "   (Athena DDL submit skipped/failed - you can paste aws/athena/create_tables.sql into the Athena console)"

rm -rf "$BUILD"
echo ">> Done. Invoke it with:"
echo "   aws lambda invoke --function-name $FUNCTION_NAME --region $REGION /dev/stdout"
echo ">> Then query in Athena (see aws/athena/example_queries.sql) or read s3://$DATA_BUCKET/reports/report.html"
