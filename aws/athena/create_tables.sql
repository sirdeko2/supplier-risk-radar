-- Athena external tables over the Parquet the Lambda writes to S3.
-- Replace {{DATA_BUCKET}} with your bucket name before running (deploy.sh does this).
-- Each table points at its own prefix under warehouse/, where the Lambda uploads
-- <table>.parquet. Run these once in the Athena query editor (or via deploy.sh).

CREATE DATABASE IF NOT EXISTS supplier_risk;

CREATE EXTERNAL TABLE IF NOT EXISTS supplier_risk.dim_supplier (
    supplier_id     STRING,
    supplier_name   STRING,
    tier            STRING,
    category        STRING,
    data_access     STRING,
    internet_facing BOOLEAN,
    criticality     INT
)
STORED AS PARQUET
LOCATION 's3://{{DATA_BUCKET}}/warehouse/dim_supplier/';

CREATE EXTERNAL TABLE IF NOT EXISTS supplier_risk.dim_vulnerability (
    cve_id      STRING,
    vendor      STRING,
    product     STRING,
    vuln_name   STRING,
    date_added  DATE,
    due_date    DATE,
    cwes        STRING,
    description STRING,
    ransomware  BOOLEAN,
    overdue     BOOLEAN,
    vuln_weight INT
)
STORED AS PARQUET
LOCATION 's3://{{DATA_BUCKET}}/warehouse/dim_vulnerability/';

CREATE EXTERNAL TABLE IF NOT EXISTS supplier_risk.bridge_supplier_product (
    supplier_id STRING,
    vendor      STRING,
    product     STRING
)
STORED AS PARQUET
LOCATION 's3://{{DATA_BUCKET}}/warehouse/bridge_supplier_product/';

CREATE EXTERNAL TABLE IF NOT EXISTS supplier_risk.fact_exposure (
    supplier_id      STRING,
    supplier_name    STRING,
    tier             STRING,
    category         STRING,
    data_access      STRING,
    internet_facing  BOOLEAN,
    criticality      INT,
    cve_id           STRING,
    vendor           STRING,
    kev_product      STRING,
    supplier_product STRING,
    vuln_name        STRING,
    ransomware       BOOLEAN,
    overdue          BOOLEAN,
    due_date         DATE,
    cwes             STRING,
    description      STRING,
    vuln_weight      INT,
    match_confidence STRING,
    risk_score       INT,
    risk_band        STRING
)
STORED AS PARQUET
LOCATION 's3://{{DATA_BUCKET}}/warehouse/fact_exposure/';
