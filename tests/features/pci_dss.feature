Feature: CDE Infrastructure Security Requirements
    As a Security Auditor
    I want to ensure all Terraform deployments comply with PCI-DSS
    So that Yuno's CDE remains compliant and secure

    Scenario: Ensure all RDS instances are encrypted with KMS
        Given I have aws_db_instance defined
        Then it must contain storage_encrypted
        And its value must be true
        And it must contain kms_key_id

    Scenario: Ensure all S3 buckets block public access
        Given I have aws_s3_bucket_public_access_block defined
        Then it must contain block_public_acls
        And its value must be true
        And it must contain block_public_policy
        And its value must be true
        And it must contain ignore_public_acls
        And its value must be true
        And it must contain restrict_public_buckets
        And its value must be true

    Scenario: Ensure IAM policies do not contain Action wildcard
        Given I have aws_iam_policy defined
        Then it must not contain policy.Statement.Action
        With value set to *

    Scenario: Ensure ALB enforces TLS 1.2+
        Given I have aws_lb_listener defined
        When it has protocol set to HTTPS
        Then it must contain ssl_policy
        And its value must match ELBSecurityPolicy-TLS13-1-2-2021-06
