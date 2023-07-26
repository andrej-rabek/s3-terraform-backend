#!/usr/bin/env python3
"""
Module Docstring
"""

__author__ = "Andrej Rabek"
__version__ = "0.0.1"
__license__ = "MIT"

import sys
import argparse
import boto3
import json
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def initialize_vars(args):
    global s3_bucket_name, dynamodb_table_name, kms_key_policy

    s3_bucket_name = (
        args.bucket_name
        if args.bucket_name is not None
        else f"tf-backend-{args.account_id}"
    )
    dynamodb_table_name = (
        args.table_name if args.table_name is not None else f"tf-lock-{args.account_id}"
    )
    kms_key_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Allow administration of the key",
                "Effect": "Allow",
                "Principal": {
                    "AWS": [
                        f"arn:aws:iam::{args.account_id}:root",
                        args.terraform_user_arn,
                    ]
                },
                "Action": [
                    "kms:Create*",
                    "kms:Describe*",
                    "kms:Enable*",
                    "kms:List*",
                    "kms:Put*",
                    "kms:Update*",
                    "kms:Revoke*",
                    "kms:Disable*",
                    "kms:Get*",
                    "kms:Delete*",
                    "kms:ScheduleKeyDeletion",
                    "kms:CancelKeyDeletion",
                ],
                "Resource": "*",
            },
        ],
    }


def create_s3_bucket(bucket_name, kms_key_id=None):
    try:
        s3 = boto3.client("s3", region_name=args.region)
        bucket_config = {"Bucket": bucket_name}

        # Add location constrain configuration if a region is not 'us-east-1'
        if args.region != "us-east-1":
            bucket_config["CreateBucketConfiguration"] = {
                "LocationConstraint": args.region
            }

        s3.create_bucket(**bucket_config)
        s3.put_bucket_versioning(
            Bucket=bucket_name, VersioningConfiguration={"Status": "Enabled"}
        )

        # Add encryption configuration if a KMS key is provided
        if kms_key_id:
            s3.put_bucket_encryption(
                Bucket=bucket_name,
                ServerSideEncryptionConfiguration={
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "aws:kms",
                                "KMSMasterKeyID": kms_key_id,
                            }
                        }
                    ]
                },
            )

        logger.info(f"S3 bucket '{bucket_name}' created successfully.")
    except Exception as e:
        logger.error(f"Error creating S3 bucket: {e}")
        sys.exit()


def create_dynamodb_table(table_name, kms_key_id=None):
    try:
        dynamodb = boto3.client("dynamodb", region_name=args.region)

        # Add encryption configuration if a KMS key is provided
        if kms_key_id:
            table_config = {
                "TableName": table_name,
                "AttributeDefinitions": [
                    {"AttributeName": "LockID", "AttributeType": "S"},
                ],
                "KeySchema": [
                    {"AttributeName": "LockID", "KeyType": "HASH"},
                ],
                "ProvisionedThroughput": {
                    "ReadCapacityUnits": 5,
                    "WriteCapacityUnits": 5,
                },
                "SSESpecification": {
                    "Enabled": True,
                    "SSEType": "KMS",
                    "KMSMasterKeyId": kms_key_id,
                },
            }
        else:
            table_config = {
                "TableName": table_name,
                "AttributeDefinitions": [
                    {"AttributeName": "LockID", "AttributeType": "S"},
                ],
                "KeySchema": [
                    {"AttributeName": "LockID", "KeyType": "HASH"},
                ],
                "ProvisionedThroughput": {
                    "ReadCapacityUnits": 5,
                    "WriteCapacityUnits": 5,
                },
            }

        dynamodb.create_table(**table_config)
        logger.info(f"DynamoDB table '{table_name}' created successfully.")
    except Exception as e:
        logger.error(f"Error creating DynamoDB table: {e}")
        sys.exit()


def create_kms_key(policy):
    try:
        kms_key_description = "Terraform State Encryption Key"
        kms = boto3.client("kms", region_name=args.region)
        response = kms.create_key(Description=kms_key_description)
        key_id = response["KeyMetadata"]["KeyId"]
        key_arn = response["KeyMetadata"]["Arn"]
        kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=policy)
        logger.info(f"KMS key '{key_id}' created successfully.")
        return key_id, key_arn
    except Exception as e:
        logger.error(f"Error creating KMS key: {e}")
        sys.exit()

def generate_backend_block(bucket, region, dynamodb_table, kms_key_arn):
    backend_block = '''
terraform {
  backend "s3" {
    bucket         = "%s"
    key            = "tfstate"
    region         = "%s"
    dynamodb_table = "%s"
    encrypt        = true
    kms_key_id     = "%s"
  }
}
''' % (bucket, region, dynamodb_table, kms_key_arn)
    return backend_block


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Create AWS resources for Terraform backend."
    )
    parser.add_argument(
        "-b",
        "--bucket-name",
        required=False,
        help="The name of the S3 bucket for Terraform state.",
    )
    parser.add_argument(
        "-t",
        "--table-name",
        required=False,
        help="The name of the DynamoDB table for Terraform state locking.",
    )
    parser.add_argument("-a", "--account-id", required=True, help="The AWS account ID.")
    parser.add_argument(
        "-u",
        "--terraform-user-arn",
        required=True,
        help="The ARN of IAM user used for Terraform.",
    )
    parser.add_argument(
        "-r",
        "--region",
        default="us-east-1",
        help="The AWS region where the resources will be created. Default: us-east-1",
    )
    args = parser.parse_args()
    initialize_vars(args)

    # Parse the JSON policy for the KMS key
    kms_key_policy = json.dumps(kms_key_policy)

    # Create KMS key
    kms_key_id, kms_key_arn = create_kms_key(kms_key_policy)

    # Create S3 bucket with versioning enabled
    create_s3_bucket(s3_bucket_name)

    # Create DynamoDB table
    create_dynamodb_table(dynamodb_table_name)

    logger.info("Generating S3 backend Terraform block:")

    print(generate_backend_block(s3_bucket_name, args.region, dynamodb_table_name, kms_key_arn))

    logger.info("AWS resources creation completed.")
