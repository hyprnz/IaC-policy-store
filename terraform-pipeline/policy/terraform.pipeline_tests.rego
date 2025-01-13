package terraform.pipeline_control

import rego.v1
import input as tf_plan

no_changes = {
  "resource_changes": []
}

dynamo_delete = {
   "resource_changes": [
      {
        "address": "address",
        "type": "aws_dynamodb_table",
        "change": {
          "actions": [
              "delete"
          ],
        },
      },
   ]
}

s3_bucket_delete = {
   "resource_changes": [
      {
        "address": "address",
        "type": "aws_s3_bucket",
        "change": {
          "actions": [
              "delete"
          ],
        },
      },
   ]
}

rds_delete = {
   "resource_changes": [
      {
        "address": "address",
        "type": "aws_db_instance",
        "change": {
          "actions": [
              "delete"
          ],
        },
      },
   ]
}

multi_resource_delete = {
   "resource_changes": [
      {
        "address": "address",
        "type": "aws_s3_bucket",
        "change": {
          "actions": [
              "delete"
          ],
        },
      },
      {
        "address": "address",
        "type": "aws_dynamodb_table",
        "change": {
          "actions": [
              "delete"
          ],
        },
      },
      {
        "address": "address",
        "type": "aws_db_instance",
        "change": {
          "actions": [
              "delete"
          ],
        },
      },
   ]
}

empty(value) if {
  count(value) == 0
}

no_violations if {
  empty(deny)
}

test_deny_with_empty if {
  no_violations with tf_plan as no_changes
}

test_deny_delete_dynamodb if {
  deny["address :: 'delete' action is not allowed for resource type 'aws_dynamodb_table'"] with tf_plan as dynamo_delete
}

test_deny_delete_s3 if {
  deny["address :: 'delete' action is not allowed for resource type 'aws_s3_bucket'"] with tf_plan as s3_bucket_delete
}

test_deny_delete_rds if {
  deny["address :: 'delete' action is not allowed for resource type 'aws_db_instance'"] with tf_plan as rds_delete
}

test_deny_multiple_resource_deletes if {
  count(deny) == 3 with tf_plan as multi_resource_delete
}