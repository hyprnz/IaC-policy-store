package terraform.pipeline_control

import rego.v1
import input as tf_plan

protected_resources := [
	"aws_s3_bucket",
	"aws_dynamodb_table",
	"aws_db_instance"
]

denied_actions := [
	"delete"
]

deny contains reason if {
	r := tf_plan.resource_changes[_]
	type := r.type
	protected_resources[_] == type
	action := r.change.actions[_]
	denied_actions[_] == action

	reason := sprintf("%s :: '%s' action is not allowed for resource type '%s'", [r.address, action, type])
}