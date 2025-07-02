package terraform

import rego.v1

check_match(resource) if {
    r := input.tfplan.resource_changes[_]
    r.type =="aws_s3_bucket_lifecycle_configuration"
    r.change.after.bucket == resource.change.after.bucket
}

check_id(resource) if {
    lc := input.tfplan.resource_changes[_]
    lc.type =="aws_s3_bucket_lifecycle_configuration"
    not lc.change.after.bucket
}

check_lifecycle(resource) if {
    r := input.tfplan.resource_changes[_]
    r.type =="aws_s3_bucket_lifecycle_configuration"
    r.change.after.bucket == resource.change.after.bucket
    rules := r.change.after.rule
    storage_classes := { sc |
        rule := rules[_]
        transition := rule.transition[_]
        sc := transition.storage_class
    }
    "INTELLIGENT_TIERING" in storage_classes
}

deny contains reason if {
    resource := input.tfplan.resource_changes[_]
    resource.type = "aws_s3_bucket"
    "create" in resource.change.actions
    not check_id(resource) # if there is a lifecyle with no bucket reference set this to false to skip rule
    not check_match(resource) 
    reason := sprintf("No matching lifecycle configuration for newly created bucket: %s", [resource.address])
}

deny contains reason if {
    resource := input.tfplan.resource_changes[_]
    resource.type =="aws_s3_bucket_lifecycle_configuration"
    "create" in resource.change.actions
    not resource.change.after.bucket
    reason := sprintf("Terraform for lifecycle configuration %s is referencing 'id'. Should reference the 'bucket' attribute", [resource.address])
}

deny contains reason if {
    resource := input.tfplan.resource_changes[_]
    resource.type = "aws_s3_bucket"
    "create" in resource.change.actions
    not check_id(resource) # if there is a lifecyle with no bucket reference set this to false to skip rule
    check_match(resource) # if there is no match then this returns false and the policy is skipped
    not check_lifecycle(resource)
    reason := sprintf("%s does not have Intelligent Tiering enabled.", [resource.address])
}
