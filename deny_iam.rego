# Denies changes to AWS IAM

package terraform

import input.tfplan as tfplan

# Function to check if a string starts with a prefix
startswith(str, prefix) {
  substr(str, 0, count(prefix)) == prefix
}

# Helper function to check if array contains element
array_contains(arr, elem) {
  arr[_] = elem
}

deny[reason] {
  resource := tfplan.resource_changes[_]
  action := resource.change.actions[count(resource.change.actions) - 1]
  array_contains(["create", "update"], action)  # allow destroy action
  startswith(resource.type, "aws_s3")
  
  reason := sprintf(
    "%s: IAM resource type %q is not allowed",
    [resource.address, resource.type]
  )
}
