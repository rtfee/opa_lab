package terraform

import rego.v1

deny[reason] if {
  resource := input.tfplan.resource_changes[_]
  action := resource.change.actions[count(resource.change.actions) - 1]

  resource.type == "null_resource"
  action == "delete"

  reason := sprintf(
   "Confirm the deletion of the null_resource %q",
   [resource.address],
  )
}
