package terraform

import input.tfplan as tfplan

# Denied Terraform resources
denied_resources = [
  "aws_iam_role",
  "aws_iam_policy",
  "aws_iam_user",
  "aws_iam_group",
  "aws_iam_role_policy",
  "aws_iam_role_policy_attachment",
  "aws_iam_user_policy",
  "aws_iam_user_policy_attachment",
  "aws_iam_group_policy",
  "aws_iam_group_policy_attachment",
  "aws_iam_instance_profile",
  "aws_iam_service_linked_role",
  "aws_iam_saml_provider",
  "aws_iam_openid_connect_provider",
  "aws_iam_server_certificate",
  "aws_iam_account_alias",
  "aws_iam_account_password_policy",
  "aws_iam_access_key"
]

array_contains(arr, elem) {
  arr[_] = elem
}

deny[reason] {
    resource := tfplan.resource_changes[_]
    action := resource.change.actions[count(resource.change.actions) - 1]
    array_contains(["create", "update"], action)  # allow destroy action
    array_contains(denied_resources, resource.type)
    reason := sprintf(
        "%s: resource type %q is not allowed",
        [resource.address, resource.type]
    )
}
