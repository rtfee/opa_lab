package terraform

import input.tfrun as tfrun

allowed_cli_users = ["d.johnson", "j.smith"]

array_contains(arr, elem) {
  arr[_] = elem
}

get_basename(path) = basename if {
    arr := split(path, "/")
    basename:= arr[count(arr)-1]
}

deny["User is not allowed to perform runs from Terraform CLI"] if {
    "cli" == tfrun.source
    not array_contains(allowed_cli_users, tfrun.created_by.username)
}
