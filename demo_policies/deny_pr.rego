package terraform

import input.tfrun as tfrun

# Deny runs when there is a merge error
deny contains msg if {
# Check if merge_error exists and is not null
    merge_error := tfrun.vcs.pull_request.merge_error
    merge_error != null

    msg := sprintf("Runs are not allowed when there is a merge error: %s", [merge_error])
}
