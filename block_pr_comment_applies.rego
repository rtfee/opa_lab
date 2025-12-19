package terraform

import input.tfrun as tfrun

# Deny runs when pr commment runs are on prod
deny[msg] {
    tfrun.is_destroy == false
    tfrun.is_dry == false
    source := tfrun.source
    source == "comment-github"
    # Check if the workspace is production
    workspace_type := tfrun.workspace.environment_type
    workspace_type == "production"

    msg := sprintf("Comment based runs are not allowed in production workspaces")
}
