package terraform

import future.keywords.if
import future.keywords.in
import input.tfplan as tfplan
import input.tfrun as tfrun

# Default policy result
default allow := false

# Block apply runs by checking if the run is NOT a dry run (plan-only)
# In Scalr, apply runs have is_dry = false and is_destroy = false
deny[msg] if {
    input.tfrun.is_dry == false
    input.tfrun.is_destroy == false
    msg := "Apply runs are blocked by policy. Only plan runs are allowed."
}

# Allow dry runs (plan-only runs)
allow if {
    input.tfrun.is_dry == true
}
