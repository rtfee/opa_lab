version = "v1"

policy "deny_pr" {
    enabled = true
    enforcement_level = "advisory"
}

policy "limit_run_source" {
    enabled = true
    enforcement_level = "advisory"
}

policy "prevent_apply" {
    enabled = true
    enforcement_level = "advisory"
}

policy "prevent_destroy" {
    enabled = true
    enforcement_level = "advisory"
}
