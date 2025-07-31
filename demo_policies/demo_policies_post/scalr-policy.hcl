version = "v1"

policy "allowed_regions" {
    enabled = true
    enforcement_level = "advisory"
}

policy "module_source" {
    enabled = true
    enforcement_level = "advisory"
}

policy "private_buckets" {
    enabled = true
    enforcement_level = "advisory"
}

policy "tagging" {
    enabled = true
    enforcement_level = "advisory"
}

policy "provider_blacklist" {
    enabled = true
    enforcement_level = "advisory"
}
