version = "v1"

policy "deny_iam" {
    enabled = false
    enforcement_level = "soft-mandatory"
}

policy "s3_advanced" {
    enabled = true
    enforcement_level = "soft-mandatory"
}
