version = "v1"

#policy "deny_iam" {
#    enabled = false
#    enforcement_level = "soft-mandatory"
#}

#policy "s3_advanced_using_v1" {
#    enabled = true
#    enforcement_level = "soft-mandatory"
#}

policy "module_source" {
    enabled = true
    enforcement_level = "advisory"
}

policy "block_applies" {
    enabled = true
    enforcement_level = "soft-mandatory"
}
