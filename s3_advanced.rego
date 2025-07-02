package terraform

import input.tfplan as tfplan

# Helper function to check if array contains element
array_contains(arr, elem) {
  arr[_] = elem
}

# STRICT FILTER: Only get S3 buckets being created (not updated/deleted)
s3_buckets_being_created[bucket] {
  bucket := tfplan.resource_changes[_]
  bucket.type == "aws_s3_bucket"
  
  # CRITICAL: Only match resources with "create" action
  bucket.change.actions == ["create"]  # Exact match for create-only
}

# Get all S3 bucket lifecycle configurations being created
s3_lifecycle_configs_being_created[config] {
  config := tfplan.resource_changes[_]
  config.type == "aws_s3_bucket_lifecycle_configuration"
  
  # Only match lifecycle configs being created
  array_contains(config.change.actions, "create")
}

# Check if lifecycle configuration has intelligent tiering
lifecycle_has_intelligent_tiering(lifecycle_config) {
  rule := lifecycle_config.change.after.rule[_]
  transition := rule.transition[_]
  transition.storage_class == "INTELLIGENT_TIERING"
}

# Alternative structure for intelligent tiering check
lifecycle_has_intelligent_tiering(lifecycle_config) {
  rule := lifecycle_config.change.after.rule[_]
  rule.transition.storage_class == "INTELLIGENT_TIERING"
}

# Match buckets to lifecycle configs using multiple strategies
bucket_has_lifecycle_config(bucket_resource) {
  lifecycle_config := s3_lifecycle_configs_being_created[_]
  
  # Strategy 1: Direct bucket name match (when using .bucket attribute)
  bucket_name := bucket_resource.change.after.bucket
  lifecycle_config.change.after.bucket == bucket_name
}

bucket_has_lifecycle_config(bucket_resource) {
  lifecycle_config := s3_lifecycle_configs_being_created[_]
  
  # Strategy 2: Configuration reference match (when using .id attribute)
  bucket_address := bucket_resource.address
  lifecycle_address := lifecycle_config.address
  
  # Look in configuration section for references
  config_resource := tfplan.configuration.root_module.resources[_]
  config_resource.address == lifecycle_address
  reference := config_resource.expressions.bucket.references[_]
  contains(reference, bucket_address)
}

bucket_has_lifecycle_config(bucket_resource) {
  lifecycle_config := s3_lifecycle_configs_being_created[_]
  
  # Strategy 3: Module-aware matching - check if they're in the same module
  bucket_address := bucket_resource.address
  lifecycle_address := lifecycle_config.address
  
  # Extract module prefixes
  bucket_parts := split(".", bucket_address)
  lifecycle_parts := split(".", lifecycle_address)
  
  # If both have module prefixes, check if they match
  count(bucket_parts) > 2
  count(lifecycle_parts) > 2
  bucket_parts[0] == lifecycle_parts[0]  # Same module
  bucket_parts[1] == lifecycle_parts[1]  # Same module instance
}

# Find matching lifecycle config for a bucket
get_matching_lifecycle_config(bucket_resource) = lifecycle_config {
  lifecycle_config := s3_lifecycle_configs_being_created[_]
  bucket_name := bucket_resource.change.after.bucket
  lifecycle_config.change.after.bucket == bucket_name
}

get_matching_lifecycle_config(bucket_resource) = lifecycle_config {
  lifecycle_config := s3_lifecycle_configs_being_created[_]
  bucket_address := bucket_resource.address
  lifecycle_address := lifecycle_config.address
  
  # Check configuration references
  config_resource := tfplan.configuration.root_module.resources[_]
  config_resource.address == lifecycle_address
  reference := config_resource.expressions.bucket.references[_]
  contains(reference, bucket_address)
}

# DENY RULES - Only for newly created buckets

# Deny newly created buckets without lifecycle configuration
deny[reason] {
  bucket := s3_buckets_being_created[_]
  not bucket_has_lifecycle_config(bucket)
  
  reason := sprintf(
    "NEWLY CREATED S3 bucket %q must have a lifecycle configuration to enforce intelligent tiering",
    [bucket.address]
  )
}

# Deny newly created buckets with lifecycle but no intelligent tiering
deny[reason] {
  bucket := s3_buckets_being_created[_]
  bucket_has_lifecycle_config(bucket)
  lifecycle_config := get_matching_lifecycle_config(bucket)
  not lifecycle_has_intelligent_tiering(lifecycle_config)
  
  reason := sprintf(
    "NEWLY CREATED S3 bucket %q lifecycle configuration must include intelligent tiering (INTELLIGENT_TIERING storage class)",
    [bucket.address]
  )
}

# Optional: Deny lifecycle configs using .id instead of .bucket (if detectable)
deny[reason] {
  bucket := s3_buckets_being_created[_]
  bucket_has_lifecycle_config(bucket)
  lifecycle_config := get_matching_lifecycle_config(bucket)
  
  # Check if bucket field is unknown (indicates .id usage)
  lifecycle_config.change.after_unknown.bucket == true
  
  reason := sprintf(
    "NEWLY CREATED S3 bucket %q lifecycle configuration should use 'bucket' attribute instead of 'id' for proper reference",
    [bucket.address]
  )
}

# Debug information to help troubleshoot
debug_new_buckets[info] {
  bucket := s3_buckets_being_created[_]
  info := sprintf("Detected new bucket: %s (actions: %v)", [bucket.address, bucket.change.actions])
}

debug_all_s3_resources[info] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_s3_bucket"
  info := sprintf("All S3 resources: %s (actions: %v)", [resource.address, resource.change.actions])
}

debug_lifecycle_configs[info] {
  config := s3_lifecycle_configs_being_created[_]
  bucket_ref := config.change.after.bucket
  info := sprintf("Detected new lifecycle config: %s (bucket: %s)", [config.address, bucket_ref])
}
