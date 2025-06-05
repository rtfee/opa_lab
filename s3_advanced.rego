package terraform

import input.tfplan as tfplan

# Helper function to check if array contains element
array_contains(arr, elem) {
  arr[_] = elem
}

# Get all S3 buckets being created
s3_buckets_created[bucket] {
  bucket := tfplan.resource_changes[_]
  bucket.type == "aws_s3_bucket"
  array_contains(bucket.change.actions, "create")
}

# Get all S3 bucket lifecycle configurations
s3_lifecycle_configs[config] {
  config := tfplan.resource_changes[_]
  config.type == "aws_s3_bucket_lifecycle_configuration"
  array_contains(["create", "update"], config.change.actions[_])
}

# Check if a bucket has an associated lifecycle configuration
bucket_has_lifecycle(bucket_resource) {
  bucket := bucket_resource
  lifecycle_config := s3_lifecycle_configs[_]
  
  # Get the actual bucket name from the bucket resource
  bucket_name := bucket.change.after.bucket
  
  # Check if lifecycle config references this bucket by name
  lifecycle_config.change.after.bucket == bucket_name
}

# Alternative check - match by resource reference patterns
bucket_has_lifecycle(bucket_resource) {
  bucket := bucket_resource
  lifecycle_config := s3_lifecycle_configs[_]
  
  # Check if lifecycle references the bucket resource directly
  # This handles cases where the lifecycle config uses resource references
  bucket_reference := sprintf("aws_s3_bucket.%s", [bucket.name])
  lifecycle_config.change.after.bucket == bucket_reference
}

# Check if lifecycle configuration has intelligent tiering enabled
lifecycle_has_intelligent_tiering(lifecycle_config) {
  rule := lifecycle_config.change.after.rule[_]
  transition := rule.transition[_]
  transition.storage_class == "INTELLIGENT_TIERING"
}

# Alternative check for intelligent tiering in different rule structure
lifecycle_has_intelligent_tiering(lifecycle_config) {
  rule := lifecycle_config.change.after.rule[_]
  rule.transition.storage_class == "INTELLIGENT_TIERING"
}

# Check if bucket uses "bucket" attribute instead of "id" in lifecycle reference
lifecycle_uses_bucket_attribute(bucket_resource) {
  bucket := bucket_resource
  lifecycle_config := s3_lifecycle_configs[_]
  bucket_name := bucket.change.after.bucket
  
  # Ensure the lifecycle config references the bucket by name (not resource ID)
  lifecycle_config.change.after.bucket == bucket_name
  
  # Additional check: the bucket value should be a string, not a resource reference
  is_string(lifecycle_config.change.after.bucket)
}

# Deny buckets without lifecycle configuration
deny[reason] {
  bucket := s3_buckets_created[_]
  not bucket_has_lifecycle(bucket)
  
  reason := sprintf(
    "S3 bucket %q must have a lifecycle configuration to enforce intelligent tiering",
    [bucket.address]
  )
}

# Deny buckets whose lifecycle config doesn't use "bucket" attribute
deny[reason] {
  bucket := s3_buckets_created[_]
  bucket_has_lifecycle(bucket)
  not lifecycle_uses_bucket_attribute(bucket)
  
  reason := sprintf(
    "S3 bucket %q lifecycle configuration must use 'bucket' attribute instead of 'id' for proper reference",
    [bucket.address]
  )
}

# Deny buckets without intelligent tiering in lifecycle policy
deny[reason] {
  bucket := s3_buckets_created[_]
  bucket_has_lifecycle(bucket)
  lifecycle_uses_bucket_attribute(bucket)
  
  # Find the matching lifecycle config
  bucket_name := bucket.change.after.bucket
  lifecycle_config := s3_lifecycle_configs[_]
  lifecycle_config.change.after.bucket == bucket_name
  not lifecycle_has_intelligent_tiering(lifecycle_config)
  
  reason := sprintf(
    "S3 bucket %q lifecycle configuration must include intelligent tiering (INTELLIGENT_TIERING storage class)",
    [bucket.address]
  )
}
