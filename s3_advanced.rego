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

# Check if a bucket has an associated lifecycle configuration using "bucket" attribute
bucket_has_lifecycle(bucket_address) {
  lifecycle_config := s3_lifecycle_configs[_]
  # Check if lifecycle config references this bucket using "bucket" attribute
  lifecycle_config.change.after.bucket == bucket_address
}

# Alternative check using planned_values for bucket reference
bucket_has_lifecycle(bucket_address) {
  lifecycle_config := s3_lifecycle_configs[_]
  # Check using the bucket attribute in planned values
  lifecycle_config.change.after.bucket != null
  lifecycle_config.change.after.bucket == bucket_address
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
lifecycle_uses_bucket_attribute(bucket_address) {
  lifecycle_config := s3_lifecycle_configs[_]
  # Ensure the lifecycle config uses "bucket" attribute, not "id"
  lifecycle_config.change.after.bucket == bucket_address
  # Verify that "id" is not being used (id would be null/undefined at plan time)
  not lifecycle_config.change.after.id
}

# Deny buckets without lifecycle configuration
deny[reason] {
  bucket := s3_buckets_created[_]
  bucket_address := bucket.address
  not bucket_has_lifecycle(bucket_address)
  
  reason := sprintf(
    "S3 bucket %q must have a lifecycle configuration to enforce intelligent tiering",
    [bucket_address]
  )
}

# Deny buckets whose lifecycle config doesn't use "bucket" attribute
deny[reason] {
  bucket := s3_buckets_created[_]
  bucket_address := bucket.address
  bucket_has_lifecycle(bucket_address)
  not lifecycle_uses_bucket_attribute(bucket_address)
  
  reason := sprintf(
    "S3 bucket %q lifecycle configuration must use 'bucket' attribute instead of 'id' for proper reference",
    [bucket_address]
  )
}

# Deny buckets without intelligent tiering in lifecycle policy
deny[reason] {
  bucket := s3_buckets_created[_]
  bucket_address := bucket.address
  bucket_has_lifecycle(bucket_address)
  lifecycle_uses_bucket_attribute(bucket_address)
  
  # Find the matching lifecycle config
  lifecycle_config := s3_lifecycle_configs[_]
  lifecycle_config.change.after.bucket == bucket_address
  not lifecycle_has_intelligent_tiering(lifecycle_config)
  
  reason := sprintf(
    "S3 bucket %q lifecycle configuration must include intelligent tiering (INTELLIGENT_TIERING storage class)",
    [bucket_address]
  )
}
