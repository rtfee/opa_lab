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

# Check if lifecycle configuration uses .id reference (bucket value is unknown at plan time)
lifecycle_uses_id_reference(lifecycle_config) {
  # If bucket is in after_unknown, it means it's using a reference like .id
  lifecycle_config.change.after_unknown.bucket == true
}

# Check if lifecycle configuration uses direct bucket name (bucket value is known at plan time)
lifecycle_uses_bucket_name(lifecycle_config) {
  # If bucket is in after and not in after_unknown, it's using direct bucket name
  lifecycle_config.change.after.bucket
  not lifecycle_config.change.after_unknown.bucket
}

# Check if lifecycle configuration has intelligent tiering
lifecycle_has_intelligent_tiering(lifecycle_config) {
  rule := lifecycle_config.change.after.rule[_]
  transition := rule.transition[_]
  transition.storage_class == "INTELLIGENT_TIERING"
}

# Get bucket name from bucket resource
get_bucket_name(bucket_resource) = bucket_name {
  bucket_name := bucket_resource.change.after.bucket
}

# Check if there's a lifecycle config that references the bucket using .id (bad)
bucket_has_id_referenced_lifecycle(bucket_resource) {
  lifecycle_config := s3_lifecycle_configs[_]
  lifecycle_uses_id_reference(lifecycle_config)
  
  # Check configuration section to see if this lifecycle references our bucket
  bucket_address := bucket_resource.address
  lifecycle_address := lifecycle_config.address
  config_resource := tfplan.configuration.root_module.resources[_]
  config_resource.address == lifecycle_address
  
  # Check if the bucket reference points to our bucket
  reference := config_resource.expressions.bucket.references[_]
  contains(reference, bucket_address)
}

# Check if there's a lifecycle config that references the bucket using bucket name (good)
bucket_has_name_referenced_lifecycle(bucket_resource) {
  lifecycle_config := s3_lifecycle_configs[_]
  lifecycle_uses_bucket_name(lifecycle_config)
  
  bucket_name := get_bucket_name(bucket_resource)
  lifecycle_config.change.after.bucket == bucket_name
}

# Check if bucket has any lifecycle configuration at all
bucket_has_any_lifecycle(bucket_resource) {
  bucket_has_id_referenced_lifecycle(bucket_resource)
}

bucket_has_any_lifecycle(bucket_resource) {
  bucket_has_name_referenced_lifecycle(bucket_resource)
}

# DENY RULES

# Deny buckets without any lifecycle configuration
deny[reason] {
  bucket := s3_buckets_created[_]
  not bucket_has_any_lifecycle(bucket)
  
  reason := sprintf(
    "S3 bucket %q must have a lifecycle configuration to enforce intelligent tiering",
    [bucket.address]
  )
}

# Deny buckets whose lifecycle config uses .id reference instead of bucket name
deny[reason] {
  bucket := s3_buckets_created[_]
  bucket_has_id_referenced_lifecycle(bucket)
  not bucket_has_name_referenced_lifecycle(bucket)
  
  reason := sprintf(
    "S3 bucket %q lifecycle configuration must use 'bucket' attribute (bucket name) instead of 'id' for proper reference",
    [bucket.address]
  )
}

# Deny buckets without intelligent tiering in their lifecycle policy
deny[reason] {
  bucket := s3_buckets_created[_]
  bucket_has_name_referenced_lifecycle(bucket)
  
  # Find the lifecycle config that uses bucket name
  lifecycle_config := s3_lifecycle_configs[_]
  lifecycle_uses_bucket_name(lifecycle_config)
  bucket_name := get_bucket_name(bucket)
  lifecycle_config.change.after.bucket == bucket_name
  
  not lifecycle_has_intelligent_tiering(lifecycle_config)
  
  reason := sprintf(
    "S3 bucket %q lifecycle configuration must include intelligent tiering (INTELLIGENT_TIERING storage class)",
    [bucket.address]
  )
}
