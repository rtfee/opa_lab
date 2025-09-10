module "s3-bucket" {
	source  = "scalrdemov2.scalr.io/acc-v0ohpf7km39ru2dtn/s3-bucket/aws"
	version = "5.0.0"

	# Set 1 required variable below.

	# (Optional, Forces new resource) The name of the bucket. If omitted, Terraform will assign a random, unique name.
 	bucket = "scalr1245678"
}
