#Basic S3 bucket with intelligent tiering
resource "aws_s3_bucket" "example_bucket" {
  bucket = "my-example-bucket-with-intelligent-tiering"
  
  tags = {
    Name        = "scalr48727464829"
    Environment = "Production"
    Purpose     = "Data Storage with Intelligent Tiering"
  }
}

