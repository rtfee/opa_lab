#Basic S3 bucket with intelligent tiering
resource "aws_s3_bucket" "example_bucket" {
  bucket = "my-example-bucket-with-intelligent-tiering"
  
  tags = {
    Name        = "scalr48727464829"
    Environment = "Production"
    Purpose     = "Data Storage with Intelligent Tiering"
  }
}

# Lifecycle configuration for the bucket - uses "bucket" attribute
resource "aws_s3_bucket_lifecycle_configuration" "example_lifecycle" {
  # IMPORTANT: Using "bucket" attribute instead of "id" to reference the bucket
  #bucket = aws_s3_bucket.example_bucket.id
  bucket = aws_s3_bucket.example_bucket.bucket
  

rule {
    id     = "intelligent_tiering_rule"
    status = "Disabled"

   filter {  
      prefix = ""  
    } 
    
    
    # Optional: Additional transitions for cost optimization
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
  }
}
