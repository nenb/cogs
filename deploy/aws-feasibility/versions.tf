terraform {
  required_version = "= 1.12.4"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.54.0"
    }
  }

  # Production initializes this backend with one fixed cycle-N state path.
  # No two ordinals can share provider state or a generation lineage.
  backend "local" {}
}

provider "aws" {
  profile = var.aws_profile
  region  = var.aws_region

  default_tags {
    tags = local.tags
  }
}
