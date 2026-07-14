terraform {
  required_version = "= 1.12.4"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.54.0"
    }
  }

  backend "local" {
    path = ".state/terraform.tfstate"
  }
}

provider "aws" {
  profile = var.aws_profile
  region  = var.aws_region

  default_tags {
    tags = local.tags
  }
}
