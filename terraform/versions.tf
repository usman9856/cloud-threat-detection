terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0" # confirm: match the version pinned in the P3 repo lockfile
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      (var.lab_tag_key) = var.lab_tag_value
      project           = "p5-cloud-threat-detection"
    }
  }
}
