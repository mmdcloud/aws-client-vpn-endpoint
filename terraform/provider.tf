terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.7.2"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.0"
    }
  }
  # Production Remote State Backend
  # backend "s3" {
  #   bucket       = "my-terraform-state-bucket"
  #   key          = "vpn-endpoint/terraform.tfstate"
  #   region       = "ap-southeast-2"
  #   encrypt      = true
  #   use_lockfile = true
  # }
}

# Configure the AWS Provider
provider "aws" {
  region = var.region
}

provider "random" {}
