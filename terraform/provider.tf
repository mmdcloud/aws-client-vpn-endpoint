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
  }
  # backend "s3" {
  #   bucket       = "awsclientvpnendpoint"
  #   key          = "terraform.tfstate"
  #   region       = var.region
  #   use_lockfile = true
  # }
}

# Configure the AWS Provider
provider "aws" {
  region = var.region
}

provider "random" {}