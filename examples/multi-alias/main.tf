terraform {
  required_providers {
    sops = {
      source  = "elioetibr/sops"
      version = ">= 0.1.0"
    }
  }
}

provider "sops" {
  alias = "prod"
  aws {
    profile = "production-sre"
    region  = "us-east-1"
  }
}

provider "sops" {
  alias = "dev"
  aws {
    profile = "test-sre"
    region  = "us-east-1"
  }
}

data "sops_file" "prod" {
  provider    = sops.prod
  source_file = "${path.module}/prod.yaml"
}

data "sops_file" "dev" {
  provider    = sops.dev
  source_file = "${path.module}/dev.yaml"
}
