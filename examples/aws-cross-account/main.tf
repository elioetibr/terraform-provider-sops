terraform {
  required_providers {
    sops = {
      source  = "elioetibr/sops"
      version = ">= 0.0.1"
    }
  }
}

provider "sops" {
  aws {
    profile = "platform-sre"
    region  = "us-east-1"
    assume_role { role_arn = "arn:aws:iam::111111111111:role/sops-reader" }
  }
}

# This file was encrypted by a key in account 222222222222 — we need a different role.
data "sops_file" "tenant_secrets" {
  source_file = "${path.module}/tenant-secrets.yaml"
  input_type  = "yaml"
  aws {
    profile = "platform-sre"
    assume_role { role_arn = "arn:aws:iam::222222222222:role/sops-reader" }
  }
}
