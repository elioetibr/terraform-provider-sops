terraform {
  required_version = ">= 1.10"
  required_providers {
    sops = {
      source  = "elioetibr/sops"
      version = ">= 0.0.1"
    }
  }
}

provider "sops" {
  aws {
    profile = "production-sre"
    region  = "us-east-1"
  }
}

data "sops_file" "app" {
  source_file = "${path.module}/secrets.yaml"
  input_type  = "yaml"
}

output "db_password" {
  value     = data.sops_file.app.data["database.password"]
  sensitive = true
}
