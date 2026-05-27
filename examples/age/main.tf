terraform {
  required_providers {
    sops = {
      source  = "elioetibr/sops"
      version = ">= 0.0.1"
    }
  }
}

provider "sops" {
  age { key_file = pathexpand("~/.config/sops/age/keys.txt") }
}

data "sops_file" "app" {
  source_file = "${path.module}/secrets.yaml"
}

output "structured" {
  value     = jsondecode(data.sops_file.app.data_json)
  sensitive = true
}
