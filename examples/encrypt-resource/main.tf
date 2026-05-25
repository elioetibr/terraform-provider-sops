terraform {
  required_version = ">= 1.11" # write-only attributes require 1.11+
  required_providers {
    sops = {
      source  = "elioetibr/sops"
      version = ">= 0.2.0"
    }
  }
}

provider "sops" {
  age { key_file = pathexpand("~/.config/sops/age/keys.txt") }
}

# An age-encrypted secrets file. The plaintext is supplied via the
# write-only content_wo attribute, which Terraform never stores in state.
# To re-encrypt with new plaintext, bump content_wo_version.
resource "sops_file" "app_secrets" {
  path               = "${path.module}/app.enc.yaml"
  content_wo         = file("${path.module}/plaintext.yaml")
  content_wo_version = "1"
  input_type         = "yaml"

  creation_rules {
    age_recipients = [
      "age1qpf4q3wxc5m9eu3a7kp7z82l49yn94zd7r6c3qpf3v66h8x35y7sz4jqlf",
    ]
  }
}

# Verify the encrypted file decrypts back to the original plaintext by
# reading it through the data source.
data "sops_file" "verify" {
  source_file = sops_file.app_secrets.path
  depends_on  = [sops_file.app_secrets]
}

output "decrypted_password" {
  value     = data.sops_file.verify.data["password"]
  sensitive = true
}

# --- Key rotation -----------------------------------------------------------
# To rotate master keys WITHOUT re-encrypting plaintext, add a new recipient
# (or remove an old one) and flip rotate_keys = true for a single apply:
#
#   creation_rules {
#     age_recipients = [
#       "age1qpf4q...",   # existing recipient
#       "age14zq6...",    # newly added recipient
#     ]
#   }
#   rotate_keys = true
#
# After the apply succeeds, set rotate_keys = false (or remove the flag) so
# subsequent applies don't rotate on every run.

# --- AWS KMS variant --------------------------------------------------------
# To encrypt with an AWS KMS key under a specific profile (no AWS_PROFILE
# export needed), use the per-resource aws block plus a kms creation rule:
#
#   resource "sops_file" "aws_secrets" {
#     path               = "${path.module}/aws.enc.yaml"
#     content_wo         = file("${path.module}/plaintext.yaml")
#     content_wo_version = "1"
#
#     aws { profile = "production-sre" region = "us-east-1" }
#
#     creation_rules {
#       kms_arns = ["arn:aws:kms:us-east-1:123456789012:alias/secrets"]
#     }
#   }
