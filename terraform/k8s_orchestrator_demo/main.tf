terraform {
  required_providers {
    keyfactor = {
      source  = "keyfactor-pub/keyfactor"
      version = "~> 2.9"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
  }
}

provider "keyfactor" {}

locals {
  k8s_config_path = coalesce(var.k8s_credentials_file, "${path.module}/k8s-creds.json")
}

provider "kubernetes" {
  config_path = local.k8s_config_path
}
