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
  # Previously fell back to a "${path.module}/k8s-creds.json" file that was never
  # generated anywhere in this demo (confirmed failure: "./k8s-creds.json: no such
  # file or directory", 2026-08-07). k8s_credentials_file now defaults to kfclab's
  # own kubeconfig (~/.kube/kfc-lab.yaml) -- no separate credentials file to manage.
  k8s_config_path = pathexpand(var.k8s_credentials_file)
}

provider "kubernetes" {
  config_path = local.k8s_config_path
}
