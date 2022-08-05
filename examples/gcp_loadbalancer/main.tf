terraform {
  required_providers {
    keyfactor = {
      version = "~> 1.0.2"
      source  = "keyfactor.com/keyfactordev/keyfactor"
    }
    google = {
      source  = "hashicorp/google"
      version = "4.27.0"
    }
  }
}

# Configure the Google Provider
provider "google" {
  project = "{{YOUR GCP PROJECT}}"
  region  = "us-central1"
  zone    = "us-central1-c"
}

provider "keyfactor" {
  alias    = "command"
  hostname = "keyfactor.example.com"
}

resource "keyfactor_certificate" "aws_cert1" {
  provider = keyfactor.command
  subject {
    subject_common_name = "aws_lb_test1"
  }
  sans {
    san_dns = ["aws_lb_test1"]
  }
  key_password          = "P@s5w0Rd2321!"
  certificate_authority = "keyfactor.example.com\\CA 1"
  cert_template         = "WebServer1yr"
}

resource "google_compute_ssl_certificate" "keyfactor_gcp" {
  name_prefix = "keyfactor-terraform-gcp1"
  description = "Some wacky numbers and letters"
  private_key = keyfactor_certificate.aws_cert1.private_key
  certificate = format("%s%s", keyfactor_certificate.aws_cert1.certificate_pem, keyfactor_certificate.aws_cert1.certificate_chain)

  lifecycle {
    create_before_destroy = true
  }
}
