terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
    keyfactor = {
      version = "~> 1.0.2"
      source  = "keyfactor.com/keyfactordev/keyfactor"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region = "us-east-1"
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

resource "aws_acm_certificate" "cert" {
  private_key       = keyfactor_certificate.aws_cert1.private_key
  certificate_body  = keyfactor_certificate.aws_cert1.certificate_pem
  certificate_chain = keyfactor_certificate.aws_cert1.certificate_chain
}
