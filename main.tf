terraform {
    required_providers {
        keyfactor = {
            version = "~> 1.0.0"
            source  = "keyfactor.com/keyfactordev/keyfactor"
        }
    }
}

provider "keyfactor" {
    alias       = "command"
    hostname    = "sedemo.thedemodrive.com"
}

resource "keyfactor_security_identity" "identity" {
    provider = keyfactor.command
    security_identity {
        account_name = "THEDEMODRIVE\\TestUser1"
    }
}