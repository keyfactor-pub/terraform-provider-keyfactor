terraform {
  required_providers {
    keyfactor = {
      version = "3.0.0"
      source  = "keyfactor-pub/keyfactor"
    }
  }
}

provider "keyfactor" {
  username = "COMMAND\\your_username"
  password = "your_api_password"
  hostname = "mykfinstance.kfdelivery.com"
  domain   = "mydomain.com"
}
