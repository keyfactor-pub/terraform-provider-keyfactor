provider "keyfactor" {
  username = "COMMAND\\your_username"
  password = "your_api_password"
  hostname = "mykfinstance.kfdelivery.com"
}

data "keyfactor_certificate" "cert_by_id" {
  identifier = "26" # Lookup by Keyfactor Command Certificate ID
}

data "keyfactor_certificate" "cert_by_id_w_collection_id" {
  identifier    = "26" # Lookup by Keyfactor Command Certificate ID
  collection_id = 1    # Optional. If not specified, will search all collections.
}

data "keyfactor_certificate" "cert_by_cn" {
  identifier = "example.com" # Lookup by certificate CN. Will return the most recently issued certificate with this CN.
}

data "keyfactor_certificate" "cert_by_cn_and_thumbprint" {
  identifier = "1234567890ABCDEF1234567890ABCDEF12345678" # Lookup by certificate thumbprint.
}

