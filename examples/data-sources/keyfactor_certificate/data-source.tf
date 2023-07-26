provider "keyfactor" {
  username = "COMMAND\\your_username"
  password = "your_api_password"
  hostname = "mykfinstance.kfdelivery.com"
}

data "keyfactor_certificate" "cert_w_pass_and_pkey_cn" {
  identifier   = "k8s-ingress"                              # Using certificate common name (CN)
  key_password = "this is required to return a private key" # This is bad practice. Use TF_VAR_<variable_name> instead.
}

data "keyfactor_certificate" "cert_w_pass_and_pkey_tp" {
  identifier   = "FF41F242C323712E8C17DECF4E6AEBFB3646F966" # Using certificate thumbprint
  key_password = "this is required to return a private key" # This is bad practice. Use TF_VAR_<variable_name> instead.
}

data "keyfactor_certificate" "cert_w_pass_and_pkey_id" {
  identifier   = "1"                                        # Using Keyfactor Command certificate ID
  key_password = "this is required to return a private key" # This is bad practice. Use TF_VAR_<variable_name> instead.
}

data "keyfactor_certificate" "cert_wo_pkey_cn" {
  # This will returns a certificate without a private key
  identifier = "my-ca-cert" # Using certificate common name (CN)
}

data "keyfactor_certificate" "cert_wo_pkey_tp" {
  # This will returns a certificate without a private key
  identifier = "FF41F242C323712E8C17DECF4E6AEBFB3646F966" # Using certificate thumbprint
}

data "keyfactor_certificate" "cert_wo_pkey_id" {
  # This will returns a certificate without a private key
  identifier = "1" # Using Keyfactor Command certificate ID
}

