# Look up a certificate authority by name
data "keyfactor_certificate_authority" "by_name" {
  identifier = "Sub-CA"
}

# Look up a certificate authority by integer ID
data "keyfactor_certificate_authority" "by_id" {
  identifier = "1"
}

output "ca_hostname" {
  value = data.keyfactor_certificate_authority.by_name.host_name
}
