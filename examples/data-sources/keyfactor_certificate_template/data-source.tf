# Look up a certificate template by common name
data "keyfactor_certificate_template" "webserver" {
  identifier = "WebServer"
}

# Look up a certificate template by integer ID
data "keyfactor_certificate_template" "by_id" {
  identifier = "5"
}
