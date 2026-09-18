provider "keyfactor" {
  hostname = "mykfinstance.kfdelivery.com"
}

# Look up a certificate collection by name
data "keyfactor_certificate_collection" "by_name" {
  name = "Web Server Certificates"
}

# Look up a certificate collection by its internal numeric ID
data "keyfactor_certificate_collection" "by_id" {
  id = 7
}
