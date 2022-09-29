provider "keyfactor" {
  username = "COMMAND\\your_username"
  password = "your_api_password"
  hostname = "mykfinstance.kfdelivery.com"
}

data "keyfactor_certificate_store" "iis_personal" {
  id       = "ef0b8005-63bf-42e8-aa3f-23bc94dcf611"
  password = "your_personal_store_password"
}

output "iis_personal_metadata" {
  value = {
    id           = data.keyfactor_certificate_store.iis_personal.id
    container_id = data.keyfactor_certificate_store.iis_personal.container_id
  }
}