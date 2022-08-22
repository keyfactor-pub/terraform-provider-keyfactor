provider "keyfactor" {
  username = "COMMAND\\your_username"
  password = "your_api_password"
  hostname = "mykfinstance.kfdelivery.com"
}

data "keyfactor_certificate_store" "iis_personal" {
  keyfactor_id = "9f8855f1-80ff-4475-89ec-d82accb32cea" #The Keyfactor GUID of an existing certificate store.
  password     = "my store password!" #The password for the certificate store. Note: This is bad practice, use TF_VAR_<variable_name> instead.
}