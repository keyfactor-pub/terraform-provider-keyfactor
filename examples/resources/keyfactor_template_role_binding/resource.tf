provider "keyfactor" {
  username = "your_username"
  password = "your_api_password"
  hostname = "mykfinstance.kfdelivery.com"
  domain   = "mydomain.com"
}

resource "keyfactor_template_role_binding" "kf_terraform_role_attachment" {
  role_name            = "WebServerTerraformer" # The name of the role to grant template access to.
  template_short_names = ["2YearTestWebServer", "2yrWebServer"]
  # List of short names of templates the role will have access to.
}