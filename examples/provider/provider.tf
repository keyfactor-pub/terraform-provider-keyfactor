# basic auth configuration example
provider "keyfactor" {
  username = "COMMAND\\your_username"
  password = "your_api_password"
  hostname = "mykfinstance.kfdelivery.com"
  domain   = "mydomain.com"
}

# oauth configuration example
provider "keyfactor" {
  client_id     = "my_oauth_client_id"
  client_secret = "my_oauth_client_secret"
  scopes        = "enroll,agents,cert:admin" # These are example, fictitious, scopes and will vary based on identity provider.
  token_url     = "https://mykfinstance.kfdelivery.com:8444/realms/Keyfactor/protocol/openid-connect/token"
  hostname      = "mykfinstance.kfdelivery.com"

  alias = "keyfactor_command_oauth" # This isn't required
}

# kerberos auth - password-based
provider "keyfactor" {
  hostname         = "mykfinstance.kfdelivery.com"
  kerberos_realm   = "EXAMPLE.COM"
  kerberos_username = "svc_terraform"
  kerberos_password = "your_kerberos_password"
  kerberos_config  = "/etc/krb5.conf" # optional, defaults to /etc/krb5.conf

  # Disable PA-FX-FAST if authenticating against Active Directory
  kerberos_disable_pafxfast = true
}

# kerberos auth - keytab-based (no password required)
provider "keyfactor" {
  hostname          = "mykfinstance.kfdelivery.com"
  kerberos_realm    = "EXAMPLE.COM"
  kerberos_username = "svc_terraform"
  kerberos_keytab   = "/etc/keyfactor/svc_terraform.keytab"
}

# kerberos auth - credential cache (ccache)
provider "keyfactor" {
  hostname        = "mykfinstance.kfdelivery.com"
  kerberos_ccache = "/tmp/krb5cc_1000" # path to an existing ccache obtained via kinit
}