output "agent_id" {
  description = "Agent ID used for all K8S stores."
  value       = local.agent_id
}

output "store_ids" {
  description = "IDs of the created K8S certificate stores."
  value = {
    k8s_tls_secret    = keyfactor_certificate_store.k8s_tls_secret.id
    k8s_opaque_secret = keyfactor_certificate_store.k8s_opaque_secret.id
    k8s_cert          = keyfactor_certificate_store.k8s_cert.id
    k8s_jks           = keyfactor_certificate_store.k8s_jks.id
    k8s_jks_buddy     = keyfactor_certificate_store.k8s_jks_buddy.id
    k8s_pkcs12        = keyfactor_certificate_store.k8s_pkcs12.id
    k8s_pkcs12_buddy  = keyfactor_certificate_store.k8s_pkcs12_buddy.id
    k8s_ns            = keyfactor_certificate_store.k8s_ns.id
    k8s_cluster       = keyfactor_certificate_store.k8s_cluster.id
  }
}
