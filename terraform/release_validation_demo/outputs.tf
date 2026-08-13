output "agent_id" {
  description = "Agent GUID used for all K8S stores."
  value       = data.keyfactor_agent.k8s.agent_id
}

output "certificate_ids" {
  description = "Keyfactor Command integer IDs of the demo certificates (used for import)."
  value = {
    pfx = keyfactor_certificate.pfx.certificate_id
    csr = keyfactor_certificate.csr.certificate_id
  }
}

output "store_ids" {
  description = "IDs of the created K8S certificate stores."
  value = {
    k8s_tls_secret    = keyfactor_certificate_store.k8s_tls_secret.id
    k8s_opaque_secret = keyfactor_certificate_store.k8s_opaque_secret.id
    k8s_jks           = keyfactor_certificate_store.k8s_jks.id
    k8s_pkcs12        = keyfactor_certificate_store.k8s_pkcs12.id
    k8s_ns            = keyfactor_certificate_store.k8s_ns.id
    k8s_cluster       = keyfactor_certificate_store.k8s_cluster.id
  }
}
