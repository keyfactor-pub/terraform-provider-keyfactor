# keyfactor_certificate_store accepts three import-ID formats. Choose whichever
# matches your permission scope.

# 1. Bare GUID (legacy). Requires read permission on every certificate store in
#    Command, because it calls GET /CertificateStores/{guid} directly.
terraform import keyfactor_certificate_store.mystore "9f8855f1-80ff-4475-89ec-d82accb32cea"

# 2. Explicit "stores/<guid>" form. Identical behavior to the bare GUID above,
#    but parses unambiguously.
terraform import keyfactor_certificate_store.mystore "stores/9f8855f1-80ff-4475-89ec-d82accb32cea"

# 3. Container-scoped form. Use this when your role only has read on certain
#    containers (formerly "applications") — the provider lists stores inside
#    that container and picks the matching GUID, avoiding the unscoped GET
#    that requires global read. The container segment accepts either a numeric
#    container ID or a container name.
terraform import keyfactor_certificate_store.mystore "containers/42/stores/9f8855f1-80ff-4475-89ec-d82accb32cea"
terraform import keyfactor_certificate_store.mystore "containers/MyTeam/stores/9f8855f1-80ff-4475-89ec-d82accb32cea"
