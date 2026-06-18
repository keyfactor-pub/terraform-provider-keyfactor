# keyfactor_certificate_store accepts four import-ID formats. Choose whichever
# matches your permission scope.

# 1. Bare GUID (legacy). Requires read permission on every certificate store in
#    Command, because it calls GET /CertificateStores/{guid} directly.
terraform import keyfactor_certificate_store.mystore "9f8855f1-80ff-4475-89ec-d82accb32cea"

# 2. Explicit "stores/<guid>" form. Identical behavior to the bare GUID above,
#    but parses unambiguously.
terraform import keyfactor_certificate_store.mystore "stores/9f8855f1-80ff-4475-89ec-d82accb32cea"

# 3. Application-scoped form (preferred on modern Keyfactor Command, where
#    "containers" have been renamed to "applications"). Use this when your role
#    only has read on certain applications — the provider lists stores inside
#    that application and picks the matching GUID, avoiding the unscoped GET
#    that requires global read. The application segment accepts either a numeric
#    ID or an application name.
terraform import keyfactor_certificate_store.mystore "applications/42/stores/9f8855f1-80ff-4475-89ec-d82accb32cea"
terraform import keyfactor_certificate_store.mystore "applications/MyTeam/stores/9f8855f1-80ff-4475-89ec-d82accb32cea"

# 4. Container-scoped form. Legacy alias for the application-scoped form above —
#    accepted for compatibility with older Keyfactor Command versions and
#    existing automation. Behavior is identical to "applications/...".
terraform import keyfactor_certificate_store.mystore "containers/42/stores/9f8855f1-80ff-4475-89ec-d82accb32cea"
terraform import keyfactor_certificate_store.mystore "containers/MyTeam/stores/9f8855f1-80ff-4475-89ec-d82accb32cea"
