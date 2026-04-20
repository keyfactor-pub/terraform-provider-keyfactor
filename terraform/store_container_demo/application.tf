# ---------------------------------------------------------------------------
# Application (container) that both stores will be linked to.
# Validates that container_name and application_name both resolve to the same
# Command application/container concept.
# ---------------------------------------------------------------------------
resource "keyfactor_application" "demo" {
  name = "Store Container Demo${var.suffix}"
}
