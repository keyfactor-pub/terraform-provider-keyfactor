variable "template_name" {
  type        = string
  default     = "AnyCA_lab-role"
  description = "Common name, display name, or integer ID of an existing certificate template to associate the demo enrollment pattern with. Defaults to the kfclab lab's AnyCA_lab-role template."
}

variable "suffix" {
  type        = string
  default     = "_TF"
  description = "Suffix appended to the enrollment pattern name to avoid conflicts with other lab resources."
}

variable "description_override" {
  type        = string
  default     = ""
  description = "Override for the enrollment pattern description during lab-update testing."
}

# ---------------------------------------------------------------------------
# Driver-attribute variables (full-review Phase 1 required tests, item 3):
# lab-update exercises these to actually CHANGE associated_role_names,
# certificate_authority_ids, and policies.default_certificate_owner_role_id
# in place -- the exact update paths findings F2/F4 fixed. Both roles and
# both CAs referenced below already exist in kfclab by default.
#
# force_template_default is deliberately NOT exercised by this demo (see
# main.tf's comment on the resource block): it is validated instead by the
# dedicated TestUnitKeyfactorEnrollmentPatternResource_MirrorFieldsFollowDriverOnUpdate
# Go test (resource_keyfactor_enrollment_pattern_mirror_fix_unit_test.go),
# which can safely undo the shared-lab-fixture side effect
# force_template_default = true causes (stealing TemplateDefault status
# from whichever pattern currently holds it for the template) via an
# out-of-band restore call after asserting the fix. A Makefile-driven
# terraform lifecycle has no equivalent safe place to do that: if this
# demo's own pattern became the template's default, its own `destroy` step
# would fail outright (Command refuses to delete a default pattern while
# other patterns exist for the same template) and would leave kfclab's
# shared "Lab - ..." seed pattern un-defaulted for every other demo/test
# that assumes it still holds that status.
# ---------------------------------------------------------------------------

variable "associated_role_name" {
  type        = string
  default     = "InstanceAdmin"
  description = "Security role name for associated_role_names. Changed during lab-update to exercise the associated_roles mirror follow-the-driver fix (full-review finding F2)."
}

variable "owner_role_name" {
  type        = string
  default     = "InstanceAdmin"
  description = "Security role name for policies.default_certificate_owner_role_id. Changed during lab-update to exercise the policies.default_certificate_owner_role_name mirror follow-the-driver fix (full-review finding F4)."
}

variable "ca_name" {
  type        = string
  default     = "OpenBao PKI"
  description = "Certificate authority logical name for certificate_authority_ids. Changed during lab-update to exercise the certificate_authorities mirror follow-the-driver fix (full-review finding F2)."
}
