# keyfactor_template_role_binding Resource — Test Documentation

**File:** `keyfactor/resource_keyfactor_template_role_binding_test.go`

---

## What It Tests

CRUD lifecycle of the `keyfactor_template_role_binding` resource:
- Creating a role binding associating a security role to one or more certificate templates
- Updating the binding (adding/removing templates)
- Verifying `role_name` and `template_short_names` attributes

> **Known limitation:** The `keyfactor-go-client` v3 `UpdateTemplateArg` struct is missing the
> `Policies` field required by Command v25+. The integration and unit tests validate the
> *expected error* until the client library is updated.

---

## Integration Test: `TestIntKeyfactorTemplateRoleBindingResource`

Requires enrollment patterns (Command v25+). Discovers a template linked to an enrollment
pattern, creates a unique role, and attempts binding — expecting the known `Policies` error.

```bash
make testint-run TEST_NAME=TestIntKeyfactorTemplateRoleBindingResource
```

---

## Unit Test: `TestUnitKeyfactorTemplateRoleBindingResource`

**Cassette:** `keyfactor/testdata/cassettes/template_role_binding_resource.yaml`
**Params:** `keyfactor/testdata/cassettes/template_role_binding_resource.params.json`

Creates a role then attempts template binding, expecting an error matching
`Policies.*cannot be empty|Error updating template`.

```bash
# Replay (no lab needed)
make testunit

# Record a new cassette (requires Command v25+ lab)
make testunit-record-one TEST_NAME=TestUnitKeyfactorTemplateRoleBindingResource
```

---

## Notes

- `ExpectError` is used intentionally — the cassette captures the server's error response.
- Once the `UpdateTemplateArg.Policies` field is added to the client library, the test should be updated to expect success instead.
