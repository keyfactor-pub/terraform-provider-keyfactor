package keyfactor

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes)
// ---------------------------------------------------------------------------

func TestUnitKeyfactorCertificateDeployResource(t *testing.T) {
	cassetteName := "certificate_deploy_resource"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var params deployTestParams
	if os.Getenv("RECORD_CASSETTES") == "1" {
		client := testAccIntegrationPreCheck(t)
		agentID, clientMachine := discoverAgent(t, client)
		storeType := discoverStoreTypeForAgent(t, client, agentID)

		var storePath string
		if strings.HasPrefix(strings.ToLower(storeType), "k8s") {
			if k8sStoreCredentials() == "" {
				t.Skip("Skipping K8S deploy test: set KEYFACTOR_K8S_CREDENTIALS_FILE or KEYFACTOR_K8S_SERVER_PASSWORD")
			}
			storePath = fmt.Sprintf("default/tf-unit-deploy-%d", time.Now().UnixNano())
		} else {
			storePath = fmt.Sprintf("/tf-unit-deploy-%d", time.Now().UnixNano())
		}

		ca := discoverCA(t, client)
		enrollmentPattern := discoverEnrollmentPattern(t, client)
		var templateName string
		if enrollmentPattern == "" {
			templateName = discoverTemplate(t, client)
		}
		cn := randomTestCN("tf-unit-deploy")

		params = deployTestParams{
			CN:                cn,
			StoreType:         storeType,
			ClientMachine:     clientMachine,
			AgentID:           agentID,
			StorePath:         storePath,
			CAName:            ca,
			TemplateName:      templateName,
			EnrollmentPattern: enrollmentPattern,
		}
		writeDeployTestParams(cassettePath, params)
	} else {
		params = readDeployTestParams(cassettePath)
		if params.CN == "" {
			t.Skip("No deploy cassette recorded. Run with RECORD_CASSETTES=1 against a live lab with an agent.")
		}
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	var certConfig string
	if params.EnrollmentPattern != "" {
		certConfig = testAccCertPFXConfigEnrollmentPattern(params.EnrollmentPattern, params.CAName, params.CN)
	} else {
		certConfig = testAccCertPFXConfig(params.TemplateName, params.CAName, params.CN)
	}
	storeConfig := testAccCertStoreConfig(params.StoreType, params.ClientMachine, params.AgentID, params.StorePath)
	deployConfig := testAccCertDeployConfig("keyfactor_certificate.test", "keyfactor_certificate_store.test")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: certConfig + "\n" + storeConfig + "\n" + deployConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_store.test", "id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_deployment.test", "id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_deployment.test", "certificate_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_deployment.test", "certificate_store_id"),
				),
			},
		},
	})
}

// TestUnitKeyfactorCertificateDeployResource_NoInvSchedule verifies that
// deploying a certificate to a store that has NO inventory schedule configured
// succeeds with a warning and skips the validateDeployment polling loop.
//
// The cassette must capture a GetCertificateStoreByID response where all
// InventorySchedule sub-fields (Immediate, Interval, Daily, ExactlyOnce) are
// nil/absent. Use a K8SPKCS12 store for recording — it exhibits this behavior
// by default unless an inventory_schedule is explicitly configured.
//
// To record: RECORD_CASSETTES=1 go test -run TestUnitKeyfactorCertificateDeployResource_NoInvSchedule -v
// (or: make testunit-record-cert-deploy-no-inv)
func TestUnitKeyfactorCertificateDeployResource_NoInvSchedule(t *testing.T) {
	cassetteName := "certificate_deploy_resource_no_inv_schedule"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var params deployTestParams
	if os.Getenv("RECORD_CASSETTES") == "1" {
		client := testAccIntegrationPreCheck(t)
		agentID, clientMachine := discoverAgent(t, client)

		// Use K8SPKCS12 specifically — it requires a separate inventory job,
		// so stores created without inventory_schedule trigger the warning path.
		storeType := "K8SPKCS12"
		if k8sStoreCredentials() == "" {
			t.Skip("Skipping no-inv-schedule deploy test: set KEYFACTOR_K8S_CREDENTIALS_FILE or KEYFACTOR_K8S_SERVER_PASSWORD")
		}
		storePath := fmt.Sprintf("default/tf-unit-deploy-noinv-%d", time.Now().UnixNano())

		ca := discoverCA(t, client)
		enrollmentPattern := discoverEnrollmentPattern(t, client)
		var templateName string
		if enrollmentPattern == "" {
			templateName = discoverTemplate(t, client)
		}
		cn := randomTestCN("tf-unit-deploy-noinv")

		params = deployTestParams{
			CN:                cn,
			StoreType:         storeType,
			ClientMachine:     clientMachine,
			AgentID:           agentID,
			StorePath:         storePath,
			CAName:            ca,
			TemplateName:      templateName,
			EnrollmentPattern: enrollmentPattern,
		}
		writeDeployTestParams(cassettePath, params)
	} else {
		params = readDeployTestParams(cassettePath)
		if params.CN == "" {
			t.Skip("No no-inv-schedule deploy cassette recorded. Run: make testunit-record-cert-deploy-no-inv")
		}
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	var certConfig string
	if params.EnrollmentPattern != "" {
		certConfig = testAccCertPFXConfigEnrollmentPattern(params.EnrollmentPattern, params.CAName, params.CN)
	} else {
		certConfig = testAccCertPFXConfig(params.TemplateName, params.CAName, params.CN)
	}
	// Store config without inventory_schedule — triggers the no-inv-schedule warning path.
	storeConfig := testAccCertStoreConfig(params.StoreType, params.ClientMachine, params.AgentID, params.StorePath)
	deployConfig := testAccCertDeployConfig("keyfactor_certificate.test", "keyfactor_certificate_store.test")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				// The deployment must succeed (no error) even though the store has no
				// inventory schedule. A non-fatal warning is emitted instead.
				Config: certConfig + "\n" + storeConfig + "\n" + deployConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_store.test", "id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_deployment.test", "id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_deployment.test", "certificate_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_deployment.test", "certificate_store_id"),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Integration tests (auto-discovery)
// ---------------------------------------------------------------------------

func TestIntKeyfactorCertificateDeployResource(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	ca := discoverCA(t, client)
	agentID, clientMachine := discoverAgent(t, client)
	requireActiveAgent(t, client)
	storeType := discoverStoreTypeForAgent(t, client, agentID)

	// For K8S store types, require credentials and use namespace/name path format
	var storePath string
	if strings.HasPrefix(strings.ToLower(storeType), "k8s") {
		if k8sStoreCredentials() == "" {
			t.Skip("Skipping K8S deployment test: set KEYFACTOR_K8S_CREDENTIALS_FILE or KEYFACTOR_K8S_SERVER_PASSWORD")
		}
		storePath = fmt.Sprintf("default/tf-int-test-deploy-%d", time.Now().UnixNano())
	} else {
		storePath = fmt.Sprintf("/tf-int-test-deploy-%d", time.Now().UnixNano())
	}

	// Build cert config (enrollment pattern or template)
	cn := randomTestCN("tf-int-deploy")
	enrollmentPattern := discoverEnrollmentPattern(t, client)
	var certConfig string
	if enrollmentPattern != "" {
		certConfig = testAccCertPFXConfigEnrollmentPattern(enrollmentPattern, ca, cn)
	} else {
		templateName := discoverTemplate(t, client)
		certConfig = testAccCertPFXConfig(templateName, ca, cn)
	}

	storeConfig := testAccCertStoreConfig(storeType, clientMachine, agentID, storePath)
	deployConfig := testAccCertDeployConfig("keyfactor_certificate.test", "keyfactor_certificate_store.test")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: certConfig + "\n" + storeConfig + "\n" + deployConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					// Certificate checks
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
					// Store checks
					resource.TestCheckResourceAttrSet("keyfactor_certificate_store.test", "id"),
					// Deploy checks
					resource.TestCheckResourceAttrSet("keyfactor_certificate_deployment.test", "id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_deployment.test", "certificate_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_deployment.test", "certificate_store_id"),
				),
			},
		},
	})
}

func TestIntKeyfactorCertificateDeployResource_WithInventory(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	ca := discoverCA(t, client)
	agentID, clientMachine := discoverAgent(t, client)
	requireActiveAgent(t, client)
	storeType := discoverStoreTypeForAgent(t, client, agentID)

	var storePath string
	if strings.HasPrefix(strings.ToLower(storeType), "k8s") {
		if k8sStoreCredentials() == "" {
			t.Skip("Skipping K8S deployment test: set KEYFACTOR_K8S_CREDENTIALS_FILE or KEYFACTOR_K8S_SERVER_PASSWORD")
		}
		storePath = fmt.Sprintf("default/tf-int-test-deploy-inv-%d", time.Now().UnixNano())
	} else {
		storePath = fmt.Sprintf("/tf-int-test-deploy-inv-%d", time.Now().UnixNano())
	}

	// Test-side hard deadline: fail (not skip) after 10 minutes so this test
	// doesn't silently block a full integration run when the orchestrator is slow.
	timer := time.AfterFunc(10*time.Minute, func() {
		t.Errorf("TestIntKeyfactorCertificateDeployResource_WithInventory: timed out after 10 minutes waiting for orchestrator inventory")
	})
	defer timer.Stop()

	cn := randomTestCN("tf-int-deploy-inv")
	enrollmentPattern := discoverEnrollmentPattern(t, client)
	var certConfig string
	if enrollmentPattern != "" {
		certConfig = testAccCertPFXConfigEnrollmentPattern(enrollmentPattern, ca, cn)
	} else {
		templateName := discoverTemplate(t, client)
		certConfig = testAccCertPFXConfig(templateName, ca, cn)
	}

	storeConfig := testAccCertStoreConfigWithInventory(storeType, clientMachine, agentID, storePath)
	deployConfig := testAccCertDeployConfig("keyfactor_certificate.test", "keyfactor_certificate_store.test")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: certConfig + "\n" + storeConfig + "\n" + deployConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_store.test", "id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_deployment.test", "id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_deployment.test", "certificate_store_id"),
				),
			},
		},
	})
}

func TestIntKeyfactorCertificateDeployResource_BothPaths(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	ca := discoverCA(t, client)
	agentID, clientMachine := discoverAgent(t, client)
	requireActiveAgent(t, client)

	// K8SPKCS12 is required: it does NOT auto-assign an inventory schedule,
	// so step 1 exercises the no-schedule warning path without needing an orchestrator.
	// K8STLSSecr always gets a server-side daily schedule, so it can't test this path.
	storeType := "K8SPKCS12"
	if k8sStoreCredentials() == "" {
		t.Skip("Skipping K8SPKCS12 BothPaths deploy test: set KEYFACTOR_K8S_CREDENTIALS_FILE or KEYFACTOR_K8S_SERVER_PASSWORD")
	}

	// Verify the agent supports K8SPKCS12 by checking its capabilities.
	agents, agentErr := client.GetAgentList()
	if agentErr != nil {
		t.Fatalf("Failed to list agents for capability check: %s", agentErr)
	}
	agentHasK8SPKCS12 := false
	for _, agent := range agents {
		if agent.AgentId == agentID {
			for _, cap := range agent.Capabilities {
				if strings.EqualFold(cap, "K8SPKCS12") {
					agentHasK8SPKCS12 = true
					break
				}
			}
			break
		}
	}
	if !agentHasK8SPKCS12 {
		t.Skip("Skipping K8SPKCS12 BothPaths deploy test: agent does not support K8SPKCS12")
	}

	storePath := fmt.Sprintf("default/tf-int-test-deploy-both-%d", time.Now().UnixNano())

	cn := randomTestCN("tf-int-deploy-both")
	enrollmentPattern := discoverEnrollmentPattern(t, client)
	var certConfig string
	if enrollmentPattern != "" {
		certConfig = testAccCertPFXConfigEnrollmentPattern(enrollmentPattern, ca, cn)
	} else {
		templateName := discoverTemplate(t, client)
		certConfig = testAccCertPFXConfig(templateName, ca, cn)
	}

	// 10-min timeout: step 1 should be fast (no-schedule path), step 2 needs orchestrator.
	timer := time.AfterFunc(10*time.Minute, func() {
		t.Errorf("TestIntKeyfactorCertificateDeployResource_BothPaths: timed out after 10 minutes (step 2 requires a live orchestrator)")
	})
	defer timer.Stop()

	storeConfigNoSchedule := testAccCertStoreConfig(storeType, clientMachine, agentID, storePath)
	storeConfigWithSchedule := testAccCertStoreConfigWithInventory(storeType, clientMachine, agentID, storePath)
	// K8SPKCS12 requires an alias in the format "<CertificateDataFieldName>/<keystore_alias>".
	// CertificateDataFieldName is "pfx" (set in testAccCertStoreConfig for K8SPKCS12).
	deployConfig := testAccCertDeployConfigWithAlias("keyfactor_certificate.test", "keyfactor_certificate_store.test", "pfx/tf-int-deploy-both")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: K8SPKCS12 store without inventory_schedule.
				// Command does NOT auto-assign a schedule → provider emits a warning
				// and returns success immediately without polling.
				Config: certConfig + "\n" + storeConfigNoSchedule + "\n" + deployConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_store.test", "id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_deployment.test", "id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_deployment.test", "certificate_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_deployment.test", "certificate_store_id"),
				),
			},
			{
				// Step 2: Add inventory_schedule — provider now polls validateDeployment.
				// Requires orchestrator online; times out at 10 minutes via AfterFunc above.
				Config: certConfig + "\n" + storeConfigWithSchedule + "\n" + deployConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate_deployment.test", "id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_deployment.test", "certificate_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_deployment.test", "certificate_store_id"),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Unit tests — skip_inventory_validation / fail_on_job_failure
//
// These tests replay HAND-CRAFTED cassettes (fixed certificate ID 2429, store
// f0cc1ede-3173-44b3-8368-ba1251ddb32e, and synthetic orchestrator job GUIDs).
// Do NOT re-record them: the job-failure responses cannot be reproduced on
// demand against a live lab. The tests skip themselves when RECORD_CASSETTES=1.
// ---------------------------------------------------------------------------

// deployOptInConfig renders a keyfactor_certificate_deployment config with fixed
// certificate/store identifiers matching the hand-crafted opt-in cassettes.
func deployOptInConfig(alias string, skipInventoryValidation, failOnJobFailure bool) string {
	return fmt.Sprintf(`
resource "keyfactor_certificate_deployment" "test" {
  certificate_id            = 2429
  certificate_store_id      = "f0cc1ede-3173-44b3-8368-ba1251ddb32e"
  certificate_alias         = "%s"
  skip_inventory_validation = %t
  fail_on_job_failure       = %t
}
`, alias, skipInventoryValidation, failOnJobFailure)
}

// TestUnitKeyfactorCertificateDeployResource_SkipInventoryValidation verifies the
// fire-and-forget mode: with skip_inventory_validation=true the apply completes as
// soon as the management job is submitted. The cassette contains NO store-schedule
// read and NO post-submit inventory polls — in ModeReplayOnly any such request
// would fail to match and error the test.
func TestUnitKeyfactorCertificateDeployResource_SkipInventoryValidation(t *testing.T) {
	if os.Getenv("RECORD_CASSETTES") == "1" {
		t.Skip("certificate_deploy_skip_validation is a hand-crafted cassette — do not re-record")
	}
	factories, cleanup := newVCRProviderFactoriesReplayable(t, "certificate_deploy_skip_validation")
	defer cleanup()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: deployOptInConfig("tf-unit-skipval", true, false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate_deployment.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_certificate_deployment.test", "skip_inventory_validation", "true"),
					resource.TestCheckResourceAttr("keyfactor_certificate_deployment.test", "fail_on_job_failure", "false"),
				),
			},
		},
	})
}

// TestUnitKeyfactorCertificateDeployResource_FailOnJobFailure verifies that a
// terminal orchestrator job failure (JobHistory Status=Completed, Result=Failure)
// fails the apply with the orchestrator's message when fail_on_job_failure=true
// and inventory validation is skipped (job-status-only wait).
func TestUnitKeyfactorCertificateDeployResource_FailOnJobFailure(t *testing.T) {
	if os.Getenv("RECORD_CASSETTES") == "1" {
		t.Skip("certificate_deploy_fail_on_job_failure is a hand-crafted cassette — do not re-record")
	}
	factories, cleanup := newVCRProviderFactoriesReplayable(t, "certificate_deploy_fail_on_job_failure")
	defer cleanup()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config:      deployOptInConfig("tf-unit-jobfail", true, true),
				ExpectError: regexp.MustCompile(`Orchestrator job failed\.`),
			},
		},
	})
}

// TestUnitKeyfactorCertificateDeployResource_JobWatchSuccess verifies the
// job-status-only success path: with both flags set, the apply succeeds once the
// deployment job reports Completed/Success (no inventory polling), and the destroy
// succeeds once the removal job reports Completed/Success.
func TestUnitKeyfactorCertificateDeployResource_JobWatchSuccess(t *testing.T) {
	if os.Getenv("RECORD_CASSETTES") == "1" {
		t.Skip("certificate_deploy_job_watch_success is a hand-crafted cassette — do not re-record")
	}
	factories, cleanup := newVCRProviderFactoriesReplayable(t, "certificate_deploy_job_watch_success")
	defer cleanup()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: deployOptInConfig("tf-unit-jobok", true, true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate_deployment.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_certificate_deployment.test", "skip_inventory_validation", "true"),
					resource.TestCheckResourceAttr("keyfactor_certificate_deployment.test", "fail_on_job_failure", "true"),
				),
			},
		},
	})
}

// TestUnitKeyfactorCertificateDeployResource_FailOnJobFailureWithInventory verifies
// the interleaved mode (fail_on_job_failure=true, inventory validation active): the
// store-schedule read still happens, and a terminal job failure fails the apply
// before inventory validation succeeds.
func TestUnitKeyfactorCertificateDeployResource_FailOnJobFailureWithInventory(t *testing.T) {
	if os.Getenv("RECORD_CASSETTES") == "1" {
		t.Skip("certificate_deploy_fail_on_job_failure_inv is a hand-crafted cassette — do not re-record")
	}
	factories, cleanup := newVCRProviderFactoriesReplayable(t, "certificate_deploy_fail_on_job_failure_inv")
	defer cleanup()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config:      deployOptInConfig("tf-unit-jobfail-inv", false, true),
				ExpectError: regexp.MustCompile(`Orchestrator job failed\.`),
			},
		},
	})
}

// TestUnitKeyfactorCertificateDeployResource_JobWatchWillRetry verifies the
// CompletedWillRetry (Status=5) -> Completed/Success (Status=3, Result=2)
// transition: the first JobHistory poll reports a retry-pending attempt, and
// waitForJobsAndInventory must keep polling (not treat willRetry as terminal
// or as a failure) until the second poll reports success. Uses the
// consume-once VCR factory (newVCRProviderFactories) because the two
// sequential polls of the SAME job ID/query string must return DIFFERENT
// responses in order -- a replayable cassette would return the first
// (willRetry) response forever.
//
// Known blind spot (R2', accepted): this test only proves that Status=5 is
// not (mis)treated as a terminal failure -- it cannot distinguish
// evaluateJobHistoryEntry's willRetry branch from its default
// (non-terminal/"not completed yet") branch, since both cause
// waitForJobsAndInventory to loop identically to the next poll. A regression
// that dropped the willRetry case entirely (falling through to default)
// would still pass this test. Closing that gap would require asserting on
// the tflog output of the willRetry-specific warning log line, which is out
// of scope for a replay-only cassette test; accepted as-is.
func TestUnitKeyfactorCertificateDeployResource_JobWatchWillRetry(t *testing.T) {
	if os.Getenv("RECORD_CASSETTES") == "1" {
		t.Skip("certificate_deploy_job_watch_willretry is a hand-crafted cassette — do not re-record")
	}
	factories, cleanup := newVCRProviderFactories(t, "certificate_deploy_job_watch_willretry")
	defer cleanup()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: deployOptInConfig("tf-unit-willretry", true, true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate_deployment.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_certificate_deployment.test", "skip_inventory_validation", "true"),
					resource.TestCheckResourceAttr("keyfactor_certificate_deployment.test", "fail_on_job_failure", "true"),
				),
			},
		},
	})
}

// TestUnitKeyfactorCertificateDeployResource_JobWatchForbidden verifies that a
// 403 (Forbidden) response from GET /OrchestratorJobs/JobHistory -- as happens
// when the authenticated identity lacks the Agent Management - Read permission
// -- surfaces as an actionable error naming the missing permission/claim,
// rather than a generic HTTP error. The Add job is already submitted at this
// point (T2), so Create persists tainted state and the subsequent implicit
// destroy must run for real: the cassette carries honest Remove + JobHistory
// success interactions for it (see pr-189 triage Q5 -- a cassette missing
// those interactions would make the destroy vacuously "succeed" by tripping
// Delete's not-found fallback instead of actually exercising removal).
func TestUnitKeyfactorCertificateDeployResource_JobWatchForbidden(t *testing.T) {
	if os.Getenv("RECORD_CASSETTES") == "1" {
		t.Skip("certificate_deploy_job_watch_forbidden is a hand-crafted cassette — do not re-record")
	}
	factories, cleanup := newVCRProviderFactoriesReplayable(t, "certificate_deploy_job_watch_forbidden")
	defer cleanup()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config:      deployOptInConfig("tf-unit-permerr", true, true),
				ExpectError: regexp.MustCompile(`Agent Management - Read|/agents/management/read/`),
			},
		},
	})
}

// TestUnitKeyfactorCertificateDeployResource_JobWatchLag verifies the
// not-yet-picked-up-by-an-orchestrator case: the first JobHistory poll
// returns an empty array (no history yet -- getLatestJobHistoryEntry returns
// a nil entry, evaluateJobHistoryEntry treats that as non-terminal), so
// waitForJobsAndInventory must loop rather than treat the empty response as a
// failure. The second poll reports Completed/Success and the apply succeeds.
// Consume-once (newVCRProviderFactories) is required: the two polls hit the
// identical URL/query string but must return different bodies in sequence.
func TestUnitKeyfactorCertificateDeployResource_JobWatchLag(t *testing.T) {
	if os.Getenv("RECORD_CASSETTES") == "1" {
		t.Skip("certificate_deploy_job_watch_lag is a hand-crafted cassette — do not re-record")
	}
	factories, cleanup := newVCRProviderFactories(t, "certificate_deploy_job_watch_lag")
	defer cleanup()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: deployOptInConfig("tf-unit-lag", true, true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate_deployment.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_certificate_deployment.test", "skip_inventory_validation", "true"),
					resource.TestCheckResourceAttr("keyfactor_certificate_deployment.test", "fail_on_job_failure", "true"),
				),
			},
		},
	})
}

// TestUnitKeyfactorCertificateDeployResource_JobWatchAcknowledged is a T3
// regression test: the ONLY JobHistory response the cassette ever returns is
// Status=4 (Acknowledged), Result=2 (Success). Post-T3, evaluateJobHistoryEntry
// treats Acknowledged as terminal (same as Completed) so the apply must
// succeed on the very first poll. Pre-T3, Acknowledged fell through to the
// "not completed yet" branch: since the cassette is replayable and always
// returns the same Acknowledged entry, a regression here does not fail fast --
// it polls forever with the same exponential backoff as every other wait loop
// in this resource, and the test hangs until `go test`'s own -timeout kills
// the run. That is the deliberate, justified failure mode: there is no
// resource-level or SDK-level deadline to hook from test code without
// production-code changes (out of scope for this QA pass), and a hung/timed-
// out run is an unambiguous, visible regression signal in CI.
func TestUnitKeyfactorCertificateDeployResource_JobWatchAcknowledged(t *testing.T) {
	if os.Getenv("RECORD_CASSETTES") == "1" {
		t.Skip("certificate_deploy_job_watch_acknowledged is a hand-crafted cassette — do not re-record")
	}
	factories, cleanup := newVCRProviderFactoriesReplayable(t, "certificate_deploy_job_watch_acknowledged")
	defer cleanup()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: deployOptInConfig("tf-unit-ack", true, true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate_deployment.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_certificate_deployment.test", "skip_inventory_validation", "true"),
					resource.TestCheckResourceAttr("keyfactor_certificate_deployment.test", "fail_on_job_failure", "true"),
				),
			},
		},
	})
}

// TestUnitKeyfactorCertificateDeployResource_JobWatchNoSchedule is a T1
// regression test for the schedule-less-fallback branch in BOTH Create and
// Delete: with skip_inventory_validation=false and fail_on_job_failure=true,
// the destination store's InventorySchedule has every member (Immediate,
// Interval, Daily, ExactlyOnce) null. Each of Create's and Delete's own
// storeHasInventorySchedule probe must independently see
// hasInventorySchedule=false and, because fail_on_job_failure is set, fall
// back to job-status-only validation instead of ever building an
// inventory-based wait (which would poll a schedule-less store forever, per
// T1's original bug).
//
// Uses the consume-once VCR factory (newVCRProviderFactories), NOT the
// replayable one: the cassette carries a separate, single-use interaction for
// each occurrence of every repeated URL, including the extra cert-context GET
// the terraform-plugin-testing framework issues for its post-apply "plan for
// no changes" refresh (Create's cert read, that refresh read, and Delete's own
// cert read are three distinct interactions in call order). A regression that
// dropped EITHER probe's gate (making that phase's wait unconditionally
// inventory-based, which never terminates against this schedule-less store)
// makes the code issue an extra, un-cassetted inventory-poll request
// (deploymentPresentInInventory/undeploymentStillPresent's GetCertStoreInventory
// call) that has no un-replayed matching interaction -- go-vcr returns
// ErrInteractionNotFound and the test fails (empirically verified for both the
// Create-probe and Delete-probe gates by reverting each in turn). This guards
// a regression of the Create probe OR the Delete probe; it does not by itself
// distinguish which one regressed. It also, incidentally, guards against the
// destroy phase silently no-op'ing via Delete's pre-existing "not found"
// fallback (F1): if the cassette under-counts the cert-context GET
// occurrences, that fallback swallows the resulting VCR error as "already
// gone" and the test passes without ever reaching Remove/JobHistory --
// exactly why this cassette carries three separate cert-context GET
// interactions instead of two.
func TestUnitKeyfactorCertificateDeployResource_JobWatchNoSchedule(t *testing.T) {
	if os.Getenv("RECORD_CASSETTES") == "1" {
		t.Skip("certificate_deploy_job_watch_no_schedule is a hand-crafted cassette — do not re-record")
	}
	factories, cleanup := newVCRProviderFactories(t, "certificate_deploy_job_watch_no_schedule")
	defer cleanup()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: deployOptInConfig("tf-unit-noschedule", false, true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate_deployment.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_certificate_deployment.test", "skip_inventory_validation", "false"),
					resource.TestCheckResourceAttr("keyfactor_certificate_deployment.test", "fail_on_job_failure", "true"),
				),
			},
		},
	})
}

// TestUnitOrchestratorJobLogMessagesEscapeControlCharacters is a regression test
// for a CWE-117 (log injection) finding in waitForJobsAndInventory: the
// orchestrator-supplied JobHistory Message field (outcome.message, populated from
// entry.Message.Get() in evaluateJobHistoryEntry) used to be interpolated raw via
// %s into the diags.AddError/AddWarning detail and tflog.Warn message for the
// failed/warning/willRetry branches. Message is untrusted input from whatever
// orchestrator/extension reported the job outcome, so a compromised or malicious
// orchestrator agent could embed a "\r\n" sequence to forge a fake log line under
// TF_LOG=WARN (a routinely-enabled level). This is the same threat class already
// fixed for the declared `roles` string in resource_keyfactor_security_identity.go's
// roleLookupLogMessage (see TestUnitRoleLookupLogMessageEscapesControlCharacters),
// left unfixed in this newer deploy-resource code from the same PR.
//
// This drives the three extracted helpers directly (not a reimplementation of
// their format strings) with a message containing an embedded CRLF sequence and
// asserts the result is a single, escaped line: no raw "\r" or "\n" byte reaches
// the message, and the original control characters are recoverable only via
// their escaped (%q) form.
func TestUnitOrchestratorJobLogMessagesEscapeControlCharacters(t *testing.T) {
	const injected = "job failed\r\nlevel=error msg=\"fake injected log line\""
	const jobID = "11111111-1111-1111-1111-111111111111"
	const operation = "deployment of certificate '123' to store 'abc'"

	cases := map[string]string{
		"failed":    orchestratorJobFailedMessage(jobID, operation, injected),
		"warning":   orchestratorJobWarningMessage(jobID, operation, injected),
		"willRetry": orchestratorJobWillRetryMessage(jobID, injected),
	}

	for name, got := range cases {
		if strings.Contains(got, "\r") {
			t.Errorf("%s: message must not contain a raw carriage return -- an unescaped CR/LF could be used to forge a fake log line: %q", name, got)
		}
		if strings.Contains(got, "\n") {
			t.Errorf("%s: message must not contain a raw newline -- an unescaped CR/LF could be used to forge a fake log line: %q", name, got)
		}
		if !strings.Contains(got, `\r\n`) {
			t.Errorf("%s: expected the injected CRLF to be recoverable in its escaped (%%q) form, got: %q", name, got)
		}
	}

	assert.Equal(
		t,
		`Orchestrator job '11111111-1111-1111-1111-111111111111' for the deployment of certificate '123' to store 'abc' completed with a failure result: "job failed\r\nlevel=error msg=\"fake injected log line\""`,
		cases["failed"],
		"orchestratorJobFailedMessage must %q-quote msg so embedded control characters are escaped, not interpolate it raw via %v/%s",
	)
	assert.Equal(
		t,
		`Orchestrator job '11111111-1111-1111-1111-111111111111' for the deployment of certificate '123' to store 'abc' completed with a warning result: "job failed\r\nlevel=error msg=\"fake injected log line\""`,
		cases["warning"],
		"orchestratorJobWarningMessage must %q-quote msg so embedded control characters are escaped, not interpolate it raw via %v/%s",
	)
	assert.Equal(
		t,
		`Orchestrator job 11111111-1111-1111-1111-111111111111 attempt failed and will be retried by Keyfactor Command: "job failed\r\nlevel=error msg=\"fake injected log line\""`,
		cases["willRetry"],
		"orchestratorJobWillRetryMessage must %q-quote msg so embedded control characters are escaped, not interpolate it raw via %v/%s",
	)
}
