// ---------------------------------------------------------------------------
// Wire-level regression: container assignment preservation
// ---------------------------------------------------------------------------
//
// This file adds a cassette-based TestUnit* test that proves, at the wire
// level and through the provider's full Update() code path, the fix landed
// in commit 0f6090b ("fix(cert-store): preserve existing container
// assignment when config declares no name").
//
// Unlike the direct-function unit tests in
// resource_keyfactor_certificate_store_unit_test.go (which call
// resolveContainerAssignmentForUpdate/containerNameArgPointer directly), this
// test drives a real two-step Terraform lifecycle through
// resource.UnitTest and asserts the literal JSON body of the PUT request
// that resourceCertificateStore.Update() sends to /KeyfactorAPI/CertificateStores.
//
// Scenario (mirrors the original customer-reported repro):
//  1. Create a keyfactor_certificate_store with neither application_name nor
//     container_name in config.
//  2. Out-of-band (bypassing Terraform entirely): assign the store to an
//     existing lab container/application via the real
//     PUT /CertificateStores/AssignContainer endpoint. This step only runs
//     during cassette recording (RECORD_CASSETTES=1) : it is a genuine,
//     unrecorded network call against the lab, simulating a portal-driven
//     assignment that Terraform never declared.
//  3. Apply an unrelated attribute change (inventory_schedule) with a config
//     that still declares no application_name/container_name.
//  4. Assert: the apply succeeds with no "inconsistent result after apply";
//     container_id in the final state matches the out-of-band assignment;
//     and : the wire-level check : the captured PUT request body sent
//     during step 3's Update() contains "ContainerId":<N> for the preserved,
//     nonzero container ID.
//
// The wire-level assertion works in pure replay mode (no network, CI-safe)
// by wrapping the VCR recorder's http.RoundTripper with a body-capturing
// shim. The go-vcr recorder does not touch/hook into request bodies at all
// in ModeReplayOnly (see requestHandler's early return for that mode), so
// the request body reaching our capturing transport is exactly what
// resourceCertificateStore.Update() constructed and serialized this test
// run : not anything baked into the cassette file.
package keyfactor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	sdkclient "github.com/Keyfactor/keyfactor-go-client-sdk/v25"
	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"gopkg.in/dnaeon/go-vcr.v4/pkg/recorder"
)

// capturedPUTRequest holds a single PUT request's path and raw JSON body as
// observed at the transport layer, before it reaches the VCR recorder.
type capturedPUTRequest struct {
	Path string
	Body []byte
}

// bodyCapturingRoundTripper wraps another http.RoundTripper (the VCR
// recorder, in this file's usage) and records the path + body of every PUT
// request that passes through it, without altering request/response
// behavior. This lets a test assert on the exact JSON the provider's
// resource code constructed and sent, independent of anything recorded in
// the cassette itself.
type bodyCapturingRoundTripper struct {
	underlying http.RoundTripper

	mu   sync.Mutex
	puts []capturedPUTRequest
}

func (b *bodyCapturingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	var bodyCopy []byte
	if req.Body != nil {
		data, err := io.ReadAll(req.Body)
		if err == nil {
			bodyCopy = data
			req.Body = io.NopCloser(bytes.NewReader(data))
		}
	}

	resp, err := b.underlying.RoundTrip(req)

	if req.Method == http.MethodPut {
		b.mu.Lock()
		b.puts = append(b.puts, capturedPUTRequest{Path: req.URL.Path, Body: bodyCopy})
		b.mu.Unlock()
	}

	return resp, err
}

// capturedPUTBodiesTo returns the raw JSON bodies of every captured PUT
// request whose path contains pathSubstr.
func (b *bodyCapturingRoundTripper) capturedPUTBodiesTo(pathSubstr string) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for _, p := range b.puts {
		if strings.Contains(p.Path, pathSubstr) {
			out = append(out, string(p.Body))
		}
	}
	return out
}

// newVCRProviderFactoriesCapturingPUTBodies is a variant of
// newVCRProviderFactoriesOpts (test_helpers_test.go) that, in replay mode,
// wraps the recorder's http.RoundTripper with a bodyCapturingRoundTripper so
// the test can assert on the literal outgoing request bodies. In recording
// mode it delegates entirely to newVCRProviderFactories (no capture needed :
// this test's wire-level assertion is skipped when RECORD_CASSETTES=1).
func newVCRProviderFactoriesCapturingPUTBodies(t *testing.T, cassetteName string) (map[string]func() (tfprotov6.ProviderServer, error), func(), *bodyCapturingRoundTripper) {
	t.Helper()

	if os.Getenv("RECORD_CASSETTES") == "1" {
		factories, cleanup := newVCRProviderFactories(t, cassetteName)
		return factories, cleanup, nil
	}

	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)
	matcher := makeVCRMatcher()
	info := readCassetteInfo(cassettePath)

	r, err := recorder.New(cassettePath,
		recorder.WithMode(recorder.ModeReplayOnly),
		recorder.WithMatcher(matcher),
		recorder.WithSkipRequestLatency(true),
	)
	if err != nil {
		t.Skipf("No cassette found for %q. Run with RECORD_CASSETTES=1 against a live lab to record.", cassetteName)
	}

	capture := &bodyCapturingRoundTripper{underlying: r}
	wrappedClient := &http.Client{Transport: capture}

	vcrAuth := &vcrAuthConfig{
		httpClient: wrappedClient,
		server: &auth_providers.Server{
			Host:          info.Host,
			APIPath:       info.APIPath,
			Username:      "vcr-test-user",
			Password:      "Vcrtestpass1!",
			SkipTLSVerify: true,
		},
	}

	p := &provider{testAuth: vcrAuth}
	factories := map[string]func() (tfprotov6.ProviderServer, error){
		"keyfactor": providerserver.NewProtocol6WithError(p),
	}
	cleanup := func() {
		if stopErr := r.Stop(); stopErr != nil {
			t.Logf("Warning: VCR recorder stop error: %s", stopErr)
		}
	}
	return factories, cleanup, capture
}

// TestUnitKeyfactorCertificateStoreResource_UpdatePreservesOutOfBandContainerAssignment
// is the wire-level regression test. See the file-level
// doc comment above for the full scenario.
//
// To record the cassette against the kfclab lab:
//
//	KEYFACTOR_ENV_FILE=~/.env_kfclab RECORD_CASSETTES=1 \
//	  make testunit-record-one TEST_NAME=TestUnitKeyfactorCertificateStoreResource_UpdatePreservesOutOfBandContainerAssignment
func TestUnitKeyfactorCertificateStoreResource_UpdatePreservesOutOfBandContainerAssignment(t *testing.T) {
	cassetteName := "certificate_store_resource_container_preservation_update"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var storeType, clientMachine, agentID, storePath, containerName string
	var containerID int

	if os.Getenv("RECORD_CASSETTES") == "1" {
		client := newTestClient(t)
		agentID, clientMachine = discoverAgent(t, client)
		storeType = discoverStoreTypeForAgent(t, client, agentID)
		storePath = fmt.Sprintf("default/tf-unit-gh175-%d", time.Now().UnixNano())

		containerName = discoverApplication(t, client)
		if containerName == "" {
			t.Skip("No application/container available in the lab : cannot record the container preservation regression cassette")
		}
		ct, err := client.GetStoreContainer(containerName)
		if err != nil || ct == nil || ct.Id == nil {
			t.Fatalf("failed to resolve container ID for %q: %v", containerName, err)
		}
		containerID = *ct.Id

		writeStoreTestParams(cassettePath, storeTestParams{
			StoreType:     storeType,
			ClientMachine: clientMachine,
			AgentID:       agentID,
			StorePath:     storePath,
			ContainerName: containerName,
			ContainerID:   containerID,
		})
	} else {
		params := readStoreTestParams(cassettePath)
		storeType = params.StoreType
		clientMachine = params.ClientMachine
		agentID = params.AgentID
		storePath = params.StorePath
		containerName = params.ContainerName
		containerID = params.ContainerID
		if containerName == "" || containerID == 0 {
			t.Skip("cassette params missing container info : record the cassette first (see RECORD_CASSETTES instructions above)")
		}
	}

	factories, cleanup, capture := newVCRProviderFactoriesCapturingPUTBodies(t, cassetteName)
	defer cleanup()

	resourceName := "keyfactor_certificate_store.test"
	var storeGUID string

	// assignContainerOutOfBand performs a REAL, UNRECORDED PUT
	// /CertificateStores/AssignContainer call directly against the lab,
	// bypassing Terraform and the VCR recorder entirely. This simulates a
	// container/application assignment made out-of-band (e.g. via the
	// Command portal) that Terraform's own config never declared : the
	// exact precondition for the bug this test guards against. It only runs while recording;
	// in replay mode it is a no-op so the test stays network-free.
	assignContainerOutOfBand := func() {
		if os.Getenv("RECORD_CASSETTES") != "1" {
			return
		}
		if storeGUID == "" {
			t.Fatalf("cannot assign container out-of-band: store GUID was not captured from step 1 state")
		}

		client := newTestClient(t)
		sdk := sdkclient.NewAPIClientWithAuth(client.AuthClient)

		cid32 := int32(containerID)
		assignment := v1.CSSCMSDataModelModelsContainerAssignment{
			CertStoreContainerId: &cid32,
			KeystoreIds:          []string{storeGUID},
		}

		_, httpResp, err := sdk.V1.CertificateStoreApi.
			NewUpdateCertificateStoresAssignContainerRequest(context.Background()).
			CSSCMSDataModelModelsContainerAssignment(assignment).
			Execute()
		if err != nil {
			body := ""
			if httpResp != nil && httpResp.Body != nil {
				if b, rerr := io.ReadAll(httpResp.Body); rerr == nil {
					body = string(b)
				}
			}
			t.Fatalf("out-of-band AssignContainer call failed: %v (response body: %s)", err, body)
		}
		t.Logf(
			"Out-of-band: assigned store %s to container %d (%q) via PUT /CertificateStores/AssignContainer, bypassing Terraform entirely",
			storeGUID, containerID, containerName,
		)
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				// Step 1: create the store declaring NEITHER application_name
				// nor container_name.
				Config: testAccCertStoreConfig(storeType, clientMachine, agentID, storePath),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckNoResourceAttr(resourceName, "application_name"),
					resource.TestCheckNoResourceAttr(resourceName, "container_name"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[resourceName]
						if !ok {
							return fmt.Errorf("not found: %s", resourceName)
						}
						storeGUID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Step 2: out-of-band assignment happens in PreConfig, before
				// this step's refresh/plan/apply : mirroring the customer
				// repro exactly. The config here changes only
				// inventory_schedule and STILL declares no
				// application_name/container_name. Before the fix in commit
				// 0f6090b, resourceCertificateStore.Update() would resolve
				// containerId to 0 here (config declares no name) and
				// intToPointer(0) would drop ContainerId from the PUT body
				// entirely (json:"ContainerId,omitempty"), so Command would
				// clear the out-of-band assignment and Terraform would then
				// fail with "Provider produced inconsistent result after
				// apply" on .container_id.
				PreConfig: assignContainerOutOfBand,
				Config:    testAccCertStoreConfigWithInventory(storeType, clientMachine, agentID, storePath),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "container_id", strconv.Itoa(containerID)),
					resource.TestCheckResourceAttr(resourceName, "inventory_schedule", "Daily at 12:00:00"),
				),
			},
		},
	})

	if os.Getenv("RECORD_CASSETTES") == "1" {
		return
	}

	// ---------------------------------------------------------------------
	// Wire-level regression assertion.
	// ---------------------------------------------------------------------
	//
	// The above resource.UnitTest run already proves state consistency (no
	// "inconsistent result after apply" : the test would have failed
	// outright otherwise) and that container_id survived the update. This
	// section additionally proves WHY: the literal PUT request body sent to
	// /KeyfactorAPI/CertificateStores during step 2's Update() call must
	// contain the preserved, nonzero ContainerId. If
	// resolveContainerAssignmentForUpdate/containerNameArgPointer ever
	// regress to the pre-fix behavior, containerId resolves to 0 and
	// intToPointer(0) drops the field from the JSON body entirely : this
	// assertion is what would catch that at the wire level.
	putBodies := capture.capturedPUTBodiesTo("CertificateStores")
	if len(putBodies) == 0 {
		t.Fatalf(
			"regression check: expected at least one PUT request to /KeyfactorAPI/CertificateStores " +
				"(resourceCertificateStore.Update()) to have been captured during step 2's apply, but none were",
		)
	}

	wantFragment := fmt.Sprintf(`"ContainerId":%d`, containerID)
	found := false
	for _, body := range putBodies {
		if strings.Contains(body, wantFragment) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf(
			"regression: expected the Update() PUT body to /KeyfactorAPI/CertificateStores to contain %q "+
				"(the container assignment preserved from state when config declares no application_name/container_name), "+
				"but none of the captured PUT bodies did: %v : this is exactly the failure mode of the bug: "+
				"resolveContainerAssignmentForUpdate/containerNameArgPointer resolved containerId to 0, "+
				"intToPointer(0) dropped ContainerId from the wire (json:\"ContainerId,omitempty\"), "+
				"and Command would silently clear a real, live out-of-band container assignment",
			wantFragment, putBodies,
		)
	}
}
