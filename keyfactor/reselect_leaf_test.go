package keyfactor

// Regression tests for reselectLeafFromChain : the provider-side guard that
// re-derives the true end-entity leaf from the combined leaf+chain set,
// independent of how Keyfactor Command ordered the chain or which client path
// (P7B findLeafCert, PFX DecodeChain fallback, or PEM UnpackPEM's positional
// certificates[0]) produced the initial pick.
//
// Background: v2.8.1 fixed the P7B path (findLeafCert) and the PFX localKeyID
// path (go-pkcs12 v0.4.0), but the PEM-unpack path (api.UnpackPEM) still treats
// certificates[0] as the leaf and returns the ROOT on a root-first bundle, and
// DecodeChain falls back to the LAST cert (the root in a leaf-first PFX). This
// guard makes the provider robust regardless.
//
// Run with:
//
//	go test -run "TestReselectLeaf|TestUnpackPEM" -v ./keyfactor/...

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"

	api "github.com/Keyfactor/keyfactor-go-client/v3/api"
)

func certToPEM(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

// parsePEMLeafCN decodes the first cert in pemStr and returns (CN, IsCA).
func parsePEMLeafCN(t *testing.T, pemStr string) (string, bool) {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatalf("not a PEM cert: %q", pemStr)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return c.Subject.CommonName, c.IsCA
}

// TestReselectLeafFromChain verifies the guard returns the end-entity leaf for
// every chain ordering, including the ones that fooled the upstream selectors.
func TestReselectLeafFromChain(t *testing.T) {
	root, intermediate, leaf, _ := buildChain(t, true)
	ctx := context.Background()

	cases := []struct {
		name     string
		leafPEM  string
		chainPEM string
	}{
		{
			// Correct input : must stay correct (no churn).
			name:     "already-leaf-first",
			leafPEM:  certToPEM(leaf),
			chainPEM: certToPEM(intermediate) + certToPEM(root),
		},
		{
			// UnpackPEM root-first bug: certificates[0]=root, rest=[int,leaf].
			name:     "unpackpem-root-first",
			leafPEM:  certToPEM(root),
			chainPEM: certToPEM(intermediate) + certToPEM(leaf),
		},
		{
			// DecodeChain fallback: last cert (root) returned as leaf, rest=[leaf,int].
			name:     "decodechain-fallback-root-as-leaf",
			leafPEM:  certToPEM(root),
			chainPEM: certToPEM(leaf) + certToPEM(intermediate),
		},
		{
			// Two-cert chain, root mislabeled as leaf.
			name:     "two-cert-root-as-leaf",
			leafPEM:  certToPEM(root),
			chainPEM: certToPEM(leaf),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotLeaf, _ := reselectLeafFromChain(ctx, tc.leafPEM, tc.chainPEM)
			cn, isCA := parsePEMLeafCN(t, gotLeaf)
			if isCA {
				t.Errorf("reselected leaf is a CA (CN=%q) : guard failed", cn)
			}
			if cn != "leaf.example.com" {
				t.Errorf("reselected leaf CN=%q, want %q", cn, "leaf.example.com")
			}
		})
	}
}

// TestReselectLeafFromChain_NoChange confirms inputs are returned unchanged when
// a unique leaf cannot be determined (single cert / all self-signed).
func TestReselectLeafFromChain_NoChange(t *testing.T) {
	root, _, leaf, _ := buildChain(t, false)
	ctx := context.Background()

	// Single cert: nothing to re-select.
	l, c := reselectLeafFromChain(ctx, certToPEM(leaf), "")
	if l != certToPEM(leaf) || c != "" {
		t.Errorf("single-cert input was modified")
	}

	// Self-signed root alone: returned unchanged (no leaf distinguishable).
	l2, _ := reselectLeafFromChain(ctx, certToPEM(root), "")
	if l2 != certToPEM(root) {
		t.Errorf("single self-signed input was modified")
	}
}

// TestUnpackPEM_RootFirstReturnsRoot documents the upstream go-client bug that
// the provider guard compensates for: api.UnpackPEM returns the ROOT as the
// leaf when the PEM bundle is root-first. If this ever starts passing (i.e.
// UnpackPEM is fixed upstream), the guard becomes belt-and-suspenders.
func TestUnpackPEM_RootFirstReturnsRoot(t *testing.T) {
	root, intermediate, leaf, _ := buildChain(t, true)
	bundle := certToPEM(root) + certToPEM(intermediate) + certToPEM(leaf)
	_, certificate, _, err := api.UnpackPEM(bundle, "")
	if err != nil {
		t.Fatalf("UnpackPEM error: %v", err)
	}
	cn, isCA := parsePEMLeafCN(t, certificate)
	if !isCA || cn != "Test Root CA" {
		t.Logf("NOTE: api.UnpackPEM no longer returns the root (CN=%q IsCA=%v) : upstream may be fixed", cn, isCA)
		return
	}
	t.Logf("confirmed upstream behavior: UnpackPEM root-first returns CN=%q (IsCA=%v); provider guard compensates", cn, isCA)
}
