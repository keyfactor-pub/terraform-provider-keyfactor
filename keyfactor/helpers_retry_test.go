package keyfactor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestUnitParseRetryAfterSeconds verifies that a delay-seconds Retry-After
// header is parsed correctly.
func TestUnitParseRetryAfterSeconds(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{"Retry-After": []string{"30"}},
	}
	got := parseRetryAfter(resp)
	want := 30 * time.Second
	if got != want {
		t.Errorf("parseRetryAfter(30s): got %s, want %s", got, want)
	}
}

// TestUnitParseRetryAfterHTTPDate verifies that an HTTP-date Retry-After
// header is parsed and produces a positive, bounded duration.
func TestUnitParseRetryAfterHTTPDate(t *testing.T) {
	// Use a date 60 seconds in the future.
	future := time.Now().Add(60 * time.Second)
	dateStr := future.UTC().Format(http.TimeFormat)
	resp := &http.Response{
		Header: http.Header{"Retry-After": []string{dateStr}},
	}
	got := parseRetryAfter(resp)
	// Allow ±2s of clock drift in the test.
	if got < 58*time.Second || got > 62*time.Second {
		t.Errorf("parseRetryAfter(HTTP-date +60s): got %s, want ~60s", got)
	}
}

// TestUnitParseRetryAfterMissing verifies that an absent Retry-After header
// returns 0.
func TestUnitParseRetryAfterMissing(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}
	got := parseRetryAfter(resp)
	if got != 0 {
		t.Errorf("parseRetryAfter(no header): got %s, want 0", got)
	}
}

// TestUnitParseRetryAfterNilResponse verifies that a nil *http.Response
// returns 0 without panicking.
func TestUnitParseRetryAfterNilResponse(t *testing.T) {
	got := parseRetryAfter(nil)
	if got != 0 {
		t.Errorf("parseRetryAfter(nil): got %s, want 0", got)
	}
}

// TestUnitParseRetryAfterGarbage verifies that an unparseable Retry-After
// value returns 0.
func TestUnitParseRetryAfterGarbage(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{"Retry-After": []string{"not-a-duration"}},
	}
	got := parseRetryAfter(resp)
	if got != 0 {
		t.Errorf("parseRetryAfter(garbage): got %s, want 0", got)
	}
}

// TestUnitParseRetryAfterPastDate verifies that an HTTP-date already in the
// past returns 0 (not a negative duration).
func TestUnitParseRetryAfterPastDate(t *testing.T) {
	past := time.Now().Add(-10 * time.Second)
	dateStr := past.UTC().Format(http.TimeFormat)
	resp := &http.Response{
		Header: http.Header{"Retry-After": []string{dateStr}},
	}
	got := parseRetryAfter(resp)
	if got != 0 {
		t.Errorf("parseRetryAfter(past date): got %s, want 0", got)
	}
}

// TestUnitReconcileBackoffCap verifies that reconcileBackoff caps at 15s for
// high attempt numbers (the plan raised the cap from 2s to 15s).
func TestUnitReconcileBackoffCap(t *testing.T) {
	// At attempt 8+, the uncapped value is 150ms * 2^7 = 19.2s > 15s cap.
	for _, attempt := range []int{8, 10, 100} {
		got := reconcileBackoff(attempt)
		if got > 15*time.Second {
			t.Errorf("reconcileBackoff(%d): got %s > 15s cap", attempt, got)
		}
	}
}

// TestUnitReconcileBackoffEarlyAttemptsUnchanged verifies that early attempts
// still use the fast path (well below 2s, preserving the original behavior for
// the common small-pattern case).
func TestUnitReconcileBackoffEarlyAttemptsUnchanged(t *testing.T) {
	// Attempt 1 should be ≤ 150ms (base delay, no jitter beyond base).
	got := reconcileBackoff(1)
	if got > 150*time.Millisecond {
		t.Errorf("reconcileBackoff(1): got %s, want ≤150ms", got)
	}
}

// TestUnitReconcileMaxAttemptsIs8 verifies the constant was updated.
func TestUnitReconcileMaxAttemptsIs8(t *testing.T) {
	if reconcileMaxAttempts != 8 {
		t.Errorf("reconcileMaxAttempts: got %d, want 8", reconcileMaxAttempts)
	}
}

// TestUnitReconcileWithRetryHonorsServerDelay verifies that when the step
// function returns a non-zero serverDelay, reconcileWithRetry sleeps for
// at least that duration before retrying.
func TestUnitReconcileWithRetryHonorsServerDelay(t *testing.T) {
	const serverSleep = 50 * time.Millisecond

	callCount := 0
	step := func(attempt int) (reconcileOutcome, error, time.Duration) {
		callCount++
		if attempt == 1 {
			// First attempt: tell the loop to wait serverSleep before retrying.
			return reconcileRetry, fmt.Errorf("transient"), serverSleep
		}
		// Second attempt: succeed.
		return reconcileDone, nil, 0
	}

	start := time.Now()
	ok, err := reconcileWithRetry(context.Background(), step)
	elapsed := time.Since(start)

	if !ok {
		t.Errorf("reconcileWithRetry: expected success, got ok=false err=%v", err)
	}
	if callCount != 2 {
		t.Errorf("reconcileWithRetry: expected 2 calls, got %d", callCount)
	}
	if elapsed < serverSleep {
		t.Errorf("reconcileWithRetry: elapsed %s < serverDelay %s — server delay was not honored", elapsed, serverSleep)
	}
}

// TestUnitReconcileWithRetryFallsBackToBackoff verifies that when the step
// returns serverDelay==0, the normal reconcileBackoff is used instead of
// sleeping zero time (i.e., at least some positive sleep occurs).
func TestUnitReconcileWithRetryFallsBackToBackoff(t *testing.T) {
	callCount := 0
	step := func(attempt int) (reconcileOutcome, error, time.Duration) {
		callCount++
		if attempt == 1 {
			// Zero serverDelay — should fall back to reconcileBackoff(1) ≤ 150ms.
			return reconcileRetry, fmt.Errorf("race"), 0
		}
		return reconcileDone, nil, 0
	}

	start := time.Now()
	ok, _ := reconcileWithRetry(context.Background(), step)
	elapsed := time.Since(start)

	if !ok {
		t.Error("reconcileWithRetry: expected success")
	}
	// reconcileBackoff(1) returns between 75ms and 150ms; at minimum
	// some non-zero time should have passed.
	if elapsed < 1*time.Millisecond {
		t.Errorf("reconcileWithRetry: elapsed %s suspiciously short — backoff may not have fired", elapsed)
	}
}

// TestUnitReconcileWithRetryRaceExhausted verifies that the race-condition path
// (serverDelay == 0) gives up after exactly reconcileMaxAttempts calls and
// returns the last error.
//
// NOTE: This test sleeps through real backoff (up to ~19s total) because
// the race-condition path uses reconcileBackoff. t.Parallel() is set so it
// does not delay other unit tests.
func TestUnitReconcileWithRetryRaceExhausted(t *testing.T) {
	t.Parallel()
	callCount := 0
	wantErr := fmt.Errorf("persistent race")
	step := func(attempt int) (reconcileOutcome, error, time.Duration) {
		callCount++
		// serverDelay == 0 → race-condition path, capped at reconcileMaxAttempts.
		return reconcileRetry, wantErr, 0
	}

	ok, gotErr := reconcileWithRetry(context.Background(), step)

	if ok {
		t.Error("reconcileWithRetry: expected failure, got ok=true")
	}
	if gotErr != wantErr {
		t.Errorf("reconcileWithRetry: got err %v, want %v", gotErr, wantErr)
	}
	if callCount != reconcileMaxAttempts {
		t.Errorf("reconcileWithRetry: called step %d times, want %d", callCount, reconcileMaxAttempts)
	}
}

// TestUnitReconcileWithRetry429ContextCancel verifies that a 429 retry loop
// respects context cancellation and returns ctx.Err() promptly.
func TestUnitReconcileWithRetry429ContextCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	wantErr := fmt.Errorf("rate limited")
	step := func(attempt int) (reconcileOutcome, error, time.Duration) {
		// Tiny server delay so the 429 path is exercised without long sleep.
		return reconcileRetry, wantErr, 10 * time.Millisecond
	}

	ok, gotErr := reconcileWithRetry(ctx, step)

	if ok {
		t.Error("reconcileWithRetry: expected failure on ctx cancel, got ok=true")
	}
	if gotErr == nil {
		t.Error("reconcileWithRetry: expected non-nil error on ctx cancel")
	}
}

// TestUnitParseRetryAfterFromHTTPRecorder uses httptest to simulate a real
// 429 response with Retry-After and verifies end-to-end parsing.
func TestUnitParseRetryAfterFromHTTPRecorder(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := http.Get(srv.URL) //nolint:noctx // test helper
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()

	got := parseRetryAfter(resp)
	want := 5 * time.Second
	if got != want {
		t.Errorf("parseRetryAfter(live 429): got %s, want %s", got, want)
	}
}

// TestUnitMaxClientTimeoutSecondsIsOneHour verifies that MaxClientTimeoutSeconds
// equals one hour, keeping it in sync with the provider's global HTTP client
// timeout ceiling. reconcileWithRetry uses this value as the overall 429 retry
// deadline — update the constant (and re-evaluate the retry budget) if the
// provider timeout ceiling changes.
func TestUnitMaxClientTimeoutSecondsIsOneHour(t *testing.T) {
	got := time.Duration(MaxClientTimeoutSeconds) * time.Second
	want := 1 * time.Hour
	if got != want {
		t.Errorf("MaxClientTimeoutSeconds: got %s, want %s; update the constant if the provider timeout ceiling changed", got, want)
	}
}
