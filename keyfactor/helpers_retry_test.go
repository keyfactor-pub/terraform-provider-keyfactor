package keyfactor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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
	if !errors.Is(gotErr, wantErr) {
		t.Errorf("reconcileWithRetry: got err %v, want it to wrap %v", gotErr, wantErr)
	}
	if !errors.Is(gotErr, errReconcileRaceExhausted) {
		t.Errorf("reconcileWithRetry: got err %v, want errReconcileRaceExhausted", gotErr)
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

// ---------------------------------------------------------------------------
// PR #219 review: #7 (backoff argument), #5 (distinct failure causes).
// ---------------------------------------------------------------------------

// TestUnitReconcileWithRetryBackoffUsesRaceAttempts verifies the backoff is
// driven by the number of race retries, not the total attempt count. With 429
// retries interleaved, attempt runs ahead of raceAttempts; passing attempt
// (the old behavior) would inflate the backoff to its 15s cap far too early.
func TestUnitReconcileWithRetryBackoffUsesRaceAttempts(t *testing.T) {
	t.Parallel()
	var got []int
	backoff := func(n int) time.Duration {
		got = append(got, n)
		return 0
	}
	step := func(attempt int) (reconcileOutcome, error, time.Duration) {
		// Attempts 1-3: 429 with a tiny server delay (does not count as a race).
		if attempt <= 3 {
			return reconcileRetry, fmt.Errorf("429"), time.Millisecond
		}
		return reconcileRetry, fmt.Errorf("race"), 0
	}
	ok, err := reconcileWithRetryOpts(context.Background(), step, backoff, time.Minute)
	if ok || !errors.Is(err, errReconcileRaceExhausted) {
		t.Fatalf("got ok=%v err=%v, want race exhaustion", ok, err)
	}
	var want []int
	for i := 1; i < reconcileMaxAttempts; i++ {
		want = append(want, i)
	}
	if !equalInts(got, want) {
		t.Fatalf("backoff called with %v, want %v (raceAttempts, not attempt)", got, want)
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestUnitReconcileWithRetryRateLimitDeadline verifies a 429 loop that outlives
// its budget reports errReconcileRateLimitDeadline (not race exhaustion).
func TestUnitReconcileWithRetryRateLimitDeadline(t *testing.T) {
	t.Parallel()
	step := func(attempt int) (reconcileOutcome, error, time.Duration) {
		return reconcileRetry, fmt.Errorf("server returned 429"), 5 * time.Millisecond
	}
	ok, err := reconcileWithRetryOpts(context.Background(), step, func(int) time.Duration { return 0 }, 30*time.Millisecond)
	if ok {
		t.Fatal("expected failure")
	}
	if !errors.Is(err, errReconcileRateLimitDeadline) || errors.Is(err, errReconcileRaceExhausted) {
		t.Fatalf("err = %v, want errReconcileRateLimitDeadline only", err)
	}
}

// TestUnitReconcileWithRetryContextCancelIsNotContention verifies cancellation
// is surfaced as ctx.Err(), distinct from both exhaustion errors.
func TestUnitReconcileWithRetryContextCancelIsNotContention(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	step := func(attempt int) (reconcileOutcome, error, time.Duration) {
		return reconcileRetry, fmt.Errorf("race"), 0
	}
	ok, err := reconcileWithRetryOpts(ctx, step, func(int) time.Duration { return time.Hour }, time.Minute)
	if ok || !errors.Is(err, context.Canceled) {
		t.Fatalf("got ok=%v err=%v, want context.Canceled", ok, err)
	}
	if errors.Is(err, errReconcileRaceExhausted) || errors.Is(err, errReconcileRateLimitDeadline) {
		t.Fatalf("cancellation misclassified as exhaustion: %v", err)
	}
}

// TestUnitReconcileFailureDiagnostic verifies the diagnostic wording follows
// the cause: only genuine race exhaustion is called "contention", and no
// message hard-codes an attempt count that disagrees with reconcileMaxAttempts.
func TestUnitReconcileFailureDiagnostic(t *testing.T) {
	t.Parallel()
	last := fmt.Errorf("last step error")
	cases := []struct {
		name            string
		err             error
		wantSummary     string
		wantDetail      string
		wantNotContains string
	}{
		{
			name:        "race exhausted",
			err:         fmt.Errorf("%w (%d attempts): %w", errReconcileRaceExhausted, reconcileMaxAttempts, last),
			wantSummary: "(concurrent write contention)",
			wantDetail:  fmt.Sprintf("(%d attempts)", reconcileMaxAttempts),
		},
		{
			name:            "rate limit deadline",
			err:             fmt.Errorf("%w (1h0m0s): %w", errReconcileRateLimitDeadline, last),
			wantSummary:     "(rate limited)",
			wantDetail:      "429",
			wantNotContains: "contention",
		},
		{
			name:            "context canceled",
			err:             context.Canceled,
			wantSummary:     "(operation cancelled or timed out)",
			wantDetail:      "context canceled",
			wantNotContains: "contention",
		},
		{
			name:            "context deadline",
			err:             context.DeadlineExceeded,
			wantSummary:     "(operation cancelled or timed out)",
			wantNotContains: "contention",
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			summary, detail := reconcileFailureDiagnostic("adding thing", "add thing", "thing's roles", c.err)
			if !strings.Contains(summary, c.wantSummary) {
				t.Errorf("summary %q missing %q", summary, c.wantSummary)
			}
			if c.wantDetail != "" && !strings.Contains(detail, c.wantDetail) {
				t.Errorf("detail %q missing %q", detail, c.wantDetail)
			}
			if c.wantNotContains != "" && (strings.Contains(summary, c.wantNotContains) || strings.Contains(detail, c.wantNotContains)) {
				t.Errorf("diagnostic %q / %q must not mention %q", summary, detail, c.wantNotContains)
			}
		})
	}
}

// TestUnitRoleBindingSchemaAttemptCountMatchesConstant guards the schema text
// against drifting from reconcileMaxAttempts again.
func TestUnitRoleBindingSchemaAttemptCountMatchesConstant(t *testing.T) {
	t.Parallel()
	schema, diags := resourceEnrollmentPatternRoleBindingType{}.GetSchema(context.Background())
	if diags.HasError() {
		t.Fatalf("GetSchema: %+v", diags)
	}
	want := fmt.Sprintf("up to %d attempts", reconcileMaxAttempts)
	if !strings.Contains(schema.MarkdownDescription, want) {
		t.Fatalf("schema description does not contain %q", want)
	}
}
