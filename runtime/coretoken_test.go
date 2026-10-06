package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// iamExchangeFixture is a real TLS server speaking the documented IAM
// workload token exchange (POST /auth/plugin-workload-token, v1alpha). It is
// the protocol peer of these tests, not a stand-in for runtime internals: it
// checks every request against the contract and answers like IAM does.
type iamExchangeFixture struct {
	t      *testing.T
	server *httptest.Server
	caFile string

	mu       sync.Mutex
	script   []int // statuses answered in order before fallback applies
	fallback int
	lifetime int
	subjects []string
	issued   []string
}

func newIAMExchangeFixture(t *testing.T) *iamExchangeFixture {
	t.Helper()
	f := &iamExchangeFixture{t: t, fallback: http.StatusOK, lifetime: 900}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	f.caFile = filepath.Join(t.TempDir(), "gateway-ca.crt")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw})
	if err := os.WriteFile(f.caFile, certificate, 0444); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *iamExchangeFixture) serve(w http.ResponseWriter, r *http.Request) {
	var body struct {
		GrantType        string `json:"grant_type"`
		SubjectToken     string `json:"subject_token"`
		SubjectTokenType string `json:"subject_token_type"`
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if r.Method != http.MethodPost || r.URL.Path != tokenExchangePath || r.Header.Get("Content-Type") != "application/json" ||
		decoder.Decode(&body) != nil || body.GrantType != tokenExchangeGrant || body.SubjectTokenType != jwtTokenType || body.SubjectToken == "" {
		f.t.Errorf("runtime broke the exchange contract: %s %s", r.Method, r.URL.Path)
		answer(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.subjects = append(f.subjects, body.SubjectToken)
	status := f.fallback
	if len(f.script) > 0 {
		status, f.script = f.script[0], f.script[1:]
	}
	switch status {
	case http.StatusOK:
		random := make([]byte, 33)
		_, _ = rand.Read(random)
		token := "PWT-" + base64.RawURLEncoding.EncodeToString(random)
		f.issued = append(f.issued, token)
		w.Header().Set("Cache-Control", "no-store")
		answer(w, status, map[string]any{"access_token": token, "issued_token_type": accessTokenType, "token_type": "Bearer", "expires_in": f.lifetime})
	case http.StatusBadRequest:
		answer(w, status, map[string]any{"error": "invalid_grant", "message": "the subject token cannot be exchanged"})
	case http.StatusServiceUnavailable:
		answer(w, status, map[string]any{"error": "temporarily_unavailable", "message": "the workload token issuer keys are unavailable"})
	default:
		answer(w, status, map[string]any{"error": "unexpected"})
	}
}

func answer(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (f *iamExchangeFixture) configure(fallback int, script ...int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fallback, f.script = fallback, script
}

func (f *iamExchangeFixture) setLifetime(seconds int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lifetime = seconds
}

func (f *iamExchangeFixture) seen() (subjects, issued []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.subjects), slices.Clone(f.issued)
}

// projectedToken mimics kubelet's projected volume: token is a symlink into
// a timestamped directory selected by the ..data symlink, swapped atomically.
type projectedToken struct {
	directory string
	path      string
	version   int
}

func newProjectedToken(t *testing.T, content string) *projectedToken {
	t.Helper()
	p := &projectedToken{directory: t.TempDir()}
	p.path = filepath.Join(p.directory, "token")
	p.rotate(t, content)
	if err := os.Symlink(filepath.Join("..data", "token"), p.path); err != nil {
		t.Fatal(err)
	}
	return p
}

func (p *projectedToken) rotate(t *testing.T, content string) {
	t.Helper()
	p.version++
	version := fmt.Sprintf("..2026_10_06_%02d", p.version)
	if err := os.Mkdir(filepath.Join(p.directory, version), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.directory, version, "token"), []byte(content), 0440); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(p.directory, "..data_tmp")
	if err := os.Symlink(version, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(link, filepath.Join(p.directory, "..data")); err != nil {
		t.Fatal(err)
	}
}

// fakeClock lets a test decide when each refresher wait ends.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []fakeTimer
	waits  chan time.Duration
}

type fakeTimer struct {
	at   time.Time
	fire chan time.Time
}

// newFakeClock starts at the real time, so check-core-token, which reads the
// real clock, judges the tokens the refresher writes under this clock.
func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Now().UTC().Truncate(time.Second), waits: make(chan time.Duration, 256)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	fire := make(chan time.Time, 1)
	c.timers = append(c.timers, fakeTimer{at: c.now.Add(d), fire: fire})
	c.mu.Unlock()
	c.waits <- d
	return fire
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	pending := c.timers[:0]
	for _, timer := range c.timers {
		if timer.at.After(c.now) {
			pending = append(pending, timer)
		} else {
			timer.fire <- c.now
		}
	}
	c.timers = pending
}

// nextWait returns the duration of the refresher's next sleep.
func (c *fakeClock) nextWait(t *testing.T) time.Duration {
	t.Helper()
	select {
	case d := <-c.waits:
		return d
	case <-time.After(10 * time.Second):
		t.Fatal("refresher did not wait")
		return 0
	}
}

type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

type refresherRun struct {
	fixture   *iamExchangeFixture
	projected *projectedToken
	clock     *fakeClock
	tokenFile string
	logs      *lockedBuffer
	done      chan error
	stop      context.CancelFunc
}

// startRefresher runs the real refresher against the fixture over TLS. Jitter
// is the identity so backoff steps are exact; equalJitter is tested apart.
func startRefresher(t *testing.T, fixture *iamExchangeFixture, prepare func(tokenFile string, now time.Time)) *refresherRun {
	t.Helper()
	run := &refresherRun{
		fixture: fixture, projected: newProjectedToken(t, "projected-sa-token-1"), clock: newFakeClock(),
		tokenFile: filepath.Join(t.TempDir(), "token"), logs: &lockedBuffer{}, done: make(chan error, 1),
	}
	if prepare != nil {
		prepare(run.tokenFile, run.clock.Now())
	}
	exchange, err := newTokenExchange(fixture.server.URL, run.projected.path, fixture.caFile)
	if err != nil {
		t.Fatal(err)
	}
	refresher := coreTokenRefresher{
		exchange: exchange.exchange, tokenFile: run.tokenFile, clock: run.clock,
		jitter: func(d time.Duration) time.Duration { return d }, logger: log.New(run.logs, "", 0),
	}
	ctx, stop := context.WithCancel(t.Context())
	run.stop = stop
	go func() { run.done <- refresher.run(ctx) }()
	t.Cleanup(func() {
		stop()
		select {
		case <-run.done:
		case <-time.After(10 * time.Second):
			t.Error("refresher did not stop")
		}
	})
	return run
}

func (r *refresherRun) result(t *testing.T) error {
	t.Helper()
	select {
	case err := <-r.done:
		r.done <- err
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("refresher did not return")
		return nil
	}
}

func (r *refresherRun) token(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(r.tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestCoreTokenIsWrittenAndRefreshedAtTwoThirdsOfItsLifetime(t *testing.T) {
	fixture := newIAMExchangeFixture(t)
	run := startRefresher(t, fixture, nil)
	if wait := run.clock.nextWait(t); wait != 600*time.Second {
		t.Fatalf("first refresh in %s, want two thirds of 900 s", wait)
	}
	_, issued := fixture.seen()
	if len(issued) != 1 || run.token(t) != issued[0] {
		t.Fatal("token file does not hold the issued token")
	}
	for name, mode := range map[string]os.FileMode{run.tokenFile: coreTokenMode, coreTokenExpiryFile(run.tokenFile): coreTokenExpiryMode} {
		info, err := os.Stat(name)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("%s: mode %v, want %o (%v)", filepath.Base(name), info.Mode().Perm(), mode, err)
		}
	}
	entries, err := os.ReadDir(filepath.Dir(run.tokenFile))
	if err != nil || len(entries) != 2 {
		t.Fatalf("token directory holds %d entries, want token and expiry only (%v)", len(entries), err)
	}
	expiry, err := readCoreTokenExpiry(run.tokenFile)
	if err != nil || !expiry.Equal(run.clock.Now().Add(900*time.Second)) {
		t.Fatalf("expiry %v (%v)", expiry, err)
	}
	if err := coreTokenReady(run.tokenFile, run.clock.Now()); err != nil {
		t.Fatal(err)
	}

	fixture.setLifetime(300)
	run.clock.advance(599 * time.Second)
	time.Sleep(50 * time.Millisecond)
	if subjects, _ := fixture.seen(); len(subjects) != 1 {
		t.Fatalf("refreshed after 599 s: %d exchanges", len(subjects))
	}
	run.clock.advance(time.Second)
	if wait := run.clock.nextWait(t); wait != 200*time.Second {
		t.Fatalf("refresh of a 300 s token in %s, want 200 s", wait)
	}
	_, issued = fixture.seen()
	if len(issued) != 2 || run.token(t) != issued[1] {
		t.Fatal("refresh did not replace the token")
	}
}

func TestCoreTokenRefusalStopsWithAClearError(t *testing.T) {
	for _, test := range []struct {
		name   string
		script []int
		// waits before the refusal arrives
		waits int
	}{
		{"first exchange", []int{http.StatusBadRequest}, 0},
		{"refresh after a valid token", []int{http.StatusOK, http.StatusBadRequest}, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newIAMExchangeFixture(t)
			fixture.configure(http.StatusOK, test.script...)
			run := startRefresher(t, fixture, nil)
			for range test.waits {
				run.clock.advance(run.clock.nextWait(t))
			}
			err := run.result(t)
			var refusal refusalError
			if !errors.As(err, &refusal) || !strings.Contains(err.Error(), "HTTP 400 (invalid_grant)") || !strings.Contains(err.Error(), "workload binding") {
				t.Fatalf("expected a clear invalid_grant refusal, got %v", err)
			}
			if subjects, _ := fixture.seen(); len(subjects) != len(test.script) {
				t.Fatalf("%d exchanges, a refusal must not be retried", len(subjects))
			}
			if _, err := os.Stat(run.tokenFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("a refused workload kept its Core token")
			}
			if coreTokenReady(run.tokenFile, run.clock.Now()) == nil {
				t.Fatal("ready without a token")
			}
		})
	}
}

func TestCoreTokenUnavailableIAMIsRetriedWithCappedExponentialBackoff(t *testing.T) {
	fixture := newIAMExchangeFixture(t)
	unavailable := slices.Repeat([]int{http.StatusServiceUnavailable}, 7)
	fixture.configure(http.StatusOK, unavailable...)
	run := startRefresher(t, fixture, nil)
	for _, want := range []time.Duration{1, 2, 4, 8, 16, 30, 30} {
		if wait := run.clock.nextWait(t); wait != want*time.Second {
			t.Fatalf("retry wait %s, want %s", wait, want*time.Second)
		}
		if coreTokenReady(run.tokenFile, run.clock.Now()) == nil {
			t.Fatal("ready before any exchange succeeded")
		}
		run.clock.advance(want * time.Second)
	}
	if wait := run.clock.nextWait(t); wait != 600*time.Second {
		t.Fatalf("after recovery the next wait is %s", wait)
	}
	if subjects, issued := fixture.seen(); len(subjects) != 8 || len(issued) != 1 || run.token(t) != issued[0] {
		t.Fatalf("%d exchanges, %d issued", len(subjects), len(issued))
	}
	if !strings.Contains(run.logs.String(), "HTTP 503 (temporarily_unavailable)") {
		t.Fatal("retries are not explained in the log")
	}
}

func TestEqualJitterStaysWithinHalfAndFullDelay(t *testing.T) {
	for range 1000 {
		if d := equalJitter(8 * time.Second); d < 4*time.Second || d > 8*time.Second {
			t.Fatalf("jittered delay %s outside [4s, 8s]", d)
		}
	}
}

// Readiness follows the token: unready before the first exchange, ready
// while a token is valid, unready from the exact moment it expires while IAM
// stays unavailable, ready again after the next successful exchange.
func TestCoreTokenReadinessTransitions(t *testing.T) {
	fixture := newIAMExchangeFixture(t)
	fixture.setLifetime(60)
	fixture.configure(http.StatusServiceUnavailable, http.StatusOK)
	ready := func(run *refresherRun) error {
		return coreTokenReady(run.tokenFile, run.clock.Now())
	}
	run := startRefresher(t, fixture, nil)
	if wait := run.clock.nextWait(t); wait != 40*time.Second {
		t.Fatalf("first refresh in %s", wait)
	}
	expiry := run.clock.Now().Add(60 * time.Second)
	if err := ready(run); err != nil {
		t.Fatal(err)
	}
	run.clock.advance(40 * time.Second)
	var pending time.Duration
	for {
		pending = run.clock.nextWait(t)
		if _, err := os.Stat(run.tokenFile); errors.Is(err, os.ErrNotExist) {
			if !run.clock.Now().Equal(expiry) {
				t.Fatalf("token removed at %s, expiry %s", run.clock.Now(), expiry)
			}
			break
		}
		if err := ready(run); err != nil {
			t.Fatalf("unready at %s before expiry: %v", run.clock.Now(), err)
		}
		run.clock.advance(pending)
	}
	if ready(run) == nil || execute([]string{"check-core-token", "--token-file=" + run.tokenFile}) == nil {
		t.Fatal("ready after the token expired")
	}
	if !strings.Contains(run.logs.String(), "Core token expired") {
		t.Fatal("expiry is not logged")
	}
	fixture.configure(http.StatusOK)
	run.clock.advance(pending)
	if wait := run.clock.nextWait(t); wait != 40*time.Second {
		t.Fatalf("after recovery the next refresh is in %s", wait)
	}
	if err := ready(run); err != nil {
		t.Fatalf("unready after recovery: %v", err)
	}
	if err := execute([]string{"check-core-token", "--token-file=" + run.tokenFile}); err != nil {
		t.Fatalf("check-core-token after recovery: %v", err)
	}
}

func TestCoreTokenReplacementIsAtomicForConcurrentReaders(t *testing.T) {
	fixture := newIAMExchangeFixture(t)
	fixture.setLifetime(3)
	run := startRefresher(t, fixture, nil)
	stop := make(chan struct{})
	reads := make(chan []string, 1)
	go func() {
		var seen []string
		first := false
		for {
			select {
			case <-stop:
				reads <- seen
				return
			default:
			}
			data, err := os.ReadFile(run.tokenFile)
			switch {
			case errors.Is(err, os.ErrNotExist) && !first:
			case err != nil:
				t.Errorf("reader failed after the first token: %v", err)
			default:
				first = true
				seen = append(seen, string(data))
			}
		}
	}()
	const refreshes = 200
	for range refreshes {
		run.clock.advance(run.clock.nextWait(t))
	}
	run.clock.nextWait(t)
	close(stop)
	seen := <-reads
	_, issued := fixture.seen()
	if len(issued) != refreshes+1 || len(seen) == 0 {
		t.Fatalf("%d tokens issued, %d reads", len(issued), len(seen))
	}
	for _, value := range seen {
		if !slices.Contains(issued, value) {
			t.Fatalf("reader saw a partial or foreign token of %d bytes", len(value))
		}
	}
}

func TestCoreTokenExchangeRereadsTheRotatedProjectedToken(t *testing.T) {
	fixture := newIAMExchangeFixture(t)
	run := startRefresher(t, fixture, nil)
	// Rotate only while the refresher sleeps after an exchange, as kubelet
	// would between two refreshes.
	wait := run.clock.nextWait(t)
	for _, next := range []string{"projected-sa-token-2", "projected-sa-token-3"} {
		run.projected.rotate(t, next)
		run.clock.advance(wait)
		wait = run.clock.nextWait(t)
	}
	subjects, _ := fixture.seen()
	if want := []string{"projected-sa-token-1", "projected-sa-token-2", "projected-sa-token-3"}; !slices.Equal(subjects, want) {
		t.Fatalf("subject tokens %q, want %q", subjects, want)
	}
}

func TestCoreTokensNeverReachLogsOrErrors(t *testing.T) {
	fixture := newIAMExchangeFixture(t)
	fixture.configure(http.StatusOK, http.StatusOK, http.StatusServiceUnavailable, http.StatusOK, http.StatusBadRequest)
	run := startRefresher(t, fixture, nil)
	for range 3 {
		run.clock.advance(run.clock.nextWait(t))
	}
	err := run.result(t)
	if err == nil {
		t.Fatal("expected the final refusal")
	}
	subjects, issued := fixture.seen()
	logs := run.logs.String()
	if logs == "" {
		t.Fatal("refresher logged nothing")
	}
	for _, secret := range append(subjects, issued...) {
		if strings.Contains(logs, secret) || strings.Contains(err.Error(), secret) {
			t.Fatal("a token reached the log or an error")
		}
	}
}

func TestCoreTokenSurvivesARestartOnlyWhileValid(t *testing.T) {
	plant := func(expiresIn time.Duration) func(string, time.Time) {
		return func(tokenFile string, now time.Time) {
			if err := writeCoreToken(tokenFile, "PWT-earlier", now.Add(expiresIn)); err != nil {
				t.Fatal(err)
			}
		}
	}
	fixture := newIAMExchangeFixture(t)
	fixture.configure(http.StatusServiceUnavailable)
	valid := startRefresher(t, fixture, plant(time.Minute))
	valid.clock.nextWait(t)
	if valid.token(t) != "PWT-earlier" || coreTokenReady(valid.tokenFile, valid.clock.Now()) != nil {
		t.Fatal("a still valid token was dropped on restart")
	}
	expired := startRefresher(t, fixture, plant(-time.Second))
	expired.clock.nextWait(t)
	if _, err := os.Stat(expired.tokenFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("an expired token survived the restart")
	}
}

func TestTokenExchangeConfigurationMustBeSafe(t *testing.T) {
	for _, gateway := range []string{"", "http://gateway.example.test", "https://", "https://user:secret@gateway.example.test",
		"https://gateway.example.test/api", "https://gateway.example.test?x=1", "https://gateway.example.test#x"} {
		if _, err := newTokenExchange(gateway, "/var/run/token", ""); err == nil {
			t.Errorf("accepted gateway URL %q", gateway)
		}
	}
	for _, files := range [][2]string{{"relative/token", ""}, {"/var/run/token", "relative/ca.crt"}} {
		if _, err := newTokenExchange("https://gateway.example.test", files[0], files[1]); err == nil {
			t.Errorf("accepted relative paths %q", files)
		}
	}
	if err := execute([]string{"refresh-core-token", "--gateway-url=https://gateway.example.test", "--token-file=relative"}); err == nil {
		t.Error("accepted a relative token file")
	}
}

func TestTokenExchangeRejectsAnswersOutsideTheContract(t *testing.T) {
	valid := map[string]any{"access_token": "PWT-abc_DEF-123", "issued_token_type": accessTokenType, "token_type": "Bearer", "expires_in": 900}
	with := func(key string, value any) []byte {
		changed := map[string]any{}
		for k, v := range valid {
			changed[k] = v
		}
		changed[key] = value
		data, _ := json.Marshal(changed)
		return data
	}
	if issued, err := parseIssuedToken(with("token_type", "bearer")); err != nil || issued.lifetime != 900*time.Second {
		t.Fatalf("rejected a valid answer: %v", err)
	}
	for name, body := range map[string][]byte{
		"malformed":         []byte(`{`),
		"token type":        with("token_type", "mac"),
		"issued token type": with("issued_token_type", jwtTokenType),
		"zero lifetime":     with("expires_in", 0),
		"too long lifetime": with("expires_in", 901),
		"foreign prefix":    with("access_token", "SU-abc"),
		"line break":        with("access_token", "PWT-abc\nX-Injected: 1"),
		"oversized token":   with("access_token", "PWT-"+strings.Repeat("a", 4097)),
	} {
		var refusal refusalError
		if _, err := parseIssuedToken(body); !errors.As(err, &refusal) {
			t.Errorf("%s: accepted or retried an off-contract answer: %v", name, err)
		}
	}

	var mu sync.Mutex
	elsewhere, status := false, http.StatusTemporaryRedirect
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/elsewhere":
			elsewhere = true
		case status == http.StatusTemporaryRedirect:
			http.Redirect(w, r, "/elsewhere", status)
		default:
			answer(w, status, map[string]any{"error": "x"})
		}
	}))
	defer server.Close()
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0444); err != nil {
		t.Fatal(err)
	}
	projected := newProjectedToken(t, "projected-sa-token")
	exchange, err := newTokenExchange(server.URL, projected.path, caFile)
	if err != nil {
		t.Fatal(err)
	}
	var refusal refusalError
	_, err = exchange.exchange(t.Context())
	mu.Lock()
	followed := elsewhere
	mu.Unlock()
	if !errors.As(err, &refusal) || followed {
		t.Fatalf("redirect followed=%v, error %v", followed, err)
	}
	for _, next := range []int{http.StatusNotFound, http.StatusInternalServerError, http.StatusTooManyRequests} {
		mu.Lock()
		status = next
		mu.Unlock()
		_, err := exchange.exchange(t.Context())
		if retryable := !errors.As(err, &refusal); retryable != (next != http.StatusNotFound) {
			t.Errorf("HTTP %d: retryable=%v, error %v", next, retryable, err)
		}
	}
	if _, err := newTokenExchange(server.URL, projected.path, ""); err != nil {
		t.Fatal(err)
	}
	untrusted, _ := newTokenExchange(server.URL, projected.path, "")
	if _, err := untrusted.exchange(t.Context()); err == nil {
		t.Fatal("trusted a gateway certificate outside the configured CA")
	}
}

// The sidecar process exits 0 on SIGTERM, stops exchanging and keeps the
// current token for the plugin's own shutdown.
func TestRefreshCoreTokenStopsCleanlyOnSIGTERM(t *testing.T) {
	fixture := newIAMExchangeFixture(t)
	projected := newProjectedToken(t, "projected-sa-token")
	tokenFile := filepath.Join(t.TempDir(), "token")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	sidecar := exec.CommandContext(ctx, self, "refresh-core-token", "--gateway-url="+fixture.server.URL,
		"--subject-token-file="+projected.path, "--token-file="+tokenFile, "--ca-file="+fixture.caFile)
	sidecar.Env = []string{"RUNTIME_TEST_LAUNCHER=run"}
	var stderr lockedBuffer
	sidecar.Stderr = &stderr
	if err := sidecar.Start(); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; coreTokenReady(tokenFile, time.Now()) != nil; attempt++ {
		if attempt == 200 {
			_ = sidecar.Process.Kill()
			t.Fatalf("no Core token: %s", stderr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := sidecar.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := sidecar.Wait(); err != nil {
		t.Fatalf("sidecar did not exit cleanly: %v %s", err, stderr.String())
	}
	subjects, issued := fixture.seen()
	if len(subjects) != 1 || coreTokenReady(tokenFile, time.Now()) != nil {
		t.Fatalf("%d exchanges; token kept: %v", len(subjects), coreTokenReady(tokenFile, time.Now()))
	}
	if logs := stderr.String(); strings.Contains(logs, issued[0]) || strings.Contains(logs, "projected-sa-token") {
		t.Fatal("the sidecar logged a token")
	}
}
