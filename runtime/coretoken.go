package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// Workload token exchange (v1alpha). A sidecar runs
// refresh-core-token next to the plugin:
//
//	projected SA token --exchange--> IAM via Core gateway --> PWT-... token
//	(sidecar only)                                             |
//	plugin reads STELLWERK_CORE_TOKEN_FILE per request <-------+ atomic write
//
// The plugin container never mounts the Kubernetes token.
const (
	coreTokenEnvironment   = "STELLWERK_CORE_TOKEN_FILE"
	tokenExchangePath      = "/auth/plugin-workload-token"
	tokenExchangeGrant     = "urn:ietf:params:oauth:grant-type:token-exchange"
	jwtTokenType           = "urn:ietf:params:oauth:token-type:jwt"
	accessTokenType        = "urn:ietf:params:oauth:token-type:access_token"
	maxSubjectTokenBytes   = 16 << 10
	maxExchangeBody        = 64 << 10
	maxIssuedTokenBytes    = 4 + 4096 // "PWT-" plus the longest accepted body
	maxIssuedLifetime      = 900 * time.Second
	coreTokenMode          = 0400
	coreTokenExpiryMode    = 0444
	initialExchangeRetry   = time.Second
	maximumExchangeRetry   = 30 * time.Second
	exchangeRequestTimeout = 10 * time.Second
)

var (
	issuedTokenPattern = regexp.MustCompile(`^PWT-[A-Za-z0-9_-]+$`)
	errorCodePattern   = regexp.MustCompile(`^[a-z_]{1,64}$`)
)

// refusalError is an exchange answer that retrying cannot change.
type refusalError struct{ reason string }

func (e refusalError) Error() string { return e.reason }

type issuedToken struct {
	value    string
	lifetime time.Duration
}

type tokenExchange struct {
	endpoint         string
	subjectTokenFile string
	caFile           string
}

func newTokenExchange(gatewayURL, subjectTokenFile, caFile string) (*tokenExchange, error) {
	origin, err := url.Parse(gatewayURL)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil ||
		(origin.Path != "" && origin.Path != "/") || origin.RawQuery != "" || origin.Fragment != "" {
		return nil, errors.New("the Core gateway URL must be an https origin without path, query or credentials")
	}
	if !filepath.IsAbs(subjectTokenFile) || (caFile != "" && !filepath.IsAbs(caFile)) {
		return nil, errors.New("subject token and CA files must be absolute paths")
	}
	return &tokenExchange{
		endpoint:         "https://" + origin.Host + tokenExchangePath,
		subjectTokenFile: subjectTokenFile, caFile: caFile,
	}, nil
}

// client re-reads the CA file per exchange so a rotated CA is picked up. An
// operator CA replaces the system roots. Redirects are refused because they
// would carry the subject token elsewhere. One request per refresh needs no
// keep-alive, and a per-exchange transport must not leave idle connections.
func (e *tokenExchange) client() (*http.Client, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if e.caFile != "" {
		pem, err := os.ReadFile(e.caFile)
		if err != nil {
			return nil, fmt.Errorf("read Core gateway CA: %w", err)
		}
		config.RootCAs = x509.NewCertPool()
		if !config.RootCAs.AppendCertsFromPEM(pem) {
			return nil, refusalError{"the Core gateway CA file contains no certificate"}
		}
	}
	return &http.Client{
		Timeout:       exchangeRequestTimeout,
		Transport:     &http.Transport{TLSClientConfig: config, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// readSubjectToken follows symlinks on purpose: kubelet publishes projected
// tokens through a symlinked ..data directory and swaps it on rotation.
func readSubjectToken(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("projected ServiceAccount token unavailable: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxSubjectTokenBytes+1))
	if err != nil {
		return "", fmt.Errorf("read projected ServiceAccount token: %w", err)
	}
	if len(data) > maxSubjectTokenBytes {
		return "", refusalError{"the projected ServiceAccount token exceeds 16 KiB"}
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", errors.New("the projected ServiceAccount token is empty")
	}
	return token, nil
}

// exchange presents the current projected token once. Error texts carry
// status and error codes only, never a token or a response body.
func (e *tokenExchange) exchange(ctx context.Context) (issuedToken, error) {
	subject, err := readSubjectToken(e.subjectTokenFile)
	if err != nil {
		return issuedToken{}, err
	}
	body, err := json.Marshal(map[string]string{
		"grant_type": tokenExchangeGrant, "subject_token": subject, "subject_token_type": jwtTokenType,
	})
	if err != nil {
		return issuedToken{}, err
	}
	client, err := e.client()
	if err != nil {
		return issuedToken{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint, bytes.NewReader(body))
	if err != nil {
		return issuedToken{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return issuedToken{}, fmt.Errorf("Core token exchange request failed: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxExchangeBody+1))
	if err != nil {
		return issuedToken{}, fmt.Errorf("read Core token exchange response: %w", err)
	}
	if response.StatusCode == http.StatusOK {
		return parseIssuedToken(data)
	}
	failure := fmt.Sprintf("Core token exchange answered HTTP %d (%s)", response.StatusCode, responseErrorCode(data))
	switch {
	case response.StatusCode >= 500, response.StatusCode == http.StatusTooManyRequests, response.StatusCode == http.StatusRequestTimeout:
		return issuedToken{}, errors.New(failure)
	case response.StatusCode == http.StatusBadRequest:
		return issuedToken{}, refusalError{failure + ": IAM refused the projected ServiceAccount token; check the workload binding, audience and service user"}
	default:
		return issuedToken{}, refusalError{failure}
	}
}

func responseErrorCode(data []byte) string {
	var answer struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(data, &answer) == nil && errorCodePattern.MatchString(answer.Error) {
		return answer.Error
	}
	return "no error code"
}

func parseIssuedToken(data []byte) (issuedToken, error) {
	var answer struct {
		AccessToken     string `json:"access_token"`
		IssuedTokenType string `json:"issued_token_type"`
		TokenType       string `json:"token_type"`
		ExpiresIn       int    `json:"expires_in"`
	}
	if len(data) > maxExchangeBody || json.Unmarshal(data, &answer) != nil {
		return issuedToken{}, refusalError{"Core token exchange returned a malformed response"}
	}
	lifetime := time.Duration(answer.ExpiresIn) * time.Second
	if !strings.EqualFold(answer.TokenType, "Bearer") || answer.IssuedTokenType != accessTokenType ||
		lifetime <= 0 || lifetime > maxIssuedLifetime || !validIssuedToken(answer.AccessToken) {
		return issuedToken{}, refusalError{"Core token exchange returned a token outside the v1alpha contract"}
	}
	return issuedToken{value: answer.AccessToken, lifetime: lifetime}, nil
}

func validIssuedToken(token string) bool {
	return len(token) <= maxIssuedTokenBytes && issuedTokenPattern.MatchString(token)
}

// clock lets tests drive refresh timing without sleeping.
type clock interface {
	Now() time.Time
	After(time.Duration) <-chan time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time                         { return time.Now() }
func (systemClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// equalJitter waits between half and all of d, so restarted replicas spread out.
func equalJitter(d time.Duration) time.Duration { return d/2 + rand.N(d/2+1) }

func coreTokenExpiryFile(tokenFile string) string { return tokenFile + ".expiry" }

type coreTokenRefresher struct {
	exchange  func(context.Context) (issuedToken, error)
	tokenFile string
	clock     clock
	jitter    func(time.Duration) time.Duration
	logger    *log.Logger
}

// run keeps a valid Core token in tokenFile until ctx ends. It refreshes at two
// thirds of each issued lifetime and retries other failures with jittered
// exponential backoff. The file exists only while its token is valid: it is
// removed when the token expires during retries and when IAM refuses the
// workload, which also ends run with that refusal.
func (r *coreTokenRefresher) run(ctx context.Context) error {
	expiry, err := r.recoverExpiry()
	if err != nil {
		return err
	}
	retry := initialExchangeRetry
	for {
		issued, err := r.exchange(ctx)
		if ctx.Err() != nil {
			return nil
		}
		var refusal refusalError
		var wait time.Duration
		switch {
		case err == nil:
			expiry = r.clock.Now().Add(issued.lifetime)
			if err := writeCoreToken(r.tokenFile, issued.value, expiry); err != nil {
				return fmt.Errorf("write Core token: %w", err)
			}
			wait, retry = issued.lifetime*2/3, initialExchangeRetry
			r.logger.Printf("Core token refreshed, valid for %s, next refresh in %s", issued.lifetime, wait)
		case errors.As(err, &refusal):
			if removeErr := removeCoreToken(r.tokenFile); removeErr != nil {
				return errors.Join(err, removeErr)
			}
			return err
		default:
			wait, retry = r.jitter(retry), min(retry*2, maximumExchangeRetry)
			r.logger.Printf("Core token exchange failed, retrying in %s: %v", wait, err)
		}
		if expiry, err = r.wait(ctx, wait, expiry); err != nil || ctx.Err() != nil {
			return err
		}
	}
}

// wait sleeps for d and removes the token file when its expiry passes first.
func (r *coreTokenRefresher) wait(ctx context.Context, d time.Duration, expiry time.Time) (time.Time, error) {
	deadline := r.clock.Now().Add(d)
	for {
		now := r.clock.Now()
		if !expiry.IsZero() && !now.Before(expiry) {
			if err := removeCoreToken(r.tokenFile); err != nil {
				return expiry, err
			}
			expiry = time.Time{}
			r.logger.Printf("Core token expired; the workload is not ready until an exchange succeeds")
		}
		if !now.Before(deadline) {
			return expiry, nil
		}
		step := deadline.Sub(now)
		if !expiry.IsZero() && expiry.Sub(now) < step {
			step = expiry.Sub(now)
		}
		select {
		case <-ctx.Done():
			return expiry, nil
		case <-r.clock.After(step):
		}
	}
}

// recoverExpiry keeps a token written before a sidecar restart only while it
// is still valid.
func (r *coreTokenRefresher) recoverExpiry() (time.Time, error) {
	expiry, err := readCoreTokenExpiry(r.tokenFile)
	if err == nil && r.clock.Now().Before(expiry) {
		return expiry, nil
	}
	return time.Time{}, removeCoreToken(r.tokenFile)
}

// writeCoreToken replaces token and expiry atomically. A reader sees the old
// or the new token, never a partial one.
func writeCoreToken(tokenFile, token string, expiry time.Time) error {
	if err := writeFileAtomically(tokenFile, []byte(token), coreTokenMode); err != nil {
		return err
	}
	return writeFileAtomically(coreTokenExpiryFile(tokenFile), []byte(expiry.UTC().Format(time.RFC3339)), coreTokenExpiryMode)
}

func removeCoreToken(tokenFile string) error {
	for _, path := range []string{tokenFile, coreTokenExpiryFile(tokenFile)} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func readCoreTokenExpiry(tokenFile string) (time.Time, error) {
	data, err := boundedRegularFile(coreTokenExpiryFile(tokenFile), 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Parse(time.RFC3339, string(data))
}

// coreTokenReady is the readiness rule: a token file and an unexpired expiry.
func coreTokenReady(tokenFile string, now time.Time) error {
	token, err := boundedRegularFile(tokenFile, maxIssuedTokenBytes)
	if err != nil {
		return fmt.Errorf("no Core token: %w", err)
	}
	if !validIssuedToken(string(token)) {
		return errors.New("the Core token file is malformed")
	}
	expiry, err := readCoreTokenExpiry(tokenFile)
	if err != nil {
		return fmt.Errorf("no Core token expiry: %w", err)
	}
	if !now.Before(expiry) {
		return errors.New("the Core token has expired")
	}
	return nil
}

func coreTokenFlags(command string) (*flag.FlagSet, *string) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	tokenFile := flags.String("token-file", "/run/stellwerk/core-token/token", "Core token file shared with the plugin")
	return flags, tokenFile
}

func refreshCoreToken(args []string) error {
	flags, tokenFile := coreTokenFlags("refresh-core-token")
	gatewayURL := flags.String("gateway-url", "", "https origin of the Core gateway")
	subjectTokenFile := flags.String("subject-token-file", "/var/run/secrets/stellwerk/workload/token", "projected ServiceAccount token")
	caFile := flags.String("ca-file", "", "optional CA bundle for the Core gateway")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !filepath.IsAbs(*tokenFile) {
		return errors.New("refresh-core-token takes only flags and an absolute --token-file")
	}
	exchange, err := newTokenExchange(*gatewayURL, *subjectTokenFile, *caFile)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	refresher := coreTokenRefresher{
		exchange: exchange.exchange, tokenFile: *tokenFile, clock: systemClock{},
		jitter: equalJitter, logger: log.New(os.Stderr, "refresh-core-token: ", log.LstdFlags|log.LUTC),
	}
	return refresher.run(ctx)
}

func checkCoreToken(args []string) error {
	flags, tokenFile := coreTokenFlags("check-core-token")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("check-core-token takes only flags")
	}
	return coreTokenReady(*tokenFile, time.Now())
}
