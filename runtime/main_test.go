package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func fixture(t *testing.T) inputs {
	t.Helper()
	return packageFixture(t, "dev.stellwerk.probe", []byte("fixture executable"))
}

// packageFixture writes a valid single-platform package. The executable is
// deliberately not executable on disk: run never executes the package path.
func packageFixture(t *testing.T, pluginID string, binary []byte) inputs {
	t.Helper()
	directory := t.TempDir()
	platform := runtime.GOOS + "/" + runtime.GOARCH
	path := expectedExecutablePath(platform)
	binaryPath := filepath.Join(directory, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(binaryPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binaryPath, binary, 0444); err != nil {
		t.Fatal(err)
	}
	manifest := packageManifest{
		SchemaVersion: 1, PluginID: pluginID, PluginVersion: "1.0.0",
		RuntimeProfile: "native-static-v1", ProtocolVersion: 1,
		Executables: map[string]executable{platform: {Path: path, SHA256: digest(binary)}},
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(directory, "plugin-manifest.json")
	if err := os.WriteFile(manifestPath, manifestBytes, 0444); err != nil {
		t.Fatal(err)
	}
	return inputs{
		packageDir: directory, manifestPath: manifestPath, stateFile: filepath.Join(directory, "runtime-state.json"),
		expectedID: manifest.PluginID, expectedVer: manifest.PluginVersion, expectedHash: digest(manifestBytes),
		platform: platform, trustState: "untrusted-development", developmentOK: true,
	}
}

func TestValidateAndReload(t *testing.T) {
	in := fixture(t)
	if err := validate(in); err != nil {
		t.Fatal(err)
	}
	stateBytes, err := boundedRegularFile(in.stateFile, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	var state validationState
	if err := decodeStrict(stateBytes, &state); err != nil {
		t.Fatal(err)
	}
	if state.TrustState != "untrusted-development" || state.ManifestSHA256 != in.expectedHash {
		t.Fatalf("unexpected state: %#v", state)
	}
	executablePath := filepath.Join(in.packageDir, filepath.FromSlash(expectedExecutablePath(in.platform)))
	info, err := os.Stat(executablePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0444 {
		t.Fatalf("validation changed the package executable mode to %o", info.Mode().Perm())
	}
}

func TestPackageFilesMustBeBoundedRegularFiles(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "exact"), []byte("1234"), 0444); err != nil {
		t.Fatal(err)
	}
	if _, err := packageFile(directory, "exact", 4); err != nil {
		t.Fatalf("rejected a file at the size limit: %v", err)
	}
	if _, err := packageFile(directory, "exact", 3); err == nil {
		t.Fatal("accepted a file above the size limit")
	}
	for _, relative := range []string{"../exact", "/exact", "a//exact", "a\\exact", "exact\x00"} {
		if _, err := packageFile(directory, relative, 4); err == nil {
			t.Fatalf("accepted invalid package path %q", relative)
		}
	}
	if err := os.Symlink("exact", filepath.Join(directory, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := boundedRegularFile(filepath.Join(directory, "link"), 4); err == nil {
		t.Fatal("followed a final symlink")
	}
	fifo := filepath.Join(directory, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := boundedRegularFile(fifo, 4)
		result <- err
	}()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("accepted a FIFO as a package file")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("opening a planted FIFO blocked")
	}
}

func TestValidationFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*inputs)
	}{
		{"manifest digest", func(in *inputs) { in.expectedHash = strings.Repeat("0", 64) }},
		{"identity", func(in *inputs) { in.expectedID = "dev.stellwerk.other" }},
		{"version", func(in *inputs) { in.expectedVer = "2.0.0" }},
		{"platform", func(in *inputs) { in.platform = "linux/other" }},
		{"untrusted without development", func(in *inputs) { in.developmentOK = false }},
		{"unknown trust", func(in *inputs) { in.trustState = "trust-me" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			in := fixture(t)
			test.mutate(&in)
			if err := validate(in); err == nil {
				t.Fatal("validation unexpectedly succeeded")
			}
		})
	}
}

func TestRejectsExecutableTamperingAndSymlinks(t *testing.T) {
	in := fixture(t)
	executablePath := filepath.Join(in.packageDir, filepath.FromSlash(expectedExecutablePath(in.platform)))
	if err := os.Chmod(executablePath, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executablePath, []byte("tampered"), 0555); err != nil {
		t.Fatal(err)
	}
	if err := validate(in); err == nil {
		t.Fatal("accepted tampered executable")
	}
	if err := os.Remove(executablePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(in.manifestPath, executablePath); err != nil {
		t.Fatal(err)
	}
	if err := validate(in); err == nil {
		t.Fatal("accepted executable symlink")
	}
}

func TestStrictManifest(t *testing.T) {
	in := fixture(t)
	data, err := os.ReadFile(in.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data[:len(data)-1], []byte(`,"unexpected":true}`)...)
	if err := os.Chmod(in.manifestPath, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(in.manifestPath, data, 0444); err != nil {
		t.Fatal(err)
	}
	in.expectedHash = digest(data)
	if err := validate(in); err == nil {
		t.Fatal("accepted unknown manifest field")
	}
}

func TestFilteredEnvironment(t *testing.T) {
	result := filteredEnvironment([]string{
		"HOME=/secret", "DATABASE_URL=postgres://ambient", "STELLWERK_PLUGIN_CP_URL=https://cp",
		"OTEL_SERVICE_NAME=probe", "SSL_CERT_FILE=/certs/ca.pem",
	}, map[string]string{"PLUGIN_ID": "dev.stellwerk.probe"})
	joined := strings.Join(result, "\n")
	for _, expected := range []string{"PLUGIN_ID=", "STELLWERK_PLUGIN_CP_URL=", "OTEL_SERVICE_NAME=", "SSL_CERT_FILE="} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("missing %s in %q", expected, joined)
		}
	}
	for _, forbidden := range []string{"HOME=", "DATABASE_URL="} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("leaked %s in %q", forbidden, joined)
		}
	}
}

func TestExecuteRequiresExplicitInputs(t *testing.T) {
	for _, args := range [][]string{{}, {"run"}, {"validate"}, {"unknown", "--plugin-id=x"}} {
		if err := execute(args); err == nil {
			t.Fatalf("accepted %#v", args)
		}
	}
}

func TestPluginVersionRequiresCanonicalSemVer(t *testing.T) {
	for _, version := range []string{
		"0.0.0", "1.2.3", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-0.3.7",
		"1.0.0-x.7.z.92", "1.0.0+20130313144700", "1.0.0-beta+exp.sha.5114f85",
	} {
		if !versionPattern.MatchString(version) {
			t.Errorf("rejected canonical SemVer %q", version)
		}
	}
	for _, version := range []string{
		"", "v1.2.3", "1.2", "01.2.3", "1.02.3", "1.2.03", "1.2.3-",
		"1.2.3-01", "1.2.3-alpha..1", "1.2.3+", "1.2.3+build..1", "1.2.3/latest",
	} {
		if versionPattern.MatchString(version) {
			t.Errorf("accepted noncanonical SemVer %q", version)
		}
	}
}

func TestEntitlementDeclarationsAreRequirementsNotAuthority(t *testing.T) {
	for _, test := range []struct {
		name        string
		declaration *entitlementDeclaration
		valid       bool
	}{
		{"unlicensed omitted", nil, true},
		{"unlicensed explicit", &entitlementDeclaration{Mode: "none"}, true},
		{"required", &entitlementDeclaration{Mode: "required", Features: []string{"feature-a", "feature-b"}}, true},
		{"unknown mode", &entitlementDeclaration{Mode: "available"}, false},
		{"missing features", &entitlementDeclaration{Mode: "required"}, false},
		{"features without licence", &entitlementDeclaration{Mode: "none", Features: []string{"feature-a"}}, false},
		{"unsorted", &entitlementDeclaration{Mode: "required", Features: []string{"feature-b", "feature-a"}}, false},
		{"duplicate", &entitlementDeclaration{Mode: "required", Features: []string{"feature-a", "feature-a"}}, false},
		{"namespace injection", &entitlementDeclaration{Mode: "required", Features: []string{"core.admin"}}, false},
		{"unsupported limits", &entitlementDeclaration{Mode: "required", Features: []string{"feature-a"}, Limits: []string{"seats"}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateEntitlement(test.declaration); (err == nil) != test.valid {
				t.Fatalf("valid=%v, got %v", test.valid, err)
			}
		})
	}
}

func TestEntitlementValidationReceiptCannotStripRequirement(t *testing.T) {
	in := fixture(t)
	raw, err := os.ReadFile(in.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest packageManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Entitlement = &entitlementDeclaration{Mode: "required", Features: []string{"feature-a"}}
	raw, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(in.manifestPath, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(in.manifestPath, raw, 0444); err != nil {
		t.Fatal(err)
	}
	in.expectedHash = digest(raw)
	if err := validate(in); err != nil {
		t.Fatal(err)
	}
	_, state, err := validatedPackage(in)
	if err != nil {
		t.Fatal(err)
	}
	if !sameEntitlement(manifest.Entitlement, state.Entitlement) {
		t.Fatal("receipt lost entitlement requirements")
	}
	state.Entitlement = nil
	if err := writeValidationState(in, state); err != nil {
		t.Fatal(err)
	}
	if _, _, err := validatedPackage(in); err == nil {
		t.Fatal("accepted receipt with stripped entitlement")
	}
}
