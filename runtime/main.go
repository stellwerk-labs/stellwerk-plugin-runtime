// The native-static-v1 launcher is a deliberately small execution adapter.
// Artifact transport and signature verification happen before this process.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"syscall"
)

const (
	manifestLimit = 256 << 10
	binaryLimit   = 256 << 20
	protocolV1    = 1
)

var (
	pluginIDPattern = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)+$`)
	versionPattern  = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)
	featurePattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	canonicalUUID   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// A plugin reports these two values to Core, which activates an installation
// only while the running plugin states exactly the installation UUID and
// package digest Core recorded for it.
const (
	// installationEnvironment carries the installation UUID Core assigned.
	// The chart sets it from installationId; run passes it through only in
	// canonical lowercase form.
	installationEnvironment = "STELLWERK_INSTALLATION_ID"
	// packageDigestEnvironment carries the SHA-256 of the package manifest run
	// verified. It always comes from that verification, never from the
	// environment the launcher inherits.
	packageDigestEnvironment = "STELLWERK_PACKAGE_SHA256"
)

type executable struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type packageManifest struct {
	SchemaVersion   int                     `json:"schemaVersion"`
	PluginID        string                  `json:"pluginId"`
	PluginVersion   string                  `json:"pluginVersion"`
	RuntimeProfile  string                  `json:"runtimeProfile"`
	ProtocolVersion int                     `json:"protocolVersion"`
	Executables     map[string]executable   `json:"executables"`
	UI              *executable             `json:"ui,omitempty"`
	Entitlement     *entitlementDeclaration `json:"entitlement,omitempty"`
}

// A declaration states package requirements, not a verified licence. Core
// owns issuer trust and authorization; this launcher never receives those keys.
type entitlementDeclaration struct {
	Mode     string   `json:"mode"`
	Features []string `json:"features"`
	Limits   []string `json:"limits"`
}

func validateEntitlement(declaration *entitlementDeclaration) error {
	if declaration == nil {
		return nil
	}
	if declaration.Mode == "none" && len(declaration.Features) == 0 && len(declaration.Limits) == 0 {
		return nil
	}
	if declaration.Mode != "required" || len(declaration.Features) == 0 || len(declaration.Features) > 64 || len(declaration.Limits) != 0 {
		return errors.New("plugin_incompatible: bounded entitlement features and no unsupported limits required")
	}
	for i, feature := range declaration.Features {
		if !featurePattern.MatchString(feature) || i > 0 && declaration.Features[i-1] >= feature {
			return errors.New("plugin_incompatible: entitlement features must be sorted unique local slugs")
		}
	}
	return nil
}

func sameEntitlement(a, b *entitlementDeclaration) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Mode == b.Mode && slices.Equal(a.Features, b.Features) && slices.Equal(a.Limits, b.Limits)
}

type validationState struct {
	SchemaVersion  int                     `json:"schemaVersion"`
	PluginID       string                  `json:"pluginId"`
	PluginVersion  string                  `json:"pluginVersion"`
	Platform       string                  `json:"platform"`
	ManifestSHA256 string                  `json:"manifestSha256"`
	ExecutablePath string                  `json:"executablePath"`
	ExecutableHash string                  `json:"executableSha256"`
	TrustState     string                  `json:"trustState"`
	Entitlement    *entitlementDeclaration `json:"entitlement,omitempty"`
}

type inputs struct {
	packageDir    string
	manifestPath  string
	stateFile     string
	expectedID    string
	expectedVer   string
	expectedHash  string
	platform      string
	trustState    string
	listen        string
	pluginState   string
	developmentOK bool
	consoleOrigin string
}

func digest(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }

// boundedRegularFile refuses to follow a final symlink and checks the opened
// file itself, so the type and size checks describe the bytes that are read.
// O_NONBLOCK keeps a planted FIFO from blocking the open.
func boundedRegularFile(path string, limit int64) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("expected a bounded regular file, not a symlink")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err == nil && int64(len(data)) > limit {
		err = errors.New("file exceeds size limit")
	}
	return data, err
}

func decodeStrict[T any](data []byte, value *T) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON content")
	}
	return nil
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(value) == value
}

func expectedExecutablePath(platform string) string {
	return filepath.ToSlash(filepath.Join("bin", platform, "plugin"))
}

// verifiedPackage is a package whose manifest and selected executable matched
// the operator-approved digests. binary holds the verified executable bytes in
// this process's private memory; run executes exactly these bytes.
type verifiedPackage struct {
	manifest     packageManifest
	selected     executable
	manifestHash string
	binary       []byte
}

func loadAndValidate(in inputs) (verifiedPackage, error) {
	manifestBytes, err := boundedRegularFile(in.manifestPath, manifestLimit)
	if err != nil {
		return verifiedPackage{}, err
	}
	manifestHash := digest(manifestBytes)
	if !validSHA256(in.expectedHash) || manifestHash != in.expectedHash {
		return verifiedPackage{}, errors.New("manifest digest mismatch")
	}
	var manifest packageManifest
	if err := decodeStrict(manifestBytes, &manifest); err != nil {
		return verifiedPackage{}, err
	}
	if manifest.SchemaVersion != 1 || manifest.RuntimeProfile != "native-static-v1" || manifest.ProtocolVersion != protocolV1 {
		return verifiedPackage{}, errors.New("plugin_incompatible: manifest schema, runtime profile or protocol")
	}
	if !pluginIDPattern.MatchString(manifest.PluginID) || manifest.PluginID != in.expectedID {
		return verifiedPackage{}, errors.New("plugin_incompatible: plugin identity")
	}
	if !versionPattern.MatchString(manifest.PluginVersion) || manifest.PluginVersion != in.expectedVer {
		return verifiedPackage{}, errors.New("plugin_incompatible: plugin version")
	}
	if err := validateEntitlement(manifest.Entitlement); err != nil {
		return verifiedPackage{}, err
	}
	selected, ok := manifest.Executables[in.platform]
	if !ok || selected.Path != expectedExecutablePath(in.platform) || !validSHA256(selected.SHA256) {
		return verifiedPackage{}, errors.New("plugin_incompatible: platform executable")
	}
	packageRoot, err := filepath.Abs(in.packageDir)
	if err != nil {
		return verifiedPackage{}, err
	}
	executablePath, err := filepath.Abs(filepath.Join(packageRoot, filepath.FromSlash(selected.Path)))
	if err != nil {
		return verifiedPackage{}, err
	}
	prefix := packageRoot + string(os.PathSeparator)
	if !strings.HasPrefix(executablePath, prefix) {
		return verifiedPackage{}, errors.New("executable escapes package directory")
	}
	binary, err := packageFile(packageRoot, selected.Path, binaryLimit)
	if err != nil {
		return verifiedPackage{}, err
	}
	if digest(binary) != selected.SHA256 {
		return verifiedPackage{}, errors.New("executable digest mismatch")
	}
	if manifest.UI != nil {
		if _, err := loadUIAssets(in, manifest); err != nil {
			return verifiedPackage{}, err
		}
	}
	return verifiedPackage{manifest: manifest, selected: selected, manifestHash: manifestHash, binary: binary}, nil
}

func trustStateAllowed(state string, developmentOK bool) bool {
	switch state {
	case "verified-local-key", "verified-sigstore":
		return true
	case "untrusted-development":
		return developmentOK
	default:
		return false
	}
}

func writeValidationState(in inputs, state validationState) error {
	if !trustStateAllowed(state.TrustState, in.developmentOK) {
		return errors.New("untrusted package requires explicit development mode")
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return writeFileAtomically(in.stateFile, append(data, '\n'), 0444)
}

// writeFileAtomically writes a temporary file with its final mode in the
// target directory and renames it over path. Readers see the old or the new
// content, never a partial file.
func writeFileAtomically(path string, data []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}

// validate never changes package files. The executable needs no mode bits
// because run executes a sealed in-memory copy, never the package path.
func validate(in inputs) error {
	pkg, err := loadAndValidate(in)
	if err != nil {
		return err
	}
	return writeValidationState(in, validationState{
		SchemaVersion: 1, PluginID: pkg.manifest.PluginID, PluginVersion: pkg.manifest.PluginVersion,
		Platform: in.platform, ManifestSHA256: pkg.manifestHash, ExecutablePath: pkg.selected.Path,
		ExecutableHash: pkg.selected.SHA256, TrustState: in.trustState, Entitlement: pkg.manifest.Entitlement,
	})
}

// filteredEnvironment is the plugin's whole environment: the allowlisted part
// of source plus the launcher's additions, which win.
func filteredEnvironment(source []string, additions map[string]string) ([]string, error) {
	allowed := map[string]string{}
	for _, item := range source {
		name, value, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		if name == installationEnvironment && !canonicalUUID.MatchString(value) {
			return nil, fmt.Errorf("%s must be the installation UUID Core assigned, in canonical lowercase form", installationEnvironment)
		}
		if strings.HasPrefix(name, "STELLWERK_PLUGIN_") || strings.HasPrefix(name, "OTEL_") || name == "SSL_CERT_FILE" || name == coreTokenEnvironment || name == installationEnvironment {
			allowed[name] = value
		}
	}
	for name, value := range additions {
		allowed[name] = value
	}
	names := make([]string, 0, len(allowed))
	for name := range allowed {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]string, 0, len(names))
	for _, name := range names {
		result = append(result, name+"="+allowed[name])
	}
	return result, nil
}

func validatedPackage(in inputs) (verifiedPackage, validationState, error) {
	var state validationState
	stateBytes, err := boundedRegularFile(in.stateFile, 64<<10)
	if err != nil {
		return verifiedPackage{}, state, fmt.Errorf("validated runtime state unavailable: %w", err)
	}
	if err := decodeStrict(stateBytes, &state); err != nil {
		return verifiedPackage{}, state, err
	}
	if !trustStateAllowed(state.TrustState, in.developmentOK) {
		return verifiedPackage{}, state, errors.New("package trust state is not executable")
	}
	pkg, err := loadAndValidate(in)
	if err != nil {
		return pkg, state, err
	}
	if state.SchemaVersion != 1 || state.PluginID != pkg.manifest.PluginID || state.PluginVersion != pkg.manifest.PluginVersion ||
		state.Platform != in.platform || state.ManifestSHA256 != pkg.manifestHash || state.ExecutablePath != pkg.selected.Path ||
		state.ExecutableHash != pkg.selected.SHA256 || !sameEntitlement(state.Entitlement, pkg.manifest.Entitlement) {
		return pkg, state, errors.New("validated runtime state does not match package")
	}
	return pkg, state, nil
}

// launch is a verified plugin process image, ready to replace the launcher.
type launch struct {
	image *os.File
	argv  []string
	env   []string
}

// prepareLaunch re-verifies package and receipt and seals the verified bytes
// into an anonymous in-memory file. From then on nothing on the package
// filesystem can change what runs, because exec never resolves a package path:
//
//	package file --read, hash--> private memory --copy, seal--> memfd --exec
//	(may change any time)        (verified bytes)               (immutable)
func prepareLaunch(in inputs) (launch, error) {
	pkg, state, err := validatedPackage(in)
	if err != nil {
		return launch{}, err
	}
	env, err := filteredEnvironment(os.Environ(), map[string]string{
		"PLUGIN_ID": pkg.manifest.PluginID, "PLUGIN_VERSION": pkg.manifest.PluginVersion,
		"PLUGIN_LISTEN": in.listen, "PLUGIN_STATE": in.pluginState, "PLUGIN_TRUST_STATE": state.TrustState,
		packageDigestEnvironment: pkg.manifestHash,
	})
	if err != nil {
		return launch{}, err
	}
	image, err := sealedImage(pkg.binary)
	if err != nil {
		return launch{}, fmt.Errorf("seal verified executable: %w", err)
	}
	// argv[0] is only the conventional program name.
	return launch{image: image, argv: []string{filepath.Join(in.packageDir, filepath.FromSlash(pkg.selected.Path))}, env: env}, nil
}

func runPlugin(in inputs) error {
	plugin, err := prepareLaunch(in)
	if err != nil {
		return err
	}
	return plugin.exec()
}

func parseInputs(command string, args []string) (inputs, error) {
	var in inputs
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.StringVar(&in.packageDir, "package-dir", "/package", "read-only package root at execution")
	flags.StringVar(&in.manifestPath, "manifest", "/package/plugin-manifest.json", "canonical plugin manifest")
	flags.StringVar(&in.stateFile, "state-file", "/package/runtime-state.json", "validation receipt")
	flags.StringVar(&in.expectedID, "plugin-id", "", "operator-approved plugin ID")
	flags.StringVar(&in.expectedVer, "plugin-version", "", "operator-approved plugin version")
	flags.StringVar(&in.expectedHash, "manifest-sha256", "", "operator-approved manifest digest")
	flags.StringVar(&in.platform, "platform", runtime.GOOS+"/"+runtime.GOARCH, "selected native platform")
	flags.StringVar(&in.trustState, "trust-state", "", "validation trust result")
	flags.StringVar(&in.listen, "listen", "0.0.0.0:8080", "plugin listen address")
	flags.StringVar(&in.pluginState, "plugin-state", "/state", "plugin-owned state directory")
	flags.BoolVar(&in.developmentOK, "development-untrusted", false, "allow visibly untrusted local package")
	flags.StringVar(&in.consoleOrigin, "console-origin", "", "exact HTTPS Console origin allowed to frame the static UI")
	if err := flags.Parse(args); err != nil {
		return in, err
	}
	if flags.NArg() != 0 || in.expectedID == "" || in.expectedVer == "" || in.expectedHash == "" {
		return in, errors.New("plugin ID, version and manifest digest are required; positional arguments are forbidden")
	}
	return in, nil
}

func execute(args []string) error {
	if len(args) == 0 {
		return errors.New("expected verify-envelope, verify-publisher, verify-bundle, validate, run, serve-ui, refresh-core-token or check-core-token")
	}
	switch args[0] {
	case "verify-envelope":
		return verifyEnvelope(args[1:])
	case "refresh-core-token":
		return refreshCoreToken(args[1:])
	case "check-core-token":
		return checkCoreToken(args[1:])
	case "verify-publisher":
		return verifyPublisher(args[1:])
	case "verify-bundle":
		return verifyBundle(args[1:])
	}
	in, err := parseInputs(args[0], args[1:])
	if err != nil {
		return err
	}
	switch args[0] {
	case "validate":
		return validate(in)
	case "run":
		return runPlugin(in)
	case "serve-ui":
		return serveUI(in)
	default:
		return errors.New("unknown command")
	}
}

func main() {
	if err := execute(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
