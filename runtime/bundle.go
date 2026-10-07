package main

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"
)

// Offline bundle: everything an air-gapped customer
// needs to install one plugin release, verified and imported without any
// vendor network. The publisher signs bundle.json, which pins every component
// by digest, with the same managed key and policy as the package itself:
//
//	bundle/
//	├── bundle.json           plugin, minimum Core and chart versions, component digests
//	├── bundle.sigstore.json  managed-key-no-tlog signature over bundle.json
//	├── publishers.json       public trust bootstrap; its digest reaches the operator out of band
//	└── oci/                  one OCI image layout
//	    ├── oci-layout
//	    ├── index.json        the five components and the package's referrers, nothing else
//	    └── blobs/sha256/     exactly the blobs those reach
//
//	components: package ─┬─ signature referrer
//	                     ├─ SBOM referrer
//	                     └─ provenance referrer
//	            runtime, ORAS and Cosign image indexes (linux/amd64 and linux/arm64)
//	            native-plugin-runtime Helm chart
//
// The entitlement (licence) is delivered separately, never in a bundle.
const (
	bundleManifestFile  = "bundle.json"
	bundleSignatureFile = "bundle.sigstore.json"
	bundleTrustFile     = "publishers.json"
	bundleLayoutDir     = "oci"

	ociIndexMediaType       = "application/vnd.oci.image.index.v1+json"
	ociManifestMediaType    = "application/vnd.oci.image.manifest.v1+json"
	dockerManifestMediaType = "application/vnd.docker.distribution.manifest.v2+json"
	helmConfigMediaType     = "application/vnd.cncf.helm.config.v1+json"
	helmChartMediaType      = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
	// Cosign's predicate type for a message signature kept as a referrer.
	signaturePredicateType = "https://sigstore.dev/cosign/sign/v1"
	predicateAnnotation    = "dev.sigstore.bundle.predicateType"
	runtimeChart           = "native-plugin-runtime"
	ociMetadataLimit       = 1 << 20
)

var (
	bundlePlatforms    = []string{"linux/amd64", "linux/arm64"}
	registryHost       = `[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]{1,5})?`
	repositoryPath     = `/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*`
	registryPattern    = regexp.MustCompile(`^` + registryHost + `(?:` + repositoryPath + `)*$`)
	imageSourcePattern = regexp.MustCompile(`^` + registryHost + `(?:` + repositoryPath + `)+@sha256:[0-9a-f]{64}$`)
	tagPattern         = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
	secretNameUnsafe   = regexp.MustCompile(`[^a-z0-9.-]+`)
)

type bundleImage struct {
	Digest string `json:"digest"`
	// Source records the upstream index whose platform manifests the bundle
	// carries. It documents provenance; the import does not use it.
	Source string `json:"source,omitempty"`
}

type bundleManifest struct {
	SchemaVersion       int    `json:"schemaVersion"`
	PluginID            string `json:"pluginId"`
	PluginVersion       string `json:"pluginVersion"`
	MinimumCoreVersion  string `json:"minimumCoreVersion"`
	MinimumChartVersion string `json:"minimumChartVersion"`
	TrustBootstrap      string `json:"trustBootstrap"`
	Package             struct {
		Digest         string `json:"digest"`
		ManifestSHA256 string `json:"manifestSHA256"`
		Signature      string `json:"signature"`
		SBOM           string `json:"sbom,omitempty"`
		Provenance     string `json:"provenance,omitempty"`
	} `json:"package"`
	Images struct {
		Runtime bundleImage `json:"runtime"`
		ORAS    bundleImage `json:"oras"`
		Cosign  bundleImage `json:"cosign"`
	} `json:"images"`
	Chart struct {
		Version string `json:"version"`
		Digest  string `json:"digest"`
	} `json:"chart"`
}

// bundleEntry is one manifest the bundle's OCI index must list.
type bundleEntry struct {
	name, digest, mediaType string
}

func (m bundleManifest) entries() []bundleEntry {
	entries := []bundleEntry{
		{"package", m.Package.Digest, ociManifestMediaType},
		{"package signature referrer", m.Package.Signature, ociManifestMediaType},
	}
	if m.Package.SBOM != "" {
		entries = append(entries, bundleEntry{"package SBOM referrer", m.Package.SBOM, ociManifestMediaType})
	}
	if m.Package.Provenance != "" {
		entries = append(entries, bundleEntry{"package provenance referrer", m.Package.Provenance, ociManifestMediaType})
	}
	for _, image := range m.images() {
		entries = append(entries, bundleEntry{"image " + image.name, image.Digest, ociIndexMediaType})
	}
	return append(entries, bundleEntry{"chart", m.Chart.Digest, ociManifestMediaType})
}

type namedImage struct {
	name string
	bundleImage
}

func (m bundleManifest) images() []namedImage {
	return []namedImage{{"runtime", m.Images.Runtime}, {"oras", m.Images.ORAS}, {"cosign", m.Images.Cosign}}
}

func (m bundleManifest) validate() error {
	switch {
	case m.SchemaVersion != 1:
		return errors.New("bundle.json: schemaVersion 1 is required")
	case !pluginIDPattern.MatchString(m.PluginID) || !versionPattern.MatchString(m.PluginVersion):
		return errors.New("bundle.json: a valid plugin ID and SemVer plugin version are required")
	case !versionPattern.MatchString(m.MinimumCoreVersion) || !versionPattern.MatchString(m.MinimumChartVersion) ||
		!versionPattern.MatchString(m.Chart.Version):
		return errors.New("bundle.json: the minimum Core version, minimum chart version and chart version must be SemVer")
	case !validDigest(m.TrustBootstrap) || !validSHA256(m.Package.ManifestSHA256):
		return errors.New("bundle.json: the trust bootstrap digest and the plugin manifest hash are required")
	}
	for _, entry := range m.entries() {
		if !validDigest(entry.digest) {
			return fmt.Errorf("bundle.json: the %s needs a canonical sha256 digest", entry.name)
		}
	}
	for _, image := range m.images() {
		if image.Source != "" && !imageSourcePattern.MatchString(image.Source) {
			return fmt.Errorf("bundle.json: image %s source %q is not a digest-pinned reference", image.name, image.Source)
		}
	}
	if compareVersions(m.Chart.Version, m.MinimumChartVersion) < 0 {
		return fmt.Errorf("bundle.json: the bundled chart %s is older than the minimum chart version %s", m.Chart.Version, m.MinimumChartVersion)
	}
	return nil
}

type ociPlatform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant"`
}

// String names a platform as os/architecture[/variant]; arm64 implies v8.
func (p *ociPlatform) String() string {
	if p == nil {
		return "unknown"
	}
	name := p.OS + "/" + p.Architecture
	if p.Variant != "" && (p.Architecture != "arm64" || p.Variant != "v8") {
		name += "/" + p.Variant
	}
	return name
}

type ociIndexEntry struct {
	ociDescriptor
	Platform *ociPlatform `json:"platform"`
}

type ociIndex struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Manifests     []ociIndexEntry `json:"manifests"`
	Subject       *ociDescriptor  `json:"subject"`
}

type ociManifest struct {
	MediaType    string            `json:"mediaType"`
	ArtifactType string            `json:"artifactType"`
	Config       ociDescriptor     `json:"config"`
	Layers       []ociDescriptor   `json:"layers"`
	Subject      *ociDescriptor    `json:"subject"`
	Annotations  map[string]string `json:"annotations"`
}

// bundleLayout reads the bundle's OCI layout and remembers which blobs the
// verified graph reached, so that nothing else can ride along.
type bundleLayout struct {
	dir     string
	present map[string]bool
	reached map[string]bool
}

// openBundle checks the bundle's exact file structure: no symlinks, no other
// files, and blob names that are SHA-256 digests.
func openBundle(dir string) (*bundleLayout, error) {
	layout := filepath.Join(dir, bundleLayoutDir)
	for _, expected := range []struct {
		dir         string
		files, dirs []string
	}{
		{dir, []string{bundleManifestFile, bundleSignatureFile, bundleTrustFile}, []string{bundleLayoutDir}},
		{layout, []string{"oci-layout", "index.json"}, []string{"blobs"}},
		{filepath.Join(layout, "blobs"), nil, []string{"sha256"}},
		{filepath.Join(layout, "blobs", "sha256"), nil, nil},
	} {
		if err := exactEntries(expected.dir, expected.files, expected.dirs); err != nil {
			return nil, err
		}
	}
	entries, err := os.ReadDir(filepath.Join(layout, "blobs", "sha256"))
	if err != nil {
		return nil, err
	}
	present := map[string]bool{}
	for _, entry := range entries {
		present[entry.Name()] = true
	}
	return &bundleLayout{dir: layout, present: present, reached: map[string]bool{}}, nil
}

// exactEntries admits exactly the named regular files and directories; in
// the blob store (no names given) only regular files named by a digest.
func exactEntries(dir string, files, dirs []string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("offline bundle: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("offline bundle: %s must be a directory, not a symlink or file", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	blobStore := files == nil && dirs == nil
	found := map[string]bool{}
	for _, entry := range entries {
		switch {
		case blobStore && entry.Type().IsRegular() && validSHA256(entry.Name()):
		case slices.Contains(files, entry.Name()) && entry.Type().IsRegular():
		case slices.Contains(dirs, entry.Name()) && entry.IsDir():
		default:
			return fmt.Errorf("unexpected entry %s in the offline bundle", filepath.Join(filepath.Base(dir), entry.Name()))
		}
		found[entry.Name()] = true
	}
	for _, name := range slices.Concat(files, dirs) {
		if !found[name] {
			return fmt.Errorf("%s is missing from the offline bundle", name)
		}
	}
	return nil
}

func (l *bundleLayout) locate(d ociDescriptor) (string, error) {
	hash, ok := strings.CutPrefix(d.Digest, "sha256:")
	if !ok || !validSHA256(hash) || d.Size < 0 {
		return "", fmt.Errorf("invalid OCI descriptor %q", d.Digest)
	}
	if !l.present[hash] {
		return "", fmt.Errorf("blob %s is missing from the bundle", d.Digest)
	}
	l.reached[hash] = true
	return filepath.Join(l.dir, "blobs", "sha256", hash), nil
}

// read returns a small blob (manifest, index, configuration, Sigstore
// bundle) after checking it against its descriptor.
func (l *bundleLayout) read(d ociDescriptor, limit int64) ([]byte, error) {
	path, err := l.locate(d)
	if err != nil {
		return nil, err
	}
	if d.Size > limit {
		return nil, fmt.Errorf("blob %s exceeds %d bytes", d.Digest, limit)
	}
	data, err := boundedRegularFile(path, limit)
	if err != nil {
		return nil, fmt.Errorf("blob %s: %w", d.Digest, err)
	}
	if int64(len(data)) != d.Size || "sha256:"+digest(data) != d.Digest {
		return nil, fmt.Errorf("blob %s does not match its digest or size", d.Digest)
	}
	return data, nil
}

// check streams a blob of any size through SHA-256.
func (l *bundleLayout) check(d ociDescriptor) error {
	path, err := l.locate(d)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("blob %s: %w", d.Digest, err)
	}
	defer file.Close()
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("blob %s is not a regular file", d.Digest)
	}
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, d.Size+1))
	if err != nil {
		return fmt.Errorf("blob %s: %w", d.Digest, err)
	}
	if size != d.Size || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != d.Digest {
		return fmt.Errorf("blob %s does not match its digest or size", d.Digest)
	}
	return nil
}

// index reads the layout's index.json, which must list exactly the manifests
// bundle.json records, each once.
func (l *bundleLayout) index(expected []bundleEntry) (map[string]ociDescriptor, error) {
	marker, err := boundedRegularFile(filepath.Join(l.dir, "oci-layout"), 4096)
	var layout struct {
		Version string `json:"imageLayoutVersion"`
	}
	if err != nil || json.Unmarshal(marker, &layout) != nil || layout.Version != "1.0.0" {
		return nil, errors.New("the bundle is not an OCI image layout 1.0.0")
	}
	data, err := boundedRegularFile(filepath.Join(l.dir, "index.json"), ociMetadataLimit)
	var index ociIndex
	if err != nil || json.Unmarshal(data, &index) != nil || index.SchemaVersion != 2 {
		return nil, errors.New("the bundle's index.json is not an OCI image index")
	}
	listed := map[string]ociDescriptor{}
	for _, entry := range index.Manifests {
		if _, twice := listed[entry.Digest]; twice {
			return nil, fmt.Errorf("the bundle's index.json lists %s twice", entry.Digest)
		}
		listed[entry.Digest] = entry.ociDescriptor
	}
	recorded := map[string]bool{}
	for _, want := range expected {
		if recorded[want.digest] {
			return nil, fmt.Errorf("bundle.json records %s for two components", want.digest)
		}
		recorded[want.digest] = true
		got, ok := listed[want.digest]
		if !ok {
			return nil, fmt.Errorf("%s %s is missing from the bundle", want.name, want.digest)
		}
		if got.MediaType != want.mediaType {
			return nil, fmt.Errorf("%s %s is a %s, not a %s", want.name, want.digest, got.MediaType, want.mediaType)
		}
	}
	for _, entry := range index.Manifests {
		if !recorded[entry.Digest] {
			return nil, fmt.Errorf("foreign manifest %s in the bundle: bundle.json records no such component or referrer", entry.Digest)
		}
	}
	return listed, nil
}

// referrer returns the Sigstore bundle a referrer manifest of subject holds.
func (l *bundleLayout) referrer(d, subject ociDescriptor, predicateType string) ([]byte, error) {
	data, err := l.read(d, ociMetadataLimit)
	if err != nil {
		return nil, err
	}
	var m ociManifest
	if json.Unmarshal(data, &m) != nil || m.MediaType != ociManifestMediaType || m.ArtifactType != sigstoreBundleV03 ||
		m.Subject == nil || m.Subject.Digest != subject.Digest || m.Subject.Size != subject.Size ||
		m.Annotations[predicateAnnotation] != predicateType || len(m.Layers) != 1 || m.Layers[0].MediaType != sigstoreBundleV03 {
		return nil, fmt.Errorf("%s is not a Sigstore bundle referrer of the package with predicate type %s", d.Digest, predicateType)
	}
	if err := l.check(m.Config); err != nil {
		return nil, err
	}
	return l.read(m.Layers[0], signatureBundleLimit)
}

// verifyPackage checks every package blob, binds the plugin manifest to
// bundle.json and verifies the signature and attestation referrers as one
// release set under the operator's trust bootstrap, exactly as the chart's
// publisher gate does. It returns the package signature bundle.
func (l *bundleLayout) verifyPackage(m bundleManifest, listed map[string]ociDescriptor, bootstrap trustBootstrap, now time.Time) ([]byte, error) {
	descriptor := listed[m.Package.Digest]
	data, err := l.read(descriptor, ociMetadataLimit)
	if err != nil {
		return nil, err
	}
	if err := checkEnvelope(data, m.Package.Digest, m.Package.ManifestSHA256); err != nil {
		return nil, fmt.Errorf("package: %w", err)
	}
	var pkg ociManifest
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}
	if err := l.check(pkg.Config); err != nil {
		return nil, err
	}
	for _, layer := range pkg.Layers {
		if layer.MediaType != manifestMediaType {
			if err := l.check(layer); err != nil {
				return nil, err
			}
			continue
		}
		plugin, err := l.read(layer, manifestLimit)
		if err != nil {
			return nil, err
		}
		var identity struct {
			PluginID      string `json:"pluginId"`
			PluginVersion string `json:"pluginVersion"`
		}
		if json.Unmarshal(plugin, &identity) != nil || identity.PluginID != m.PluginID || identity.PluginVersion != m.PluginVersion {
			return nil, fmt.Errorf("the package's plugin manifest is not %s %s", m.PluginID, m.PluginVersion)
		}
	}
	parts := map[string][]byte{}
	for _, part := range []struct{ name, digest, predicateType string }{
		{"signature", m.Package.Signature, signaturePredicateType},
		{"SBOM", m.Package.SBOM, sbomPredicateType},
		{"provenance", m.Package.Provenance, provenancePredicateType},
	} {
		if part.digest == "" {
			continue
		}
		bundle, err := l.referrer(listed[part.digest], descriptor, part.predicateType)
		if err != nil {
			return nil, fmt.Errorf("package %s referrer: %w", part.name, err)
		}
		parts[part.name] = bundle
	}
	if _, err := verifyRelease(bootstrap, m.PluginID, parts["signature"], parts["SBOM"], parts["provenance"], data, now, ""); err != nil {
		return nil, fmt.Errorf("package release set: %w", err)
	}
	return parts["signature"], nil
}

// image checks a multi-platform image: an OCI index of exactly one
// linux/amd64 and one linux/arm64 image whose configurations agree with the
// index, and every blob. It returns the platform manifest digests.
func (l *bundleLayout) image(name string, d ociDescriptor) ([]string, error) {
	data, err := l.read(d, ociMetadataLimit)
	if err != nil {
		return nil, err
	}
	var index ociIndex
	if json.Unmarshal(data, &index) != nil || index.SchemaVersion != 2 || index.MediaType != ociIndexMediaType || index.Subject != nil {
		return nil, fmt.Errorf("image %s is not an OCI image index", name)
	}
	platforms := make([]string, 0, len(index.Manifests))
	for _, child := range index.Manifests {
		platforms = append(platforms, child.Platform.String())
	}
	if !slices.Equal(slices.Sorted(slices.Values(platforms)), bundlePlatforms) {
		return nil, fmt.Errorf("image %s must hold exactly the platforms %s, found %s",
			name, strings.Join(bundlePlatforms, " and "), strings.Join(platforms, ", "))
	}
	children := make([]string, 0, len(index.Manifests))
	for i, child := range index.Manifests {
		if child.MediaType != ociManifestMediaType && child.MediaType != dockerManifestMediaType {
			return nil, fmt.Errorf("image %s lists %s, which is not an image manifest", name, child.Digest)
		}
		data, err := l.read(child.ociDescriptor, ociMetadataLimit)
		if err != nil {
			return nil, err
		}
		var manifest ociManifest
		if json.Unmarshal(data, &manifest) != nil || (manifest.MediaType != "" && manifest.MediaType != child.MediaType) {
			return nil, fmt.Errorf("image %s manifest %s is not a %s", name, child.Digest, child.MediaType)
		}
		config, err := l.read(manifest.Config, ociMetadataLimit)
		if err != nil {
			return nil, err
		}
		var configured ociPlatform
		if json.Unmarshal(config, &configured) != nil || configured.String() != platforms[i] {
			return nil, fmt.Errorf("image %s lists a %s manifest whose configuration is %s", name, platforms[i], configured.String())
		}
		for _, layer := range manifest.Layers {
			if err := l.check(layer); err != nil {
				return nil, err
			}
		}
		children = append(children, child.Digest)
	}
	return children, nil
}

// chart checks the Helm chart OCI artifact (the layout `helm push` writes).
func (l *bundleLayout) chart(d ociDescriptor, version string) error {
	data, err := l.read(d, ociMetadataLimit)
	if err != nil {
		return err
	}
	var m ociManifest
	if json.Unmarshal(data, &m) != nil || m.MediaType != ociManifestMediaType || m.Config.MediaType != helmConfigMediaType ||
		len(m.Layers) != 1 || m.Layers[0].MediaType != helmChartMediaType {
		return errors.New("the chart is not a Helm chart OCI artifact")
	}
	config, err := l.read(m.Config, ociMetadataLimit)
	if err != nil {
		return err
	}
	var metadata struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if json.Unmarshal(config, &metadata) != nil || metadata.Name != runtimeChart || metadata.Version != version {
		return fmt.Errorf("the bundled chart is %s %s, bundle.json records %s %s", metadata.Name, metadata.Version, runtimeChart, version)
	}
	return l.check(m.Layers[0])
}

// foreign refuses any blob the verified graph did not reach.
func (l *bundleLayout) foreign() error {
	for _, hash := range slices.Sorted(maps.Keys(l.present)) {
		if !l.reached[hash] {
			return fmt.Errorf("foreign blob sha256:%s in the bundle: nothing bundle.json records refers to it", hash)
		}
	}
	return nil
}

// verifiedBundle is a bundle whose every file and blob was checked.
type verifiedBundle struct {
	manifest  bundleManifest
	publisher string
	trust     []byte
	signature []byte
	children  map[string][]string
}

// loadBundle verifies a bundle completely offline. The operator pins the
// trust bootstrap by its digest, obtained out of band; it must pin the
// plugin's publisher under managed-key-no-tlog, whose key must have signed
// bundle.json. Then every component, blob and referrer bundle.json records
// is checked, and nothing else may be present.
func loadBundle(dir, trustDigest string, now time.Time) (verifiedBundle, error) {
	layout, err := openBundle(dir)
	if err != nil {
		return verifiedBundle{}, err
	}
	trust, err := boundedRegularFile(filepath.Join(dir, bundleTrustFile), trustBootstrapLimit)
	if err != nil {
		return verifiedBundle{}, fmt.Errorf("trust bootstrap unavailable: %w", err)
	}
	if got := "sha256:" + digest(trust); got != trustDigest {
		return verifiedBundle{}, fmt.Errorf("the bundle's trust bootstrap %s is not the one the operator pinned (%s)", got, trustDigest)
	}
	bootstrap, err := parseTrustBootstrap(trust)
	if err != nil {
		return verifiedBundle{}, err
	}
	data, err := boundedRegularFile(filepath.Join(dir, bundleManifestFile), ociMetadataLimit)
	if err != nil {
		return verifiedBundle{}, fmt.Errorf("bundle.json: %w", err)
	}
	var manifest bundleManifest
	if err := decodeStrict(data, &manifest); err != nil {
		return verifiedBundle{}, fmt.Errorf("bundle.json: %w", err)
	}
	if err := manifest.validate(); err != nil {
		return verifiedBundle{}, err
	}
	if manifest.TrustBootstrap != trustDigest {
		return verifiedBundle{}, fmt.Errorf("bundle.json records trust bootstrap %s, the bundle carries %s", manifest.TrustBootstrap, trustDigest)
	}
	signature, err := boundedRegularFile(filepath.Join(dir, bundleSignatureFile), signatureBundleLimit)
	if err != nil {
		return verifiedBundle{}, fmt.Errorf("bundle.json signature unavailable: %w", err)
	}
	if _, err := verifyManagedKeySignature(bootstrap, manifest.PluginID, signature, data, now, ""); err != nil {
		return verifiedBundle{}, fmt.Errorf("bundle.json signature: %w", err)
	}
	publisher, err := pinnedPublisher(bootstrap, manifest.PluginID)
	if err != nil {
		return verifiedBundle{}, err
	}
	listed, err := layout.index(manifest.entries())
	if err != nil {
		return verifiedBundle{}, err
	}
	packageSignature, err := layout.verifyPackage(manifest, listed, bootstrap, now)
	if err != nil {
		return verifiedBundle{}, err
	}
	children := map[string][]string{}
	for _, image := range manifest.images() {
		if children[image.name], err = layout.image(image.name, listed[image.Digest]); err != nil {
			return verifiedBundle{}, err
		}
	}
	if err := layout.chart(listed[manifest.Chart.Digest], manifest.Chart.Version); err != nil {
		return verifiedBundle{}, err
	}
	if err := layout.foreign(); err != nil {
		return verifiedBundle{}, err
	}
	return verifiedBundle{manifest: manifest, publisher: publisher.ID, trust: trust, signature: packageSignature, children: children}, nil
}

// render writes what the import and the installer need into out:
//
//	plan              copy, manifest and referrers lines for import-offline-bundle.sh
//	values.json       chart values pinning everything to the mirror by digest
//	publishers.json   the verified trust bootstrap, for trust.bootstrapSecret
//	oci-manifest.sigstore.json  the package signature, for trust.signatureBundleSecret
//	instructions.txt  the installation steps
//
// Every component keeps its digest and gets one tag, <pluginId>-<version>,
// so registry garbage collection of untagged manifests cannot remove it.
func (b verifiedBundle) render(registry string, plainHTTP bool, out string) error {
	if !registryPattern.MatchString(registry) {
		return errors.New("--registry must be HOST[:PORT][/PATH] with lowercase repository path components")
	}
	m := b.manifest
	tag := m.PluginID + "-" + strings.ReplaceAll(m.PluginVersion, "+", "_")
	if !tagPattern.MatchString(tag) {
		return fmt.Errorf("the import tag %s is not a valid OCI tag", tag)
	}
	repositories := map[string]string{
		"package": registry + "/" + m.PluginID,
		"runtime": registry + "/" + runtimeChart,
		"oras":    registry + "/oras",
		"cosign":  registry + "/cosign",
		"chart":   registry + "/charts/" + runtimeChart,
	}
	var plan strings.Builder
	fmt.Fprintf(&plan, "copy %s %s %s\n", repositories["package"], m.Package.Digest, tag)
	referrers := slices.DeleteFunc([]string{m.Package.Signature, m.Package.SBOM, m.Package.Provenance}, func(s string) bool { return s == "" })
	slices.Sort(referrers)
	fmt.Fprintf(&plan, "referrers %s %s %s\n", repositories["package"], m.Package.Digest, strings.Join(referrers, ","))
	for _, image := range m.images() {
		fmt.Fprintf(&plan, "copy %s %s %s\n", repositories[image.name], image.Digest, tag)
		for _, child := range b.children[image.name] {
			fmt.Fprintf(&plan, "manifest %s %s\n", repositories[image.name], child)
		}
	}
	fmt.Fprintf(&plan, "copy %s %s %s\n", repositories["chart"], m.Chart.Digest, tag)

	signatureSecret := "signature-" + strings.Trim(secretNameUnsafe.ReplaceAllString(strings.ToLower(m.PluginVersion), "-"), ".-")
	values, err := json.MarshalIndent(map[string]any{
		"enabled": true,
		"plugin":  map[string]any{"id": m.PluginID, "version": m.PluginVersion},
		"package": map[string]any{
			"reference":      repositories["package"] + "@" + m.Package.Digest,
			"manifestSHA256": m.Package.ManifestSHA256,
			"plainHTTP":      plainHTTP,
			"attestations":   map[string]any{"sbom": m.Package.SBOM, "provenance": m.Package.Provenance},
		},
		"trust": map[string]any{
			"mode":                  managedKeyNoTlogPolicy,
			"bootstrapSecret":       map[string]any{"name": "plugin-trust"},
			"signatureBundleSecret": map[string]any{"name": signatureSecret},
		},
		"images": map[string]any{
			"runtime": repositories["runtime"] + "@" + m.Images.Runtime.Digest,
			"oras":    repositories["oras"] + "@" + m.Images.ORAS.Digest,
			"cosign":  repositories["cosign"] + "@" + m.Images.Cosign.Digest,
		},
	}, "", "  ")
	if err != nil {
		return err
	}
	values = append(values, '\n')
	helmPlainHTTP := ""
	if plainHTTP {
		helmPlainHTTP = " --plain-http"
	}
	instructions := fmt.Sprintf(`Offline bundle %[1]s %[2]s (publisher %[3]s) imported into %[4]s.
It requires Stellwerk Core %[5]s or later and the %[6]s chart %[7]s or later.

1. Create the trust Secrets in the release namespace:
   kubectl create secret generic plugin-trust --from-file=publishers.json=%[8]s
   kubectl create secret generic %[9]s --from-file=oci-manifest.sigstore.json=%[10]s
2. List the address and port of %[4]s as the cluster reaches it in networkPolicy.registryMirrors.
3. Install the chart from the mirror with these values (run the migration phase first
   when the release needs one, see the chart README):
   helm upgrade --install RELEASE oci://%[11]s@%[12]s%[13]s --namespace NAMESPACE -f %[14]s

The licence (entitlement) is delivered separately and is not part of the bundle.

Chart values (%[14]s):
%[15]s`, m.PluginID, m.PluginVersion, b.publisher, registry, m.MinimumCoreVersion, runtimeChart, m.MinimumChartVersion,
		filepath.Join(out, bundleTrustFile), signatureSecret, filepath.Join(out, "oci-manifest.sigstore.json"),
		repositories["chart"], m.Chart.Digest, helmPlainHTTP, filepath.Join(out, "values.json"), values)

	for name, data := range map[string][]byte{
		"plan": []byte(plan.String()), "values.json": values, bundleTrustFile: b.trust,
		"oci-manifest.sigstore.json": b.signature, "instructions.txt": []byte(instructions),
	} {
		if err := writeFileAtomically(filepath.Join(out, name), data, 0644); err != nil {
			return err
		}
	}
	return nil
}

func verifyBundle(args []string) error {
	flags := flag.NewFlagSet("verify-bundle", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dir := flags.String("bundle", "", "offline bundle directory")
	trustDigest := flags.String("trust-bootstrap-digest", "", "sha256 digest of the trust bootstrap, obtained out of band")
	registry := flags.String("registry", "", "import destination HOST[:PORT][/PATH]; renders the import plan and chart values")
	plainHTTP := flags.Bool("plain-http", false, "the destination registry serves plain HTTP")
	out := flags.String("out", "", "existing directory for the import plan, chart values and trust files")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *dir == "" || !validDigest(*trustDigest) || (*registry == "") != (*out == "") {
		return errors.New("--bundle and a canonical --trust-bootstrap-digest are required; --registry and --out go together")
	}
	bundle, err := loadBundle(*dir, *trustDigest, time.Now())
	if err != nil {
		return err
	}
	if *out == "" {
		fmt.Printf("Offline bundle %s %s verified.\n", bundle.manifest.PluginID, bundle.manifest.PluginVersion)
		return nil
	}
	if info, err := os.Stat(*out); err != nil || !info.IsDir() {
		return errors.New("--out must be an existing directory")
	}
	return bundle.render(*registry, *plainHTTP, *out)
}

// compareVersions orders SemVer versions by precedence, ignoring build
// metadata. Both must match versionPattern.
func compareVersions(a, b string) int {
	coreA, preA := splitVersion(a)
	coreB, preB := splitVersion(b)
	for i := range coreA {
		if c := compareNumeric(coreA[i], coreB[i]); c != 0 {
			return c
		}
	}
	switch {
	case preA == preB:
		return 0
	case preA == "":
		return 1
	case preB == "":
		return -1
	}
	idsA, idsB := strings.Split(preA, "."), strings.Split(preB, ".")
	for i := range min(len(idsA), len(idsB)) {
		if c := compareIdentifier(idsA[i], idsB[i]); c != 0 {
			return c
		}
	}
	return cmp.Compare(len(idsA), len(idsB))
}

func splitVersion(version string) ([]string, string) {
	version, _, _ = strings.Cut(version, "+")
	core, prerelease, _ := strings.Cut(version, "-")
	return strings.Split(core, "."), prerelease
}

// compareNumeric compares numeric identifiers without leading zeros.
func compareNumeric(a, b string) int {
	return cmp.Or(cmp.Compare(len(a), len(b)), strings.Compare(a, b))
}

func compareIdentifier(a, b string) int {
	numericA := strings.Trim(a, "0123456789") == ""
	numericB := strings.Trim(b, "0123456789") == ""
	switch {
	case numericA && numericB:
		return compareNumeric(a, b)
	case numericA:
		return -1
	case numericB:
		return 1
	}
	return strings.Compare(a, b)
}
