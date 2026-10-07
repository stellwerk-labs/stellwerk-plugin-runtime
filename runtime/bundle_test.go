package main

import (
	"crypto/elliptic"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const bundleTag = "dev.stellwerk.native-probe-1.0.0"

// bundleFixture writes a complete offline bundle with small stand-ins for
// the images and the chart, signed by one pinned publisher key, and keeps
// what the tests tamper with.
type bundleFixture struct {
	t         *testing.T
	dir       string
	signer    publisherSigner
	trust     []byte
	manifest  bundleManifest
	index     []ociIndexEntry
	empty     ociDescriptor
	pkg       ociDescriptor
	pkgData   []byte
	signature []byte
	layers    map[string]ociDescriptor
}

func newBundleFixture(t *testing.T) *bundleFixture {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, bundleLayoutDir, "blobs", "sha256"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, bundleLayoutDir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0644); err != nil {
		t.Fatal(err)
	}
	f := &bundleFixture{t: t, dir: dir, signer: newPublisherSigner(t, elliptic.P256()), layers: map[string]ociDescriptor{}}
	f.trust = bundleJSON(t, map[string]any{"schemaVersion": 1, "publishers": []any{managedPublisher(managedKeyNoTlogPolicy, f.signer.validPin())}})
	f.empty = f.put("application/vnd.oci.empty.v1+json", []byte("{}"))

	plugin := bundleJSON(t, map[string]any{"schemaVersion": 1, "pluginId": "dev.stellwerk.native-probe", "pluginVersion": "1.0.0"})
	layers := []ociDescriptor{f.titled(manifestMediaType, plugin, "plugin-manifest.json")}
	for _, architecture := range []string{"amd64", "arm64"} {
		layers = append(layers, f.titled(executableMediaType, []byte("plugin "+architecture), "bin/linux/"+architecture+"/plugin"))
	}
	f.pkgData = bundleJSON(t, map[string]any{"schemaVersion": 2, "mediaType": ociManifestMediaType,
		"artifactType": packageArtifactType, "config": f.empty, "layers": layers})
	f.pkg = f.root(ociManifestMediaType, f.pkgData)

	m := &f.manifest
	m.SchemaVersion, m.PluginID, m.PluginVersion = 1, "dev.stellwerk.native-probe", "1.0.0"
	m.MinimumCoreVersion, m.MinimumChartVersion = "1.2.0", "0.1.0"
	m.TrustBootstrap = "sha256:" + digest(f.trust)
	m.Package.Digest, m.Package.ManifestSHA256 = f.pkg.Digest, digest(plugin)
	f.signature = f.signer.sign(t, f.pkgData, f.signer.id)
	m.Package.Signature = f.referrer(f.signature, f.pkg, signaturePredicateType)
	m.Package.SBOM = f.referrer(f.signer.attest(t, f.pkgData, sbomPredicateType, fixtureSBOM), f.pkg, sbomPredicateType)
	m.Package.Provenance = f.referrer(f.signer.attest(t, f.pkgData, provenancePredicateType, fixtureProvenance), f.pkg, provenancePredicateType)
	m.Images.Runtime.Digest = f.image("runtime", "linux/amd64", "linux/arm64").Digest
	m.Images.ORAS = bundleImage{Digest: f.image("oras", "linux/amd64", "linux/arm64").Digest,
		Source: "ghcr.io/oras-project/oras@sha256:" + strings.Repeat("a", 64)}
	// arm64 implies v8; order within the index does not matter.
	m.Images.Cosign.Digest = f.image("cosign", "linux/arm64/v8", "linux/amd64").Digest
	m.Chart.Version = "0.1.0"
	m.Chart.Digest = f.chart(runtimeChart, "0.1.0").Digest
	f.write()
	return f
}

func (f *bundleFixture) put(mediaType string, data []byte) ociDescriptor {
	f.t.Helper()
	if err := os.WriteFile(f.blob("sha256:"+digest(data)), data, 0644); err != nil {
		f.t.Fatal(err)
	}
	return ociDescriptor{MediaType: mediaType, Digest: "sha256:" + digest(data), Size: int64(len(data))}
}

func (f *bundleFixture) titled(mediaType string, data []byte, title string) ociDescriptor {
	d := f.put(mediaType, data)
	d.Annotations = map[string]string{titleAnnotation: title}
	return d
}

// root stores a manifest and lists it in index.json.
func (f *bundleFixture) root(mediaType string, data []byte) ociDescriptor {
	d := f.put(mediaType, data)
	f.index = append(f.index, ociIndexEntry{ociDescriptor: d})
	return d
}

func (f *bundleFixture) blob(digest string) string {
	return filepath.Join(f.dir, bundleLayoutDir, "blobs", "sha256", strings.TrimPrefix(digest, "sha256:"))
}

// referrer attaches a Sigstore bundle to subject the way `oras attach` does.
func (f *bundleFixture) referrer(bundle []byte, subject ociDescriptor, predicateType string) string {
	layer := f.put(sigstoreBundleV03, bundle)
	return f.root(ociManifestMediaType, bundleJSON(f.t, map[string]any{
		"schemaVersion": 2, "mediaType": ociManifestMediaType, "artifactType": sigstoreBundleV03,
		"config": f.empty, "layers": []any{layer}, "subject": subject,
		"annotations": map[string]string{predicateAnnotation: predicateType},
	})).Digest
}

// image stores an index with one image per platform. "linux/arm64=linux/amd64"
// lists an arm64 manifest whose configuration says amd64.
func (f *bundleFixture) image(name string, platforms ...string) ociDescriptor {
	var manifests []ociIndexEntry
	for _, platform := range platforms {
		listed, configured, mislabeled := strings.Cut(platform, "=")
		if !mislabeled {
			configured = listed
		}
		config := f.put("application/vnd.oci.image.config.v1+json", bundleJSON(f.t, parsePlatform(configured)))
		layer := f.put("application/vnd.oci.image.layer.v1.tar+gzip", []byte(name+" "+platform))
		f.layers[name+" "+listed] = layer
		manifest := f.put(ociManifestMediaType, bundleJSON(f.t, map[string]any{
			"schemaVersion": 2, "mediaType": ociManifestMediaType, "config": config, "layers": []any{layer}}))
		manifests = append(manifests, ociIndexEntry{ociDescriptor: manifest, Platform: parsePlatform(listed)})
	}
	return f.root(ociIndexMediaType, bundleJSON(f.t, map[string]any{"schemaVersion": 2, "mediaType": ociIndexMediaType, "manifests": manifests}))
}

func parsePlatform(platform string) *ociPlatform {
	parts := strings.Split(platform, "/")
	p := &ociPlatform{OS: parts[0], Architecture: parts[1]}
	if len(parts) == 3 {
		p.Variant = parts[2]
	}
	return p
}

func (f *bundleFixture) chart(name, version string) ociDescriptor {
	config := f.put(helmConfigMediaType, bundleJSON(f.t, map[string]any{"apiVersion": "v2", "name": name, "version": version}))
	layer := f.put(helmChartMediaType, []byte("chart "+version))
	return f.root(ociManifestMediaType, bundleJSON(f.t, map[string]any{
		"schemaVersion": 2, "mediaType": ociManifestMediaType, "config": config, "layers": []any{layer}}))
}

// unlist drops a manifest from index.json; its blobs stay.
func (f *bundleFixture) unlist(digest string) {
	f.index = slices.DeleteFunc(f.index, func(e ociIndexEntry) bool { return e.Digest == digest })
}

func (f *bundleFixture) writeFile(name string, data []byte) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, name), data, 0644); err != nil {
		f.t.Fatal(err)
	}
}

// write stores the trust bootstrap, index.json and bundle.json and signs
// bundle.json with the fixture's publisher key.
func (f *bundleFixture) write() {
	f.writeFile(bundleTrustFile, f.trust)
	f.writeFile(filepath.Join(bundleLayoutDir, "index.json"), bundleJSON(f.t, map[string]any{
		"schemaVersion": 2, "mediaType": ociIndexMediaType, "manifests": f.index}))
	f.writeFile(bundleManifestFile, bundleJSON(f.t, f.manifest))
	f.signWith(f.signer)
}

func (f *bundleFixture) signWith(signer publisherSigner) {
	data, err := os.ReadFile(filepath.Join(f.dir, bundleManifestFile))
	if err != nil {
		f.t.Fatal(err)
	}
	f.writeFile(bundleSignatureFile, signer.sign(f.t, data, signer.id))
}

func (f *bundleFixture) load() (verifiedBundle, error) {
	return loadBundle(f.dir, "sha256:"+digest(f.trust), publisherTestNow)
}

func TestOfflineBundleVerifiesAndRendersTheImport(t *testing.T) {
	f := newBundleFixture(t)
	bundle, err := f.load()
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	if err := bundle.render("registry.example:5000/mirror", true, out); err != nil {
		t.Fatal(err)
	}
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}

	m := f.manifest
	prefix := "registry.example:5000/mirror/"
	referrers := []string{m.Package.Signature, m.Package.SBOM, m.Package.Provenance}
	slices.Sort(referrers)
	want := []string{
		"copy " + prefix + "dev.stellwerk.native-probe " + m.Package.Digest + " " + bundleTag,
		"referrers " + prefix + "dev.stellwerk.native-probe " + m.Package.Digest + " " + strings.Join(referrers, ","),
	}
	for _, image := range m.images() {
		repository := map[string]string{"runtime": "native-plugin-runtime", "oras": "oras", "cosign": "cosign"}[image.name]
		want = append(want, "copy "+prefix+repository+" "+image.Digest+" "+bundleTag)
		for _, child := range bundle.children[image.name] {
			want = append(want, "manifest "+prefix+repository+" "+child)
		}
	}
	want = append(want, "copy "+prefix+"charts/native-plugin-runtime "+m.Chart.Digest+" "+bundleTag)
	if got := string(read("plan")); got != strings.Join(want, "\n")+"\n" {
		t.Fatalf("plan:\n%s\nwant:\n%s", got, strings.Join(want, "\n"))
	}
	for name, children := range bundle.children {
		if len(children) != 2 {
			t.Fatalf("image %s: %d platform manifests", name, len(children))
		}
	}

	var values struct {
		Enabled bool
		Plugin  struct{ ID, Version string }
		Package struct {
			Reference, ManifestSHA256 string
			PlainHTTP                 bool
			Attestations              struct{ SBOM, Provenance string }
		}
		Trust struct {
			Mode                                   string
			BootstrapSecret, SignatureBundleSecret struct{ Name string }
		}
		Images struct{ Runtime, ORAS, Cosign string }
	}
	if err := json.Unmarshal(read("values.json"), &values); err != nil {
		t.Fatal(err)
	}
	if !values.Enabled || values.Plugin.ID != m.PluginID || values.Plugin.Version != "1.0.0" ||
		values.Package.Reference != prefix+"dev.stellwerk.native-probe@"+m.Package.Digest ||
		values.Package.ManifestSHA256 != m.Package.ManifestSHA256 || !values.Package.PlainHTTP ||
		values.Package.Attestations.SBOM != m.Package.SBOM || values.Package.Attestations.Provenance != m.Package.Provenance ||
		values.Trust.Mode != managedKeyNoTlogPolicy || values.Trust.BootstrapSecret.Name != "plugin-trust" ||
		values.Trust.SignatureBundleSecret.Name != "signature-1.0.0" ||
		values.Images.Runtime != prefix+"native-plugin-runtime@"+m.Images.Runtime.Digest ||
		values.Images.ORAS != prefix+"oras@"+m.Images.ORAS.Digest || values.Images.Cosign != prefix+"cosign@"+m.Images.Cosign.Digest {
		t.Fatalf("values: %+v", values)
	}
	if string(read(bundleTrustFile)) != string(f.trust) || string(read("oci-manifest.sigstore.json")) != string(f.signature) {
		t.Fatal("the trust bootstrap or package signature written for the Secrets differs from the verified bytes")
	}
	instructions := string(read("instructions.txt"))
	for _, part := range []string{
		"publisher stellwerk", "Stellwerk Core 1.2.0 or later", "native-plugin-runtime chart 0.1.0 or later",
		"oci://" + prefix + "charts/native-plugin-runtime@" + m.Chart.Digest + " --plain-http",
		"--from-file=publishers.json=" + filepath.Join(out, bundleTrustFile),
		"kubectl create secret generic signature-1.0.0", "networkPolicy.registryMirrors", "delivered separately",
	} {
		if !strings.Contains(instructions, part) {
			t.Fatalf("instructions lack %q:\n%s", part, instructions)
		}
	}
	if err := bundle.render("Registry.example/Mirror", false, out); err == nil {
		t.Fatal("an invalid registry prefix was accepted")
	}
}

func TestOfflineBundleCommand(t *testing.T) {
	f := newBundleFixture(t)
	pin := "--trust-bootstrap-digest=sha256:" + digest(f.trust)
	if err := execute([]string{"verify-bundle", "--bundle=" + f.dir, pin}); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	if err := execute([]string{"verify-bundle", "--bundle=" + f.dir, pin, "--registry=registry.example/mirror", "--out=" + out}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, "plan")); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--bundle=" + f.dir},
		{"--bundle=" + f.dir, "--trust-bootstrap-digest=" + digest(f.trust)},
		{"--bundle=" + f.dir, pin, "--registry=registry.example"},
		{"--bundle=" + f.dir, pin, "--out=" + out},
		{"--bundle=" + f.dir, pin, "extra"},
	} {
		expectRefusal(t, execute(append([]string{"verify-bundle"}, args...)), "--trust-bootstrap-digest")
	}
	expectRefusal(t, execute([]string{"verify-bundle", "--bundle=" + f.dir, pin, "--registry=registry.example", "--out=" + filepath.Join(out, "plan")}),
		"--out must be an existing directory")
}

func TestOfflineBundleRefusesAnUnpinnedTrustBootstrapOrPublisher(t *testing.T) {
	f := newBundleFixture(t)
	_, err := loadBundle(f.dir, "sha256:"+strings.Repeat("0", 64), publisherTestNow)
	expectRefusal(t, err, "is not the one the operator pinned")

	f.signWith(newPublisherSigner(t, elliptic.P256()))
	_, err = f.load()
	expectRefusal(t, err, "which publisher stellwerk does not pin")

	f = newBundleFixture(t)
	other := managedPublisher(managedKeyNoTlogPolicy, f.signer.validPin())
	other["pluginIds"] = []string{"dev.stellwerk.other"}
	f.trust = bundleJSON(t, map[string]any{"schemaVersion": 1, "publishers": []any{other}})
	f.manifest.TrustBootstrap = "sha256:" + digest(f.trust)
	f.write()
	_, err = f.load()
	expectRefusal(t, err, "no publisher is pinned for plugin dev.stellwerk.native-probe")

	f = newBundleFixture(t)
	f.manifest.TrustBootstrap = "sha256:" + strings.Repeat("1", 64)
	f.write()
	_, err = f.load()
	expectRefusal(t, err, "bundle.json records trust bootstrap")

	f = newBundleFixture(t)
	f.manifest.MinimumCoreVersion = "0.1.0"
	f.writeFile(bundleManifestFile, bundleJSON(t, f.manifest))
	_, err = f.load()
	expectRefusal(t, err, "bundle.json signature: the signature bundle does not cover")
}

func TestOfflineBundleRefusesMissingAlteredOrForeignContent(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(f *bundleFixture)
		reason string
	}{
		{"a missing component", func(f *bundleFixture) {
			f.unlist(f.manifest.Images.Cosign.Digest)
			f.write()
		}, "image cosign " + "sha256:"},
		{"a missing blob", func(f *bundleFixture) {
			if err := os.Remove(f.blob(f.layers["runtime linux/arm64"].Digest)); err != nil {
				f.t.Fatal(err)
			}
		}, "is missing from the bundle"},
		{"altered bytes", func(f *bundleFixture) {
			file, err := os.OpenFile(f.blob(f.layers["runtime linux/amd64"].Digest), os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				f.t.Fatal(err)
			}
			defer file.Close()
			if _, err := file.WriteString("x"); err != nil {
				f.t.Fatal(err)
			}
		}, "does not match its digest or size"},
		{"a foreign blob", func(f *bundleFixture) { f.put("application/octet-stream", []byte("smuggled")) }, "foreign blob"},
		{"an unexpected file", func(f *bundleFixture) { f.writeFile("licence.cbor", []byte("x")) }, "unexpected entry"},
		{"a symlinked blob", func(f *bundleFixture) {
			blob := f.blob(f.layers["oras linux/amd64"].Digest)
			moved := filepath.Join(f.t.TempDir(), "moved")
			if err := os.Rename(blob, moved); err != nil {
				f.t.Fatal(err)
			}
			if err := os.Symlink(moved, blob); err != nil {
				f.t.Fatal(err)
			}
		}, "unexpected entry"},
		{"a missing referrer", func(f *bundleFixture) {
			f.unlist(f.manifest.Package.SBOM)
			f.write()
		}, "package SBOM referrer sha256:"},
		{"an omitted SBOM", func(f *bundleFixture) {
			f.unlist(f.manifest.Package.SBOM)
			f.manifest.Package.SBOM = ""
			f.write()
		}, "requires a signed SBOM attestation"},
		{"a foreign referrer", func(f *bundleFixture) {
			f.referrer(f.signer.attest(f.t, f.pkgData, sbomPredicateType, fixtureSBOM), f.pkg, sbomPredicateType)
			f.write()
		}, "foreign manifest"},
		{"a referrer of another subject", func(f *bundleFixture) {
			f.unlist(f.manifest.Package.SBOM)
			chart := ociDescriptor{MediaType: ociManifestMediaType, Digest: f.manifest.Chart.Digest, Size: 1}
			f.manifest.Package.SBOM = f.referrer(f.signer.attest(f.t, f.pkgData, sbomPredicateType, fixtureSBOM), chart, sbomPredicateType)
			f.write()
		}, "is not a Sigstore bundle referrer of the package"},
		{"a package signature by an unpinned key", func(f *bundleFixture) {
			other := newPublisherSigner(f.t, elliptic.P256())
			f.unlist(f.manifest.Package.Signature)
			f.manifest.Package.Signature = f.referrer(other.sign(f.t, f.pkgData, other.id), f.pkg, signaturePredicateType)
			f.write()
		}, "package release set: the signature names key"},
		{"another plugin version", func(f *bundleFixture) {
			f.manifest.PluginVersion = "1.0.1"
			f.write()
		}, "the package's plugin manifest is not dev.stellwerk.native-probe 1.0.1"},
		{"a component recorded twice", func(f *bundleFixture) {
			f.manifest.Images.Cosign.Digest = f.manifest.Images.ORAS.Digest
			f.write()
		}, "for two components"},
		{"a chart older than the minimum", func(f *bundleFixture) {
			f.manifest.MinimumChartVersion = "0.2.0"
			f.write()
		}, "older than the minimum chart version 0.2.0"},
		{"another chart", func(f *bundleFixture) {
			f.unlist(f.manifest.Chart.Digest)
			f.manifest.Chart.Digest = f.chart("other-chart", "0.1.0").Digest
			f.write()
		}, "the bundled chart is other-chart 0.1.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBundleFixture(t)
			tc.mutate(f)
			_, err := f.load()
			expectRefusal(t, err, tc.reason)
		})
	}
}

func TestOfflineBundleImagesHoldExactlyAmd64AndArm64(t *testing.T) {
	for _, tc := range []struct {
		platforms []string
		reason    string
	}{
		{[]string{"linux/amd64"}, "found linux/amd64"},
		{[]string{"linux/amd64", "linux/arm64", "linux/s390x"}, "found linux/amd64, linux/arm64, linux/s390x"},
		{[]string{"linux/amd64", "linux/amd64"}, "found linux/amd64, linux/amd64"},
		{[]string{"linux/amd64", "linux/arm/v7"}, "found linux/amd64, linux/arm/v7"},
		{[]string{"linux/amd64", "linux/arm64=linux/amd64"}, "lists a linux/arm64 manifest whose configuration is linux/amd64"},
	} {
		t.Run(strings.Join(tc.platforms, ","), func(t *testing.T) {
			f := newBundleFixture(t)
			f.unlist(f.manifest.Images.Runtime.Digest)
			f.manifest.Images.Runtime.Digest = f.image("runtime", tc.platforms...).Digest
			f.write()
			_, err := f.load()
			expectRefusal(t, err, "image runtime")
			expectRefusal(t, err, tc.reason)
		})
	}
}

func TestCompareVersionsFollowsSemVerPrecedence(t *testing.T) {
	ordered := []string{"0.9.9", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2",
		"1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.2.0", "1.10.0", "10.0.0"}
	for i := range ordered {
		for j := range ordered {
			if got, want := compareVersions(ordered[i], ordered[j]), max(-1, min(1, i-j)); got != want {
				t.Fatalf("compareVersions(%s, %s) = %d, want %d", ordered[i], ordered[j], got, want)
			}
		}
	}
	if compareVersions("1.0.0+build.1", "1.0.0+build.2") != 0 {
		t.Fatal("build metadata must not affect precedence")
	}
}
