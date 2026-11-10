package main

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func httpsFixtureFiles(t *testing.T, f *bundleFixture) map[string][]byte {
	t.Helper()
	layout := &bundleLayout{dir: filepath.Join(f.dir, "oci"), present: map[string]bool{}, reached: map[string]bool{}}
	for _, entry := range f.index {
		layout.present[strings.TrimPrefix(entry.Digest, "sha256:")] = true
	}
	// The real closure verifier determines the package-only graph, not a test
	// implementation of graph traversal.
	blobs, err := os.ReadDir(filepath.Join(layout.dir, "blobs", "sha256"))
	if err != nil {
		t.Fatal(err)
	}
	for _, blob := range blobs {
		layout.present[blob.Name()] = true
	}
	listed := map[string]ociDescriptor{}
	roots := []ociIndexEntry{}
	for _, entry := range f.index[:4] {
		listed[entry.Digest] = entry.ociDescriptor
		roots = append(roots, entry)
	}
	bootstrap, err := loadTrustBootstrap(filepath.Join(f.dir, "publishers.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := layout.verifyPackage(f.manifest, listed, bootstrap, publisherTestNow, ""); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`), "index.json": bundleJSON(t, ociIndex{SchemaVersion: 2, MediaType: ociIndexMediaType, Manifests: roots})}
	for hash := range layout.reached {
		data, err := os.ReadFile(f.blob("sha256:" + hash))
		if err != nil {
			t.Fatal(err)
		}
		files["blobs/sha256/"+hash] = data
	}
	return files
}

func httpsTar(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := tar.NewWriter(&out)
	for _, name := range slices.Sorted(maps.Keys(files)) {
		data := files[name]
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(data)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func httpsServerFiles(t *testing.T, handler http.HandlerFunc) (string, string, string) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(server.URL)
	credentials := filepath.Join(dir, "config.json")
	config := map[string]any{"auths": map[string]any{u.Host: map[string]string{"auth": base64.StdEncoding.EncodeToString([]byte("reader:private-token"))}}}
	if err := os.WriteFile(credentials, bundleJSON(t, config), 0600); err != nil {
		t.Fatal(err)
	}
	return server.URL + "/plugin.tar", credentials, ca
}

func httpsArgs(t *testing.T, f *bundleFixture, raw, credentials, ca string, archive []byte) []string {
	t.Helper()
	return []string{"--url=" + raw, "--credentials=" + credentials, "--ca-file=" + ca, "--archive-sha256=" + digest(archive), "--package-digest=" + f.manifest.Package.Digest, "--signature-digest=" + f.manifest.Package.Signature, "--sbom-digest=" + f.manifest.Package.SBOM, "--provenance-digest=" + f.manifest.Package.Provenance, "--manifest-sha256=" + f.manifest.Package.ManifestSHA256, "--plugin-id=" + f.manifest.PluginID, "--plugin-version=" + f.manifest.PluginVersion, "--trust-bootstrap=" + filepath.Join(f.dir, "publishers.json"), "--package-dir=" + t.TempDir(), "--evidence-dir=" + t.TempDir()}
}

func argValue(args []string, name string) string {
	for _, arg := range args {
		if value, ok := strings.CutPrefix(arg, "--"+name+"="); ok {
			return value
		}
	}
	return ""
}

func replaceHTTPSArg(args []string, name, value string) []string {
	args = slices.Clone(args)
	for i, arg := range args {
		if strings.HasPrefix(arg, "--"+name+"=") {
			args[i] = "--" + name + "=" + value
			return args
		}
	}
	return append(args, "--"+name+"="+value)
}

func TestHTTPSFetchPreservesTheSignedPackage(t *testing.T) {
	f := newBundleFixtureWithFiles(t, map[string][]byte{"LICENSE": []byte("licence"), "registration-manifest.json": []byte(`{"pluginId":"dev.stellwerk.native-probe"}`)})
	archive := httpsTar(t, httpsFixtureFiles(t, f))
	calls := 0
	raw, credentials, ca := httpsServerFiles(t, func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "reader" || password != "private-token" {
			t.Error("missing scoped Basic credentials")
			w.WriteHeader(401)
			return
		}
		calls++
		_, _ = w.Write(archive)
	})
	args := httpsArgs(t, f, raw, credentials, ca, archive)
	if err := fetchHTTPS(args); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("requests=%d", calls)
	}
	out, evidence := argValue(args, "package-dir"), argValue(args, "evidence-dir")
	for name, want := range map[string][]byte{"oci-manifest.json": f.pkgData, "LICENSE": []byte("licence"), "bin/linux/amd64/plugin": []byte("plugin amd64"), "bin/linux/arm64/plugin": []byte("plugin arm64")} {
		got, err := os.ReadFile(filepath.Join(out, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s bytes changed: %v", name, err)
		}
	}
	signature, err := os.ReadFile(filepath.Join(evidence, "oci-manifest.sigstore.json"))
	if err != nil || !bytes.Equal(signature, f.signature) {
		t.Fatalf("signature bytes changed: %v", err)
	}
	// Exercise the unchanged downstream publisher command against the exact
	// files the chart hands to independent Cosign next.
	if err := verifyPublisher([]string{"--trust-bootstrap=" + filepath.Join(f.dir, "publishers.json"), "--bundle=" + filepath.Join(evidence, "oci-manifest.sigstore.json"), "--sbom-bundle=" + filepath.Join(evidence, "sbom", "sbom.sigstore.json"), "--provenance-bundle=" + filepath.Join(evidence, "provenance", "provenance.sigstore.json"), "--oci-manifest=" + filepath.Join(out, "oci-manifest.json"), "--plugin-id=" + f.manifest.PluginID, "--key-dir=" + t.TempDir()}); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPSFetchRefusesTamperAndMissingEvidenceBeforeMaterializing(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		mutate       func(*testing.T, *bundleFixture, map[string][]byte, []string) []string
	}{
		{"archive hash", "archive SHA256", func(_ *testing.T, _ *bundleFixture, _ map[string][]byte, args []string) []string {
			return replaceHTTPSArg(args, "archive-sha256", strings.Repeat("0", 64))
		}},
		{"payload bytes", "digest or size", func(_ *testing.T, f *bundleFixture, files map[string][]byte, args []string) []string {
			var envelope ociManifest
			_ = json.Unmarshal(f.pkgData, &envelope)
			files["blobs/sha256/"+strings.TrimPrefix(envelope.Layers[1].Digest, "sha256:")] = []byte("tampered")
			return args
		}},
		{"wrong version", "plugin manifest is not", func(_ *testing.T, _ *bundleFixture, _ map[string][]byte, args []string) []string {
			return replaceHTTPSArg(args, "plugin-version", "2.0.0")
		}},
		{"missing provenance", "missing from", func(_ *testing.T, f *bundleFixture, files map[string][]byte, args []string) []string {
			delete(files, "blobs/sha256/"+strings.TrimPrefix(f.manifest.Package.Provenance, "sha256:"))
			return args
		}},
		{"missing required SBOM", "requires a signed SBOM", func(t *testing.T, f *bundleFixture, files map[string][]byte, args []string) []string {
			var index ociIndex
			_ = json.Unmarshal(files["index.json"], &index)
			index.Manifests = slices.DeleteFunc(index.Manifests, func(e ociIndexEntry) bool { return e.Digest == f.manifest.Package.SBOM })
			files["index.json"] = bundleJSON(t, index)
			bootstrap := writeBootstrap(t, map[string]any{"id": "stellwerk", "pluginIds": []string{f.manifest.PluginID}, "policy": managedKeyNoTlogPolicy, "requireSBOM": true, "keys": []any{f.signer.validPin()}})
			return replaceHTTPSArg(replaceHTTPSArg(args, "sbom-digest", ""), "trust-bootstrap", bootstrap)
		}},
		{"foreign blob", "foreign blob", func(_ *testing.T, _ *bundleFixture, files map[string][]byte, args []string) []string {
			files["blobs/sha256/"+digest([]byte("foreign"))] = []byte("foreign")
			return args
		}},
		{"untrusted publisher", "does not pin", func(t *testing.T, f *bundleFixture, _ map[string][]byte, args []string) []string {
			other := newBundleFixture(t)
			return replaceHTTPSArg(args, "trust-bootstrap", filepath.Join(other.dir, "publishers.json"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBundleFixture(t)
			files := httpsFixtureFiles(t, f)
			var archive []byte
			raw, credentials, ca := httpsServerFiles(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(archive) })
			args := httpsArgs(t, f, raw, credentials, ca, nil)
			args = tc.mutate(t, f, files, args)
			archive = httpsTar(t, files)
			if tc.name != "archive hash" {
				args = replaceHTTPSArg(args, "archive-sha256", digest(archive))
			}
			err := fetchHTTPS(args)
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("want %q refusal, got %v", tc.reason, err)
			}
			for _, dir := range []string{argValue(args, "package-dir"), argValue(args, "evidence-dir")} {
				entries, err := os.ReadDir(dir)
				if err != nil || len(entries) != 0 {
					t.Fatalf("unverified payload was written: %v", entries)
				}
			}
		})
	}
}

func TestHTTPSDownloadScopesCredentialsAndRefusesRedirects(t *testing.T) {
	leaked := false
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true; w.WriteHeader(200) }))
	defer target.Close()
	raw, credentials, ca := httpsServerFiles(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) })
	err := downloadPackage(raw, strings.Repeat("0", 64), credentials, ca, filepath.Join(t.TempDir(), "archive"))
	if err == nil || !strings.Contains(err.Error(), "302") || leaked {
		t.Fatalf("redirect followed: %v, leaked=%v", err, leaked)
	}
	for _, bad := range []string{strings.Replace(raw, "https:", "http:", 1), strings.Replace(raw, "https://", "https://reader:token@", 1), raw + "?token=private-token", raw + "#fragment"} {
		if err := downloadPackage(bad, "", credentials, ca, filepath.Join(t.TempDir(), "archive")); err == nil {
			t.Fatal("unsafe URL accepted")
		}
	}
	badCA := filepath.Join(t.TempDir(), "bad-ca")
	_ = os.WriteFile(badCA, []byte("not a CA"), 0600)
	if err := downloadPackage(raw, "", credentials, badCA, filepath.Join(t.TempDir(), "archive")); err == nil {
		t.Fatal("invalid CA accepted")
	}
	if err := downloadPackage(raw, "", credentials, "", filepath.Join(t.TempDir(), "archive")); err == nil {
		t.Fatal("untrusted TLS server accepted")
	}
	config := map[string]any{"auths": map[string]any{"other.test": map[string]string{"auth": base64.StdEncoding.EncodeToString([]byte("reader:private-token"))}}}
	_ = os.WriteFile(credentials, bundleJSON(t, config), 0600)
	if err := downloadPackage(raw, "", credentials, ca, filepath.Join(t.TempDir(), "archive")); err == nil || !strings.Contains(err.Error(), "exact URL host") {
		t.Fatalf("credential scope accepted: %v", err)
	}
}

func TestHTTPSArchiveRefusesUnsafeEntries(t *testing.T) {
	for _, header := range []*tar.Header{
		{Name: "../escape", Typeflag: tar.TypeReg}, {Name: "/escape", Typeflag: tar.TypeReg}, {Name: "blobs/sha256/../escape", Typeflag: tar.TypeReg},
		{Name: "oci-layout", Typeflag: tar.TypeSymlink, Linkname: "/escape"}, {Name: "oci-layout", Typeflag: tar.TypeLink, Linkname: "/escape"},
		{Name: "oci-layout", Typeflag: tar.TypeFifo}, {Name: "source/private.go", Typeflag: tar.TypeReg}, {Name: "blobs/sha256/" + strings.Repeat("a", 64), Typeflag: tar.TypeReg, Size: binaryLimit + 1},
	} {
		t.Run(header.Name+string(header.Typeflag), func(t *testing.T) {
			var buffer bytes.Buffer
			writer := tar.NewWriter(&buffer)
			if err := writer.WriteHeader(header); err != nil {
				t.Fatal(err)
			}
			if header.Size > binaryLimit {
				// Preserve a complete outer tar shape so the declared entry
				// size, rather than an absent footer, causes the refusal.
				_, _ = buffer.Write(make([]byte, 1024))
			} else if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			archive := filepath.Join(t.TempDir(), "archive.tar")
			_ = os.WriteFile(archive, buffer.Bytes(), 0600)
			_, err := extractPackageArchive(archive, t.TempDir())
			if err == nil {
				t.Fatal("unsafe entry accepted")
			}
			if header.Size > binaryLimit && !strings.Contains(err.Error(), "oversized entry") {
				t.Fatalf("declared size guard was not reached: %v", err)
			}
		})
	}
	for _, name := range []string{"duplicate", "truncated", "entry count"} {
		t.Run(name, func(t *testing.T) {
			var buffer bytes.Buffer
			writer := tar.NewWriter(&buffer)
			count := 2
			if name == "entry count" {
				count = httpsEntryLimit + 1
			}
			for i := 0; i < count; i++ {
				entry := "oci-layout"
				if name == "entry count" {
					entry = "blobs/sha256/" + digest([]byte(strings.Repeat("a", i)))
				}
				_ = writer.WriteHeader(&tar.Header{Name: entry, Typeflag: tar.TypeReg, Size: 1})
				_, _ = writer.Write([]byte("a"))
			}
			_ = writer.Close()
			data := buffer.Bytes()
			if name == "truncated" {
				data = data[:513]
			}
			archive := filepath.Join(t.TempDir(), "archive.tar")
			_ = os.WriteFile(archive, data, 0600)
			if _, err := extractPackageArchive(archive, t.TempDir()); err == nil {
				t.Fatal("unsafe tar accepted")
			}
		})
	}
}

func TestHTTPSFetchRetainsInstalledDigestKeyPolicy(t *testing.T) {
	f := newBundleFixture(t)
	archive := httpsTar(t, httpsFixtureFiles(t, f))
	raw, credentials, ca := httpsServerFiles(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(archive) })
	expired := f.signer.pin(publisherTestNow.Add(-2*time.Hour), publisherTestNow.Add(-time.Hour))
	bootstrap := writeBootstrap(t, managedPublisher(managedKeyNoTlogPolicy, expired))
	args := replaceHTTPSArg(httpsArgs(t, f, raw, credentials, ca, archive), "trust-bootstrap", bootstrap)
	if err := fetchHTTPS(args); err == nil {
		t.Fatal("expired key accepted for new installation")
	}
	if err := fetchHTTPS(append(args, "--installed-digest=sha256:"+strings.Repeat("0", 64))); err == nil {
		t.Fatal("unrelated installed digest bypassed expiry")
	}
	if err := fetchHTTPS(append(args, "--installed-digest="+f.pkg.Digest)); err != nil {
		t.Fatalf("existing digest refused: %v", err)
	}
}

func TestHTTPSDownloadBoundAndErrorRedaction(t *testing.T) {
	raw, credentials, ca := httpsServerFiles(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "99999999999")
		w.WriteHeader(200)
	})
	err := downloadPackage(raw, "", credentials, ca, filepath.Join(t.TempDir(), "archive"))
	if err == nil || !strings.Contains(err.Error(), "archive limit") {
		t.Fatalf("oversized download accepted: %v", err)
	}
	raw, credentials, ca = httpsServerFiles(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		_, _ = io.WriteString(w, "private-token private-server-diagnostic")
	})
	err = downloadPackage(raw, "", credentials, ca, filepath.Join(t.TempDir(), "archive"))
	if err == nil || !strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "private-") {
		t.Fatalf("unsafe HTTP diagnostic: %v", err)
	}
}

func TestHTTPSDownloadAllowsOneApprovedCredentialFreeRedirect(t *testing.T) {
	body := []byte("approved archive")
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie", "Referer"} {
			if r.Header.Get(name) != "" {
				t.Errorf("redirect leaked %s", name)
			}
		}
		_, _ = w.Write(body)
	}))
	defer target.Close()
	raw, credentials, ca := httpsServerFiles(t, func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := r.BasicAuth(); !ok {
			t.Error("initial request lacks Basic auth")
		}
		http.Redirect(w, r, target.URL+"/plugin?X-Amz-Signature=private-query", 302)
	})
	u, _ := url.Parse(target.URL)
	if err := downloadPackage(raw, digest(body), credentials, ca, filepath.Join(t.TempDir(), "archive"), u.Host); err != nil {
		t.Fatal(err)
	}
	// A second hop is refused even when both hosts are approved.
	raw, credentials, ca = httpsServerFiles(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/plugin.tar" {
			http.Redirect(w, r, "/again", 302)
			return
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("same-host redirect leaked credentials")
		}
		http.Redirect(w, r, target.URL, 302)
	})
	first, _ := url.Parse(raw)
	err := downloadPackage(raw, digest(body), credentials, ca, filepath.Join(t.TempDir(), "archive"), first.Host, u.Host)
	if err == nil || !strings.Contains(err.Error(), "302") {
		t.Fatalf("second redirect followed: %v", err)
	}
}

func TestHTTPSInstalledDigestDoesNotBypassRevocation(t *testing.T) {
	f := newBundleFixture(t)
	archive := httpsTar(t, httpsFixtureFiles(t, f))
	raw, credentials, ca := httpsServerFiles(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(archive) })
	var bootstrap map[string]any
	if err := json.Unmarshal(f.trust, &bootstrap); err != nil {
		t.Fatal(err)
	}
	bootstrap["revokedKeyIds"] = []string{f.signer.id}
	trust := filepath.Join(t.TempDir(), "publishers.json")
	if err := os.WriteFile(trust, bundleJSON(t, bootstrap), 0600); err != nil {
		t.Fatal(err)
	}
	args := replaceHTTPSArg(httpsArgs(t, f, raw, credentials, ca, archive), "trust-bootstrap", trust)
	err := fetchHTTPS(append(args, "--installed-digest="+f.pkg.Digest))
	if err == nil || !strings.Contains(err.Error(), "revokes") {
		t.Fatalf("installed digest bypassed revocation: %v", err)
	}
}

func TestHTTPSCredentialsRefuseUnscopedFiles(t *testing.T) {
	auth := base64.StdEncoding.EncodeToString([]byte("reader:fixture-token"))
	for _, config := range []string{
		`{}`, `{"auths":{"gitlab.example":{"auth":"not-base64"}}}`,
		`{"auths":{"gitlab.example":{"auth":"` + auth + `","identitytoken":"secret"}}}`,
		`{"auths":{"gitlab.example":{"auth":"` + auth + `"},"other.example":{"auth":"` + auth + `"}}}`,
		`{"auths":{"gitlab.example":{"auth":"` + auth + `"}},"credsStore":"helper"}`,
		`{"auths":{"gitlab.example":{"auth":"` + auth + `"}}} {}`,
	} {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(config), 0600); err != nil {
			t.Fatal(err)
		}
		err := downloadPackage("https://gitlab.example/file", strings.Repeat("0", 64), path, "", filepath.Join(t.TempDir(), "archive"))
		if err == nil || !strings.Contains(err.Error(), "credentials") || strings.Contains(err.Error(), "secret") {
			t.Fatalf("unscoped config accepted or exposed: %v", err)
		}
	}
}
