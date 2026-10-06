package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func envelopeLayer(mediaType, title, digest string, size int64) string {
	return fmt.Sprintf(`{"mediaType":%q,"digest":%q,"size":%d,"annotations":{"org.opencontainers.image.title":%q}}`, mediaType, digest, size, title)
}

func TestVerifyEnvelope(t *testing.T) {
	hash := strings.Repeat("a", 64)
	blob := "sha256:" + strings.Repeat("c", 64)
	layer := envelopeLayer(manifestMediaType, "plugin-manifest.json", "sha256:"+hash, 200)
	amd64 := envelopeLayer(executableMediaType, "bin/linux/amd64/plugin", blob, 6<<20)
	arm64 := envelopeLayer(executableMediaType, "bin/linux/arm64/plugin", blob, 6<<20)
	asset := envelopeLayer(uiAssetMediaType, "ui/index.html", blob, 100)
	envelope := func(layers ...string) string {
		return `{"schemaVersion":2,"artifactType":"application/vnd.stellwerk.plugin.package.v1","config":{},"layers":[` + strings.Join(layers, ",") + `]}`
	}
	valid := envelope(layer, amd64, arm64, asset)
	tooManyAssets := []string{layer}
	for i := 0; i <= uiLayerLimit; i++ {
		tooManyAssets = append(tooManyAssets, envelopeLayer(uiAssetMediaType, fmt.Sprintf("ui/%d.js", i), blob, 1))
	}
	nearlyFull := []string{layer,
		envelopeLayer(executableMediaType, "bin/linux/amd64/plugin", blob, binaryLimit),
		envelopeLayer(executableMediaType, "bin/linux/arm64/plugin", blob, binaryLimit)}
	for i := 0; i < 3; i++ {
		nearlyFull = append(nearlyFull, envelopeLayer(uiAssetMediaType, fmt.Sprintf("ui/%d.bin", i), blob, uiAssetLimit/2))
	}
	for _, test := range []struct {
		name, data, hash string
		reason           string // empty for a valid envelope
	}{
		{"valid", valid, hash, ""},
		{"manifest only", envelope(layer), hash, ""},
		{"wrong type", strings.Replace(valid, "package.v1", "other.v1", 1), hash, "unsupported OCI package envelope"},
		{"wrong schema", strings.Replace(valid, `"schemaVersion":2`, `"schemaVersion":3`, 1), hash, "unsupported OCI package envelope"},
		{"wrong target manifest", valid, strings.Repeat("b", 64), "descriptor does not match launcher inputs"},
		{"duplicate layer", envelope(layer, layer), hash, "not a unique package path"},
		{"absent layer", envelope(amd64), hash, "exactly one plugin manifest layer"},
		{"zero size", strings.Replace(valid, `"size":200`, `"size":0`, 1), hash, "descriptor does not match launcher inputs"},
		{"oversized manifest", strings.Replace(valid, `"size":200`, `"size":262145`, 1), hash, "exceeds the package size limits"},
		{"trailing document", valid + `{}`, hash, "invalid character"},
		{"invalid JSON", `{`, hash, "unexpected end of JSON input"},
		{"untitled layer", envelope(layer, `{"mediaType":"`+uiAssetMediaType+`","digest":"`+blob+`","size":1}`), hash, "not a unique package path"},
		{"traversal title", envelope(layer, envelopeLayer(uiAssetMediaType, "ui/../plugin-manifest.json", blob, 1)), hash, "not a unique package path"},
		{"absolute title", envelope(layer, envelopeLayer(uiAssetMediaType, "/ui/index.html", blob, 1)), hash, "not a unique package path"},
		{"backslash title", envelope(layer, envelopeLayer(uiAssetMediaType, `ui\index.html`, blob, 1)), hash, "not a unique package path"},
		{"receipt overwrite", envelope(layer, envelopeLayer(uiAssetMediaType, "runtime-state.json", blob, 1)), hash, "not part of the package format"},
		{"duplicate executable", envelope(layer, amd64, amd64), hash, "not a unique package path"},
		{"unsupported platform", envelope(layer, envelopeLayer(executableMediaType, "bin/linux/riscv64/plugin", blob, 1)), hash, "not part of the package format"},
		{"executable outside bin", envelope(layer, envelopeLayer(executableMediaType, "ui/plugin", blob, 1)), hash, "not part of the package format"},
		{"unknown media type", envelope(layer, envelopeLayer("application/vnd.oci.image.layer.v1.tar", "ui/x", blob, 1)), hash, "not part of the package format"},
		{"oversized executable", envelope(layer, envelopeLayer(executableMediaType, "bin/linux/amd64/plugin", blob, binaryLimit+1)), hash, "exceeds the package size limits"},
		{"oversized asset", envelope(layer, envelopeLayer(uiAssetMediaType, "ui/big.bin", blob, uiAssetLimit+1)), hash, "exceeds the package size limits"},
		{"oversized package", envelope(nearlyFull...), hash, "exceeds the package size limits"},
		{"too many assets", envelope(tooManyAssets...), hash, "exceeds the package size limits"},
		{"negative size", envelope(layer, envelopeLayer(uiAssetMediaType, "ui/x", blob, -1)), hash, "invalid descriptor"},
		{"malformed blob digest", envelope(layer, envelopeLayer(uiAssetMediaType, "ui/x", "sha256:XYZ", 1)), hash, "invalid descriptor"},
		{"archive layer", envelope(layer, `{"mediaType":"`+uiAssetMediaType+`","digest":"`+blob+`","size":131,"annotations":{"io.deis.oras.content.digest":"`+blob+`","io.deis.oras.content.unpack":"true","org.opencontainers.image.title":"ui"}}`), hash, "is an archive"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "manifest.json")
			if err := os.WriteFile(path, []byte(test.data), 0o600); err != nil {
				t.Fatal(err)
			}
			err := execute([]string{"verify-envelope", "--oci-manifest=" + path,
				"--package-digest=sha256:" + digest([]byte(test.data)), "--manifest-sha256=" + test.hash})
			switch {
			case test.reason == "" && err != nil:
				t.Fatalf("rejected a valid envelope: %v", err)
			case test.reason != "" && (err == nil || !strings.Contains(err.Error(), test.reason)):
				t.Fatalf("expected rejection %q, got %v", test.reason, err)
			}
		})
	}
}

func TestVerifyEnvelopeRejectsUnboundInputs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{},
		{"--oci-manifest=" + path},
		{"--oci-manifest=" + path, "--package-digest=sha256:" + strings.Repeat("0", 64), "--manifest-sha256=" + strings.Repeat("a", 64)},
		{"--oci-manifest=" + path, "--package-digest=sha256:" + strings.Repeat("A", 64), "--manifest-sha256=" + strings.Repeat("a", 64)},
		{"--oci-manifest=" + path, "--package-digest=sha256:" + digest([]byte(`{}`)), "--manifest-sha256=" + strings.Repeat("a", 64), "extra"},
	} {
		if err := verifyEnvelope(args); err == nil {
			t.Fatalf("accepted unbound input %v", args)
		}
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := verifyEnvelope([]string{"--oci-manifest=" + link,
		"--package-digest=sha256:" + digest([]byte(`{}`)), "--manifest-sha256=" + strings.Repeat("a", 64)}); err == nil {
		t.Fatal("accepted symlinked envelope")
	}
}
