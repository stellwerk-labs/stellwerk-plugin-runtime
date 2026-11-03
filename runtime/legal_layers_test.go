package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMetadataAndLegalLayerPolicy(t *testing.T) {
	hash := strings.Repeat("a", 64)
	layer := func(mediaType, title string, size int64) ociDescriptor {
		return ociDescriptor{MediaType: mediaType, Digest: "sha256:" + hash, Size: size,
			Annotations: map[string]string{titleAnnotation: title}}
	}
	manifest := layer(manifestMediaType, "plugin-manifest.json", 100)
	metadata := layer(metadataMediaType, "registration-manifest.json", 100)
	license := layer(licenseMediaType, "LICENSE", 100)
	for _, test := range []struct {
		name   string
		layers []ociDescriptor
		reason string
	}{
		{"old package", nil, ""},
		{"registration and notices", []ociDescriptor{metadata, license, layer(licenseMediaType, "licenses/go/example.org/lib/LICENSE", 100)}, ""},
		{"metadata at limit", []ociDescriptor{layer(metadataMediaType, "registration-manifest.json", metadataFileLimit)}, ""},
		{"metadata outside fixed path", []ociDescriptor{layer(metadataMediaType, "registration.json", 1)}, "not part of the package format"},
		{"metadata cannot masquerade as legal", []ociDescriptor{layer(licenseMediaType, "registration-manifest.json", 1)}, "not part of the package format"},
		{"legal outside legal paths", []ociDescriptor{layer(licenseMediaType, "NOTICE", 1)}, "not part of the package format"},
		{"legal directory is not a file", []ociDescriptor{layer(licenseMediaType, "licenses", 1)}, "not part of the package format"},
		{"unknown fallback refused", []ociDescriptor{layer("application/vnd.stellwerk.plugin.asset.v1", "LICENSE", 1)}, "not part of the package format"},
		{"duplicate registration", []ociDescriptor{metadata, metadata}, "not a unique package path"},
		{"duplicate legal", []ociDescriptor{license, license}, "not a unique package path"},
		{"traversal", []ociDescriptor{layer(licenseMediaType, "licenses/../LICENSE", 1)}, "not a unique package path"},
		{"backslash", []ociDescriptor{layer(licenseMediaType, `licenses/go\LICENSE`, 1)}, "not a unique package path"},
		{"encoded traversal", []ociDescriptor{layer(licenseMediaType, "licenses/%2e%2e/LICENSE", 1)}, "not a unique package path"},
		{"control character", []ociDescriptor{layer(licenseMediaType, "licenses/a\nLICENSE", 1)}, "not a unique package path"},
		{"absolute path", []ociDescriptor{layer(licenseMediaType, "/LICENSE", 1)}, "not a unique package path"},
		{"directory conflict", []ociDescriptor{layer(licenseMediaType, "licenses/go", 1), layer(licenseMediaType, "licenses/go/LICENSE", 1)}, "conflicts with file"},
		{"reverse directory conflict", []ociDescriptor{layer(licenseMediaType, "licenses/go/LICENSE", 1), layer(licenseMediaType, "licenses/go", 1)}, "conflicts with file"},
		{"archive media", []ociDescriptor{layer("application/vnd.oci.image.layer.v1.tar", "licenses/archive", 1)}, "not part of the package format"},
		{"metadata per file", []ociDescriptor{layer(metadataMediaType, "registration-manifest.json", metadataFileLimit+1)}, "exceeds the package size limits"},
		{"legal per file", []ociDescriptor{layer(licenseMediaType, "LICENSE", licenseFileLimit+1)}, "exceeds the package size limits"},
		{"invalid digest", []ociDescriptor{{MediaType: licenseMediaType, Digest: "sha256:bad", Size: 1, Annotations: license.Annotations}}, "invalid descriptor"},
		{"negative metadata size", []ociDescriptor{layer(metadataMediaType, "registration-manifest.json", -1)}, "invalid descriptor"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := checkLayers(append([]ociDescriptor{manifest}, test.layers...), hash)
			if test.reason == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				expectRefusal(t, err, test.reason)
			}
		})
	}
	for _, key := range []string{"io.deis.oras.content.unpack", "io.deis.oras.content.digest"} {
		d := layer(licenseMediaType, "licenses/archive", 1)
		d.Annotations[key] = "true"
		expectRefusal(t, checkLayers([]ociDescriptor{manifest, d}, hash), "is an archive")
	}
	for _, test := range []struct {
		name   string
		count  int
		size   int64
		reason string
	}{
		{"legal aggregate at limit", licenseTotalLimit / licenseFileLimit, licenseFileLimit, ""},
		{"legal aggregate exceeds limit", licenseTotalLimit/licenseFileLimit + 1, licenseFileLimit, "exceeds the package size limits"},
		{"legal count at limit", licenseLayerLimit, 1, ""},
		{"legal count exceeds limit", licenseLayerLimit + 1, 1, "exceeds the package size limits"},
	} {
		t.Run(test.name, func(t *testing.T) {
			layers := []ociDescriptor{manifest}
			for i := 0; i < test.count; i++ {
				layers = append(layers, layer(licenseMediaType, fmt.Sprintf("licenses/%d", i), test.size))
			}
			err := checkLayers(layers, hash)
			if test.reason == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				expectRefusal(t, err, test.reason)
			}
		})
	}
}

// A complete synthetic 96-file package includes both executable platforms,
// registration metadata, root licensing, dependency notices and static UI.
// Real publisher signatures and attestations authenticate its exact envelope.
func fullLegalPayload() map[string][]byte {
	files := map[string][]byte{"registration-manifest.json": []byte(`{"pluginId":"dev.stellwerk.native-probe"}`), "LICENSE": []byte("Package license\n")}
	for i := 0; i < 86; i++ {
		files[fmt.Sprintf("licenses/go/example.org/dependency-%d/LICENSE", i)] = []byte(fmt.Sprintf("Dependency %d legal terms\n", i))
	}
	for i := 0; i < 5; i++ {
		files[fmt.Sprintf("ui/asset-%d.js", i)] = []byte(fmt.Sprintf("// UI asset %d\n", i))
	}
	return files
}

func TestOfflineBundleFullLegalPayload(t *testing.T) {
	f := newBundleFixtureWithFiles(t, fullLegalPayload())
	var pkg ociManifest
	if err := json.Unmarshal(f.pkgData, &pkg); err != nil {
		t.Fatal(err)
	}
	if len(pkg.Layers) != 96 {
		t.Fatalf("got %d package files, want 96", len(pkg.Layers))
	}
	if _, err := f.load(); err != nil {
		t.Fatal(err)
	}
}

func TestOfflineBundleAuthenticatesMetadataAndLegalBytes(t *testing.T) {
	for _, title := range []string{"LICENSE", "registration-manifest.json", "licenses/go/example.org/dependency-0/LICENSE"} {
		for _, mutation := range []string{"changed bytes", "wrong size", "symlink"} {
			t.Run(title+"/"+mutation, func(t *testing.T) {
				f := newBundleFixtureWithFiles(t, fullLegalPayload())
				var pkg ociManifest
				if err := json.Unmarshal(f.pkgData, &pkg); err != nil {
					t.Fatal(err)
				}
				for _, layer := range pkg.Layers {
					if layer.Annotations[titleAnnotation] != title {
						continue
					}
					path := f.blob(layer.Digest)
					data := fullLegalPayload()[title]
					switch mutation {
					case "changed bytes":
						data[0] ^= 1
					case "wrong size":
						data = append(data, 'x')
					case "symlink":
						if err := os.Remove(path); err != nil {
							t.Fatal(err)
						}
						if err := os.Symlink("/does-not-exist", path); err != nil {
							t.Fatal(err)
						}
						_, err := f.load()
						expectRefusal(t, err, "unexpected entry")
						return
					}
					if err := os.WriteFile(path, data, 0644); err != nil {
						t.Fatal(err)
					}
					_, err := f.load()
					expectRefusal(t, err, "does not match its digest or size")
					return
				}
				t.Fatal("missing fixture layer")
			})
		}
	}
}

func TestPublisherBindsMetadataAndLegalDescriptors(t *testing.T) {
	for _, title := range []string{"LICENSE", "registration-manifest.json"} {
		t.Run(title, func(t *testing.T) {
			f := newBundleFixtureWithFiles(t, fullLegalPayload())
			bootstrap, err := loadTrustBootstrap(filepath.Join(f.dir, bundleTrustFile))
			if err != nil {
				t.Fatal(err)
			}
			var pkg struct {
				SchemaVersion int `json:"schemaVersion"`
				ociManifest
			}
			if err := json.Unmarshal(f.pkgData, &pkg); err != nil {
				t.Fatal(err)
			}
			for i := range pkg.Layers {
				if pkg.Layers[i].Annotations[titleAnnotation] == title {
					pkg.Layers[i].Digest = "sha256:" + digest([]byte("replacement content"))
					pkg.Layers[i].Size = int64(len("replacement content"))
				}
			}
			changed := bundleJSON(t, pkg)
			// Rebinding an otherwise valid package digest cannot make the original
			// publisher signature authorize different legal or registration bytes.
			if err := checkEnvelope(changed, "sha256:"+digest(changed), f.manifest.Package.ManifestSHA256); err != nil {
				t.Fatal(err)
			}
			_, err = verifyRelease(bootstrap, f.manifest.PluginID, f.signature, nil, nil, changed, publisherTestNow, "")
			expectRefusal(t, err, "does not cover this OCI manifest")
		})
	}
}
