package main

import (
	"embed"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const originalHelmChartDigest = "sha256:e651532301bc341be962859b4d9f1f4687bda403d65db479f98a7aa29ef52702"

// Keep the original public bytes available when linux-test.sh copies only the
// test executable into its sealed scratch container.
//
//go:embed testdata/original-helm-chart-0.1.0-rc.1/index.json testdata/original-helm-chart-0.1.0-rc.1/blobs/sha256/*
var originalHelmChartFiles embed.FS

// originalHelmChart copies only the three unchanged public chart blobs into a
// test directory. It neither builds a chart nor creates a key or signature.
func originalHelmChart(t *testing.T) (*bundleLayout, ociDescriptor) {
	t.Helper()
	fixture := "testdata/original-helm-chart-0.1.0-rc.1"
	data, err := originalHelmChartFiles.ReadFile(fixture + "/index.json")
	if err != nil {
		t.Fatal(err)
	}
	var index ociIndex
	if err := json.Unmarshal(data, &index); err != nil {
		t.Fatal(err)
	}
	if len(index.Manifests) != 1 || index.Manifests[0].Digest != originalHelmChartDigest ||
		index.Manifests[0].Size != 650 || index.Manifests[0].MediaType != ociManifestMediaType {
		t.Fatalf("original public chart descriptor changed: %+v", index)
	}
	layout := &bundleLayout{dir: t.TempDir(), present: map[string]bool{}, reached: map[string]bool{}}
	store := filepath.Join(layout.dir, "blobs", "sha256")
	if err := os.MkdirAll(store, 0755); err != nil {
		t.Fatal(err)
	}
	for _, hash := range []string{
		strings.TrimPrefix(originalHelmChartDigest, "sha256:"),
		"b1b2e5d9e274f1b8002d9e4452f189f60343d8d43a6ff0602c4f8e0a348f6a0a",
		"7a6d46e7b935cbecfb5515ff5bfeb68c30f43dc56c521755f66e1ce017fcdcff",
	} {
		blob, err := originalHelmChartFiles.ReadFile(fixture + "/blobs/sha256/" + hash)
		if err != nil {
			t.Fatal(err)
		}
		if digest(blob) != hash {
			t.Fatalf("original public chart blob %s changed", hash)
		}
		if err := os.WriteFile(filepath.Join(store, hash), blob, 0644); err != nil {
			t.Fatal(err)
		}
		layout.present[hash] = true
	}
	return layout, index.Manifests[0].ociDescriptor
}

func TestOfflineBundleChartAcceptsOriginalHelmManifest(t *testing.T) {
	layout, descriptor := originalHelmChart(t)
	data, err := layout.read(descriptor, ociMetadataLimit)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if _, present := fields["mediaType"]; present {
		t.Fatal("regression fixture must retain the original absent manifest mediaType")
	}
	if err := layout.chart(descriptor, "0.1.0-rc.1"); err != nil {
		t.Fatalf("unchanged original public Helm chart rejected: %v", err)
	}
	if err := layout.foreign(); err != nil {
		t.Fatal(err)
	}
}

func putChartTestBlob(t *testing.T, layout *bundleLayout, mediaType string, data []byte) ociDescriptor {
	t.Helper()
	descriptor := ociDescriptor{MediaType: mediaType, Digest: "sha256:" + digest(data), Size: int64(len(data))}
	hash := strings.TrimPrefix(descriptor.Digest, "sha256:")
	if err := os.WriteFile(filepath.Join(layout.dir, "blobs", "sha256", hash), data, 0644); err != nil {
		t.Fatal(err)
	}
	layout.present[hash] = true
	return descriptor
}

func TestOfflineBundleChartMediaTypeAndSchemaRemainStrict(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any, *ociDescriptor)
		accept bool
	}{
		{"explicit OCI media type", func(m map[string]any, _ *ociDescriptor) { m["mediaType"] = ociManifestMediaType }, true},
		{"null media type", func(m map[string]any, _ *ociDescriptor) { m["mediaType"] = nil }, false},
		{"empty media type", func(m map[string]any, _ *ociDescriptor) { m["mediaType"] = "" }, false},
		{"wrong media type", func(m map[string]any, _ *ociDescriptor) { m["mediaType"] = ociIndexMediaType }, false},
		{"numeric media type", func(m map[string]any, _ *ociDescriptor) { m["mediaType"] = 1 }, false},
		{"array media type", func(m map[string]any, _ *ociDescriptor) { m["mediaType"] = []any{} }, false},
		{"missing schema version", func(m map[string]any, _ *ociDescriptor) { delete(m, "schemaVersion") }, false},
		{"null schema version", func(m map[string]any, _ *ociDescriptor) { m["schemaVersion"] = nil }, false},
		{"schema version one", func(m map[string]any, _ *ociDescriptor) { m["schemaVersion"] = 1 }, false},
		{"schema version three", func(m map[string]any, _ *ociDescriptor) { m["schemaVersion"] = 3 }, false},
		{"string schema version", func(m map[string]any, _ *ociDescriptor) { m["schemaVersion"] = "2" }, false},
		{"wrong parent descriptor type", func(_ map[string]any, d *ociDescriptor) { d.MediaType = ociIndexMediaType }, false},
		{"missing parent descriptor type", func(_ map[string]any, d *ociDescriptor) { d.MediaType = "" }, false},
		{"missing config", func(m map[string]any, _ *ociDescriptor) { delete(m, "config") }, false},
		{"wrong config type", func(m map[string]any, _ *ociDescriptor) {
			m["config"].(map[string]any)["mediaType"] = "application/json"
		}, false},
		{"missing layer", func(m map[string]any, _ *ociDescriptor) { m["layers"] = []any{} }, false},
		{"extra layer", func(m map[string]any, _ *ociDescriptor) {
			m["layers"] = append(m["layers"].([]any), m["layers"].([]any)[0])
		}, false},
		{"wrong layer type", func(m map[string]any, _ *ociDescriptor) {
			m["layers"].([]any)[0].(map[string]any)["mediaType"] = "application/octet-stream"
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout, descriptor := originalHelmChart(t)
			data, err := layout.read(descriptor, ociMetadataLimit)
			if err != nil {
				t.Fatal(err)
			}
			var manifest map[string]any
			if err := json.Unmarshal(data, &manifest); err != nil {
				t.Fatal(err)
			}
			tc.mutate(manifest, &descriptor)
			descriptor = putChartTestBlob(t, layout, descriptor.MediaType, bundleJSON(t, manifest))
			err = layout.chart(descriptor, "0.1.0-rc.1")
			if tc.accept {
				if err != nil {
					t.Fatalf("valid explicit media type rejected: %v", err)
				}
			} else if err == nil || err.Error() != "the chart is not a Helm chart OCI artifact" {
				t.Fatalf("expected chart format refusal, got %v", err)
			}
		})
	}
}

func TestOfflineBundleChartOriginalContentBindingsRemainStrict(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, *bundleLayout, *ociDescriptor, map[string]any)
		reason string
	}{
		{"wrong config digest", func(_ *testing.T, _ *bundleLayout, _ *ociDescriptor, m map[string]any) {
			m["config"].(map[string]any)["digest"] = "sha256:" + strings.Repeat("0", 64)
		}, "blob sha256:" + strings.Repeat("0", 64) + " is missing from the bundle"},
		{"wrong config size", func(_ *testing.T, _ *bundleLayout, _ *ociDescriptor, m map[string]any) {
			m["config"].(map[string]any)["size"] = 1
		}, "blob sha256:b1b2e5d9e274f1b8002d9e4452f189f60343d8d43a6ff0602c4f8e0a348f6a0a does not match its digest or size"},
		{"wrong layer digest", func(_ *testing.T, _ *bundleLayout, _ *ociDescriptor, m map[string]any) {
			m["layers"].([]any)[0].(map[string]any)["digest"] = "sha256:" + strings.Repeat("1", 64)
		}, "blob sha256:" + strings.Repeat("1", 64) + " is missing from the bundle"},
		{"wrong layer size", func(_ *testing.T, _ *bundleLayout, _ *ociDescriptor, m map[string]any) {
			m["layers"].([]any)[0].(map[string]any)["size"] = 1
		}, "blob sha256:7a6d46e7b935cbecfb5515ff5bfeb68c30f43dc56c521755f66e1ce017fcdcff does not match its digest or size"},
		{"wrong chart name", func(t *testing.T, l *bundleLayout, _ *ociDescriptor, m map[string]any) {
			m["config"] = putChartTestBlob(t, l, helmConfigMediaType, bundleJSON(t, map[string]any{"name": "other-chart", "version": "0.1.0-rc.1"}))
		}, "the bundled chart is other-chart 0.1.0-rc.1, bundle.json records native-plugin-runtime 0.1.0-rc.1"},
		{"wrong chart version", func(t *testing.T, l *bundleLayout, _ *ociDescriptor, m map[string]any) {
			m["config"] = putChartTestBlob(t, l, helmConfigMediaType, bundleJSON(t, map[string]any{"name": runtimeChart, "version": "0.2.0"}))
		}, "the bundled chart is native-plugin-runtime 0.2.0, bundle.json records native-plugin-runtime 0.1.0-rc.1"},
		{"tampered original chart layer", func(t *testing.T, l *bundleLayout, _ *ociDescriptor, m map[string]any) {
			value := m["layers"].([]any)[0].(map[string]any)["digest"].(string)
			path := filepath.Join(l.dir, "blobs", "sha256", strings.TrimPrefix(value, "sha256:"))
			if err := os.WriteFile(path, []byte("tampered original chart bytes"), 0644); err != nil {
				t.Fatal(err)
			}
		}, "blob sha256:7a6d46e7b935cbecfb5515ff5bfeb68c30f43dc56c521755f66e1ce017fcdcff does not match its digest or size"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout, descriptor := originalHelmChart(t)
			data, err := layout.read(descriptor, ociMetadataLimit)
			if err != nil {
				t.Fatal(err)
			}
			var manifest map[string]any
			if err := json.Unmarshal(data, &manifest); err != nil {
				t.Fatal(err)
			}
			tc.mutate(t, layout, &descriptor, manifest)
			descriptor = putChartTestBlob(t, layout, descriptor.MediaType, bundleJSON(t, manifest))
			if err := layout.chart(descriptor, "0.1.0-rc.1"); err == nil || err.Error() != tc.reason {
				t.Fatalf("expected %q, got %v", tc.reason, err)
			}
		})
	}

	t.Run("original manifest descriptor size", func(t *testing.T) {
		layout, descriptor := originalHelmChart(t)
		descriptor.Size++
		err := layout.chart(descriptor, "0.1.0-rc.1")
		if want := "blob " + originalHelmChartDigest + " does not match its digest or size"; err == nil || err.Error() != want {
			t.Fatalf("expected %q, got %v", want, err)
		}
	})
}
