package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func uiFixture(t *testing.T) inputs {
	t.Helper()
	in := fixture(t)
	in.consoleOrigin = "https://console.example.test"
	assets := uiAssetManifest{SchemaVersion: "1", PluginID: in.expectedID, Version: in.expectedVer}
	assets.UI.SDKVersion = "1"
	assets.UI.Entrypoint = "/embed/"
	assets.UI.RuntimeConfig = "/embed/config.js"
	for name, content := range map[string]string{"index.html": "<!doctype html><h1>Isolated plugin</h1>", "assets/main.js": "console.log('isolated')"} {
		file := filepath.Join(in.packageDir, "ui", filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(content), 0444); err != nil {
			t.Fatal(err)
		}
		assets.Files = append(assets.Files, struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
			Size   int64  `json:"size"`
		}{name, digest([]byte(content)), int64(len(content))})
	}
	data, err := json.Marshal(assets)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in.packageDir, "ui/plugin-ui-manifest.json"), data, 0444); err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := os.ReadFile(in.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest packageManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.UI = &executable{Path: "ui/plugin-ui-manifest.json", SHA256: digest(data)}
	manifestBytes, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(in.manifestPath, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(in.manifestPath, manifestBytes, 0444); err != nil {
		t.Fatal(err)
	}
	in.expectedHash = digest(manifestBytes)
	if err := validate(in); err != nil {
		t.Fatal(err)
	}
	return in
}

func TestStaticUIUsesOnlyVerifiedAssetsAndPublicRuntimeConfig(t *testing.T) {
	in := uiFixture(t)
	if err := os.WriteFile(filepath.Join(in.packageDir, "ui/unlisted.txt"), []byte("not public"), 0444); err != nil {
		t.Fatal(err)
	}
	handler, err := uiHandler(in)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	for _, test := range []struct {
		method, path string
		status       int
		contains     string
	}{
		{"GET", "/embed/", 200, "Isolated plugin"}, {"GET", "/embed/assets/main.js", 200, "isolated"},
		{"GET", "/embed/config.js", 200, `"allowedConsoleOrigin":"https://console.example.test"`},
		{"HEAD", "/embed/config.js", 200, ""}, {"GET", "/health", 204, ""},
		{"GET", "/embed/unlisted.txt", 404, ""}, {"GET", "/plugin-manifest.json", 404, ""},
		{"GET", "/embed/plugin-ui-manifest.json", 404, ""}, {"GET", "/embed/../plugin-manifest.json", 404, ""},
		{"GET", "/embed/assets%2fmain.js", 404, ""}, {"POST", "/embed/", 405, ""},
	} {
		t.Run(test.method+test.path, func(t *testing.T) {
			request, err := http.NewRequest(test.method, server.URL+test.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Cookie", "session-token=must-not-be-reflected")
			response, err := server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			data, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != test.status || !strings.Contains(string(data), test.contains) {
				t.Fatalf("status %d, expected %d", response.StatusCode, test.status)
			}
			if strings.Contains(string(data), "must-not-be-reflected") || response.Header.Get("Set-Cookie") != "" {
				t.Fatal("static server must not reflect credentials or issue cookies")
			}
			if response.Header.Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(response.Header.Get("Content-Security-Policy"), "connect-src 'none'") {
				t.Fatal("missing isolation headers")
			}
			if test.method == "HEAD" && len(data) != 0 {
				t.Fatal("HEAD returned a body")
			}
		})
	}
	for _, host := range []string{"console.example.test:8444", "CONSOLE.EXAMPLE.TEST", "console.example.test."} {
		request := httptest.NewRequest("GET", "https://ui.example.test/embed/", nil)
		request.Host = host
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusMisdirectedRequest {
			t.Fatal("same-hostname UI must fail closed")
		}
	}
}

func TestStaticUIFailsClosedOnTamperingAndInvalidOrigin(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(inputs)
	}{
		{"asset bytes", func(in inputs) {
			if err := os.Chmod(filepath.Join(in.packageDir, "ui/index.html"), 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(in.packageDir, "ui/index.html"), []byte("tampered"), 0444); err != nil {
				t.Fatal(err)
			}
		}},
		{"manifest bytes", func(in inputs) {
			if err := os.Chmod(filepath.Join(in.packageDir, "ui/plugin-ui-manifest.json"), 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(in.packageDir, "ui/plugin-ui-manifest.json"), []byte("{}"), 0444); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink component", func(in inputs) {
			if err := os.Rename(filepath.Join(in.packageDir, "ui/assets"), filepath.Join(in.packageDir, "moved-assets")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("../moved-assets", filepath.Join(in.packageDir, "ui/assets")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			in := uiFixture(t)
			test.mutate(in)
			if _, err := uiHandler(in); err == nil {
				t.Fatal("tampered package was served")
			}
		})
	}
	for _, origin := range []string{"", "http://console.test", "https://user:password@console.test", "https://console.test/path", "https://console.test?x=y", "https://console.test#x"} {
		in := uiFixture(t)
		in.consoleOrigin = origin
		if _, err := uiHandler(in); err == nil {
			t.Fatal("unsafe Console origin accepted")
		}
	}
}

func TestUIAssetManifestBoundsAndPaths(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*uiAssetManifest)
	}{
		{"wrong plugin", func(m *uiAssetManifest) { m.PluginID = "dev.example.other" }},
		{"unsupported SDK", func(m *uiAssetManifest) { m.UI.SDKVersion = "99" }},
		{"duplicate", func(m *uiAssetManifest) { m.Files = append(m.Files, m.Files[0]) }},
		{"traversal", func(m *uiAssetManifest) { m.Files[0].Path = "../plugin-manifest.json" }},
		{"encoded path", func(m *uiAssetManifest) { m.Files[0].Path = "assets%2fmain.js" }},
		{"runtime configuration", func(m *uiAssetManifest) { m.Files[0].Path = "config.js" }},
		{"oversize", func(m *uiAssetManifest) { m.Files[0].Size = uiAssetLimit + 1 }},
		{"negative size", func(m *uiAssetManifest) { m.Files[0].Size = -1 }},
		{"empty catalogue", func(m *uiAssetManifest) { m.Files = nil }},
		{"alternate entrypoint", func(m *uiAssetManifest) { m.UI.Entrypoint = "/" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			in := uiFixture(t)
			manifestData, err := os.ReadFile(in.manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			var manifest packageManifest
			if err := json.Unmarshal(manifestData, &manifest); err != nil {
				t.Fatal(err)
			}
			assetPath := filepath.Join(in.packageDir, manifest.UI.Path)
			data, err := os.ReadFile(assetPath)
			if err != nil {
				t.Fatal(err)
			}
			var assets uiAssetManifest
			if err := json.Unmarshal(data, &assets); err != nil {
				t.Fatal(err)
			}
			test.change(&assets)
			data, err = json.Marshal(assets)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(assetPath, 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(assetPath, data, 0444); err != nil {
				t.Fatal(err)
			}
			manifest.UI.SHA256 = digest(data)
			manifestData, err = json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(in.manifestPath, manifestData, 0444); err != nil {
				t.Fatal(err)
			}
			in.expectedHash = digest(manifestData)
			if err := validate(in); err == nil {
				t.Fatal("invalid digest-bound UI manifest was accepted")
			}
		})
	}
}

// The UI container's only process is serve-ui. SIGTERM must stop it cleanly
// with exit status 0, not kill it, so a Deployment update never reports a
// failed container.
func TestServeUIShutsDownCleanlyOnSIGTERM(t *testing.T) {
	in := uiFixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	server := exec.CommandContext(ctx, self, "serve-ui", "--package-dir="+in.packageDir,
		"--manifest="+in.manifestPath, "--state-file="+in.stateFile, "--plugin-id="+in.expectedID,
		"--plugin-version="+in.expectedVer, "--manifest-sha256="+in.expectedHash, "--platform="+in.platform,
		"--development-untrusted", "--listen="+address, "--console-origin="+in.consoleOrigin)
	server.Env = []string{"RUNTIME_TEST_LAUNCHER=run"}
	var stderr strings.Builder
	server.Stderr = &stderr
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	ready := false
	for attempt := 0; attempt < 100 && !ready; attempt++ {
		response, err := http.Get("http://" + address + "/health")
		if err == nil {
			response.Body.Close()
			ready = response.StatusCode == http.StatusNoContent
		}
		if !ready {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if !ready {
		_ = server.Process.Kill()
		_ = server.Wait()
		t.Fatalf("UI server never became ready: %s", stderr.String())
	}
	if err := server.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := server.Wait(); err != nil {
		t.Fatalf("UI server did not exit cleanly on SIGTERM: %v %s", err, stderr.String())
	}
	if _, err := http.Get("http://" + address + "/health"); err == nil {
		t.Fatal("UI server still accepts connections after SIGTERM")
	}
}
