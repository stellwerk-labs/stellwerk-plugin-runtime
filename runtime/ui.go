package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const uiAssetLimit = 64 << 20

type uiAssetManifest struct {
	SchemaVersion string `json:"schema_version"`
	PluginID      string `json:"plugin_id"`
	Version       string `json:"version"`
	UI            struct {
		SDKVersion    string `json:"sdk_version"`
		Entrypoint    string `json:"entrypoint"`
		RuntimeConfig string `json:"runtime_config"`
	} `json:"ui"`
	Files []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	} `json:"files"`
}

type uiAssets struct {
	manifest uiAssetManifest
	files    map[string][]byte
}

// packageFile rejects symlink components as well as traversal. Only immutable
// manifest-declared files are ever exposed by the static server.
func packageFile(root, relative string, limit int64) ([]byte, error) {
	if !fs.ValidPath(relative) || strings.ContainsAny(relative, "\\\x00") {
		return nil, errors.New("invalid package path")
	}
	current := root
	parts := strings.Split(relative, "/")
	for index, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 || (index < len(parts)-1 && !info.IsDir()) {
			return nil, errors.New("package path contains a symlink or non-directory")
		}
	}
	return boundedRegularFile(current, limit)
}

func loadUIAssets(in inputs, manifest packageManifest) (*uiAssets, error) {
	if manifest.UI == nil || manifest.UI.Path != "ui/plugin-ui-manifest.json" || !validSHA256(manifest.UI.SHA256) {
		return nil, errors.New("plugin package has no valid UI manifest")
	}
	data, err := packageFile(in.packageDir, manifest.UI.Path, manifestLimit)
	if err != nil {
		return nil, err
	}
	if digest(data) != manifest.UI.SHA256 {
		return nil, errors.New("UI manifest digest mismatch")
	}
	result := &uiAssets{files: map[string][]byte{}}
	if err := decodeStrict(data, &result.manifest); err != nil {
		return nil, err
	}
	m := result.manifest
	if m.SchemaVersion != "1" || m.PluginID != manifest.PluginID || m.UI.SDKVersion != "1" || !versionPattern.MatchString(m.Version) || m.UI.Entrypoint != "/embed/" || m.UI.RuntimeConfig != "/embed/config.js" || len(m.Files) == 0 || len(m.Files) > 2000 {
		return nil, errors.New("plugin_incompatible: UI manifest contract")
	}
	var total int64
	for _, file := range m.Files {
		if file.Path == "config.js" || file.Path == "plugin-ui-manifest.json" || !fs.ValidPath(file.Path) || strings.ContainsAny(file.Path, "\\%?#:") || !validSHA256(file.SHA256) || file.Size < 0 || file.Size > uiAssetLimit {
			return nil, errors.New("invalid immutable UI asset")
		}
		if _, exists := result.files[file.Path]; exists {
			return nil, errors.New("duplicate UI asset")
		}
		total += file.Size
		if total > uiAssetLimit {
			return nil, errors.New("UI package exceeds 64 MiB")
		}
		content, err := packageFile(in.packageDir, "ui/"+file.Path, file.Size)
		if err != nil {
			return nil, err
		}
		if int64(len(content)) != file.Size || digest(content) != file.SHA256 {
			return nil, errors.New("UI asset digest or size mismatch")
		}
		result.files[file.Path] = content
	}
	if _, exists := result.files["index.html"]; !exists {
		return nil, errors.New("UI package requires index.html")
	}
	return result, nil
}

func uiHandler(in inputs) (http.Handler, error) {
	pkg, _, err := validatedPackage(in)
	if err != nil {
		return nil, err
	}
	assets, err := loadUIAssets(in, pkg.manifest)
	if err != nil {
		return nil, err
	}
	origin, err := url.Parse(in.consoleOrigin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" || origin.String() != in.consoleOrigin {
		return nil, errors.New("UI requires one canonical HTTPS Console origin")
	}
	config, err := json.Marshal(map[string]string{"allowedConsoleOrigin": in.consoleOrigin})
	if err != nil {
		return nil, err
	}
	config = append(append([]byte("window.__STELLWERK_PLUGIN_UI_CONFIG__="), config...), ';')
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; connect-src 'none'; form-action 'none'; frame-ancestors "+in.consoleOrigin+"; img-src 'self' data:; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		requestOrigin, originErr := url.Parse("https://" + r.Host)
		if originErr != nil || requestOrigin.Hostname() == "" || strings.EqualFold(strings.TrimSuffix(requestOrigin.Hostname(), "."), strings.TrimSuffix(origin.Hostname(), ".")) {
			http.Error(w, "Console and UI require separate hostnames", http.StatusMisdirectedRequest)
			return
		}
		if r.URL.Path == assets.manifest.UI.RuntimeConfig {
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			if r.Method == http.MethodGet {
				_, _ = w.Write(config)
			}
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/embed/") || r.URL.RawPath != "" {
			http.NotFound(w, r)
			return
		}
		relative := strings.TrimPrefix(r.URL.Path, "/embed/")
		if relative == "" {
			relative = "index.html"
		}
		if !fs.ValidPath(relative) {
			http.NotFound(w, r)
			return
		}
		content, exists := assets.files[relative]
		if !exists {
			http.NotFound(w, r)
			return
		}
		contentType := mime.TypeByExtension(path.Ext(relative))
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		w.Header().Set("Content-Type", contentType)
		http.ServeContent(w, r, relative, time.Time{}, bytes.NewReader(content))
	}), nil
}

// TLS terminates at the existing Gateway. This process has only read-only
// package files, no backend credentials, and no plugin domain implementation.
// It is its container's PID 1, so it handles SIGTERM itself: stop accepting,
// drain in-flight requests within the grace period and exit 0.
func serveUI(in inputs) error {
	handler, err := uiHandler(in)
	if err != nil {
		return err
	}
	server := &http.Server{Addr: in.listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	terminated, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	drained := make(chan error, 1)
	go func() {
		<-terminated.Done()
		deadline, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		drained <- server.Shutdown(deadline)
	}()
	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("static UI server: %w", err)
	}
	return <-drained
}
