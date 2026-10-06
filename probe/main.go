// Probe is a test-only plugin executable without any product logic. It proves
// that the runtime starts a plugin and is not an integration test.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

var version = "0.0.0"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	stateDirectory := os.Getenv("PLUGIN_STATE")
	if stateDirectory == "" {
		os.Exit(1)
	}
	if err := os.MkdirAll(stateDirectory, 0700); err != nil {
		os.Exit(1)
	}
	notePath := filepath.Join(stateDirectory, "note")
	var mutex sync.Mutex
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /v1/info", func(writer http.ResponseWriter, _ *http.Request) {
		mutex.Lock()
		defer mutex.Unlock()
		note, err := os.ReadFile(notePath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			http.Error(writer, "state unavailable", http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"id": os.Getenv("PLUGIN_ID"), "version": version, "protocol": 1,
			"trust": os.Getenv("PLUGIN_TRUST_STATE"), "uid": os.Getuid(), "pid": os.Getpid(),
			"note": string(note), "ambientCanaryPresent": os.Getenv("AMBIENT_CANARY") != "",
		})
	})
	mux.HandleFunc("POST /v1/note", func(writer http.ResponseWriter, request *http.Request) {
		mutex.Lock()
		defer mutex.Unlock()
		value, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, 1024))
		if err != nil {
			http.Error(writer, "invalid note", http.StatusBadRequest)
			return
		}
		if err := os.WriteFile(notePath, value, 0600); err != nil {
			http.Error(writer, "state unavailable", http.StatusInternalServerError)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
	server := &http.Server{Addr: os.Getenv("PLUGIN_LISTEN"), Handler: mux, ReadHeaderTimeout: 2 * time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		os.Exit(1)
	}
	<-done
}
