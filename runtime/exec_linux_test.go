package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const fGetSeals = 1024 + 10

// execCase packages a copy of this test binary as the plugin and prepares a
// different, equally runnable executable that an attacker could swap in: the
// same binary with its marker patched.
type execCase struct {
	in             inputs
	executable     string
	replacement    string
	replacementSum string
}

func newExecCase(t *testing.T) execCase {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	verified, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	swapped := bytes.ReplaceAll(verified, []byte(verifiedMarker), []byte(swappedMarker))
	if bytes.Equal(swapped, verified) {
		t.Fatal("test binary does not contain its execution marker")
	}
	c := execCase{in: packageFixture(t, execProbeID, verified), replacementSum: digest(swapped)}
	c.executable = filepath.Join(c.in.packageDir, filepath.FromSlash(expectedExecutablePath(c.in.platform)))
	c.replacement = filepath.Join(t.TempDir(), "replacement")
	if err := os.WriteFile(c.replacement, swapped, 0555); err != nil {
		t.Fatal(err)
	}
	if err := validate(c.in); err != nil {
		t.Fatal(err)
	}
	return c
}

// launch runs the launcher in a child process and returns the marker and
// kernel executable name reported by the started plugin.
func (c execCase) launch(t *testing.T, mode string, extraArgs ...string) (string, string, error) {
	t.Helper()
	output, err := c.start(t, mode, nil, extraArgs...)
	if err != nil {
		return "", "", err
	}
	executed, name, ok := strings.Cut(strings.TrimSpace(output), " ")
	if !ok || (executed != verifiedMarker && executed != swappedMarker) {
		t.Fatalf("unexpected plugin report %q", output)
	}
	return executed, name, nil
}

// start runs the launcher in a child process whose environment also holds
// env and returns what the started plugin printed.
func (c execCase) start(t *testing.T, mode string, env []string, extraArgs ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := append([]string{
		"run", "--package-dir=" + c.in.packageDir, "--manifest=" + c.in.manifestPath,
		"--state-file=" + c.in.stateFile, "--plugin-id=" + c.in.expectedID,
		"--plugin-version=" + c.in.expectedVer, "--manifest-sha256=" + c.in.expectedHash,
		"--platform=" + c.in.platform, "--development-untrusted",
	}, extraArgs...)
	command := exec.CommandContext(ctx, self, args...)
	command.Env = append([]string{"RUNTIME_TEST_LAUNCHER=" + mode, "RUNTIME_TEST_REPLACEMENT=" + c.replacement}, env...)
	var stderr strings.Builder
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return string(output), nil
}

func TestRunExecutesTheSealedVerifiedImage(t *testing.T) {
	c := newExecCase(t)
	executed, name, err := c.launch(t, "run")
	if err != nil {
		t.Fatal(err)
	}
	if executed != verifiedMarker {
		t.Fatalf("executed %s", executed)
	}
	// Natively the kernel names the sealed memfd; under emulation it names the
	// emulator. Either way never the package path.
	if strings.Contains(name, c.in.packageDir) {
		t.Fatalf("plugin was executed from the package path %q", name)
	}
	t.Logf("plugin executable as seen by the kernel: %s", name)
	info, err := os.Stat(c.executable)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0111 != 0 {
		t.Fatalf("package executable mode %o; execution must not depend on it", info.Mode().Perm())
	}
}

// The executed plugin learns which installation it is and which package the
// launcher verified, so it can report both to Core. An inherited digest never
// replaces the verified one.
func TestRunHandsThePluginItsInstallationAndVerifiedPackageDigest(t *testing.T) {
	const installation = "0b7e6c1a-3f52-4d8e-9a41-6c2f0e8d5b17"
	c := newExecCase(t)
	output, err := c.start(t, "run", []string{
		"STELLWERK_PLUGIN_EXEC_PROBE=environment", "STELLWERK_INSTALLATION_ID=" + installation,
		"STELLWERK_PACKAGE_SHA256=" + strings.Repeat("0", 64), "HOME=/ambient",
	})
	if err != nil {
		t.Fatal(err)
	}
	environment := strings.Split(strings.TrimSpace(output), "\n")
	for _, expected := range []string{"STELLWERK_INSTALLATION_ID=" + installation, "STELLWERK_PACKAGE_SHA256=" + c.in.expectedHash, "PLUGIN_ID=" + execProbeID} {
		if !slices.Contains(environment, expected) {
			t.Fatalf("plugin environment lacks %s: %q", expected, environment)
		}
	}
	for _, item := range environment {
		if strings.HasPrefix(item, "HOME=") || strings.HasPrefix(item, "RUNTIME_TEST_") || item == "STELLWERK_PACKAGE_SHA256="+strings.Repeat("0", 64) {
			t.Fatalf("plugin environment carries %s", item)
		}
	}
}

func TestSwapBetweenVerificationAndExecRunsOnlyVerifiedBytes(t *testing.T) {
	for _, mode := range []string{"rename", "overwrite"} {
		t.Run(mode, func(t *testing.T) {
			c := newExecCase(t)
			executed, name, err := c.launch(t, mode)
			if err != nil {
				t.Fatal(err)
			}
			onDisk, err := os.ReadFile(c.executable)
			if err != nil {
				t.Fatal(err)
			}
			if digest(onDisk) != c.replacementSum {
				t.Fatal("the swap did not happen; the test proves nothing")
			}
			if executed != verifiedMarker {
				t.Fatalf("launcher executed the swapped bytes via %s", name)
			}
		})
	}
}

// A writer flips the package executable between the verified and a foreign
// binary as fast as it can while the launcher starts again and again. Each
// start must either reject the package or run the verified bytes.
func TestConcurrentSwapsNeverExecuteUnverifiedBytes(t *testing.T) {
	c := newExecCase(t)
	spare := t.TempDir()
	good, bad := filepath.Join(spare, "good"), filepath.Join(spare, "bad")
	if err := os.Link(c.executable, good); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(c.replacement, bad); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var swapper sync.WaitGroup
	swapper.Add(1)
	go func() {
		defer swapper.Done()
		temporary := c.executable + ".swap"
		for flip := 0; ; flip++ {
			select {
			case <-stop:
				return
			default:
			}
			source := good
			if flip%2 == 1 {
				source = bad
			}
			_ = os.Remove(temporary)
			if os.Link(source, temporary) == nil {
				_ = os.Rename(temporary, c.executable)
			}
		}
	}()
	const starts = 64
	verified, rejected := 0, 0
	for start := 0; start < starts; start++ {
		executed, name, err := c.launch(t, "run")
		switch {
		case err != nil && strings.Contains(err.Error(), "executable digest mismatch"):
			rejected++
		case err != nil:
			t.Errorf("start %d failed unexpectedly: %v", start, err)
		case executed == verifiedMarker:
			verified++
		default:
			t.Errorf("start %d executed unverified bytes %s via %s", start, executed, name)
		}
	}
	close(stop)
	swapper.Wait()
	t.Logf("%d starts under concurrent swaps: %d ran verified bytes, %d rejected", starts, verified, rejected)
	if verified == 0 {
		t.Fatal("no start ran the verified bytes; the swap loop starved every launch")
	}
}

func TestSealedImageCannotBeModified(t *testing.T) {
	image, err := sealedImage([]byte("verified payload"))
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	seals, _, errno := syscall.Syscall(syscall.SYS_FCNTL, image.Fd(), fGetSeals, 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	if seals&immutableSeals != immutableSeals {
		t.Fatalf("seals %#x, want at least %#x", seals, immutableSeals)
	}
	if _, err := image.WriteAt([]byte("x"), 0); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("write to sealed image: %v", err)
	}
	if err := image.Truncate(0); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("truncate of sealed image: %v", err)
	}
	// A second open file description, as another process would obtain it.
	reopened, err := os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", image.Fd()), os.O_WRONLY, 0)
	if err == nil {
		_, err = reopened.Write([]byte("x"))
		reopened.Close()
	}
	if err == nil {
		t.Fatal("reopened sealed image accepted a write")
	}
	content, err := os.ReadFile(fmt.Sprintf("/proc/self/fd/%d", image.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "verified payload" {
		t.Fatalf("sealed image holds %q", content)
	}
}

func TestRunFailsClosedBeforeExec(t *testing.T) {
	for _, test := range []struct {
		name, reason string
		mutate       func(c execCase) error
		args, env    []string
	}{
		{"tampered executable", "executable digest mismatch", func(c execCase) error {
			return swapExecutable(c.executable, "rename", c.replacement)
		}, nil, nil},
		{"symlinked executable", "symlink", func(c execCase) error {
			if err := os.Remove(c.executable); err != nil {
				return err
			}
			return os.Symlink(c.replacement, c.executable)
		}, nil, nil},
		{"missing receipt", "validated runtime state unavailable", func(c execCase) error {
			return os.Remove(c.in.stateFile)
		}, nil, nil},
		{"wrong platform", "plugin_incompatible: platform executable", nil, []string{"--platform=linux/riscv64"}, nil},
		{"untrusted without development mode", "package trust state is not executable", nil, []string{"--development-untrusted=false"}, nil},
		{"non-canonical installation ID", "STELLWERK_INSTALLATION_ID must be the installation UUID Core assigned", nil, nil,
			[]string{"STELLWERK_INSTALLATION_ID=0B7E6C1A-3F52-4D8E-9A41-6C2F0E8D5B17"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := newExecCase(t)
			if test.mutate != nil {
				if err := test.mutate(c); err != nil {
					t.Fatal(err)
				}
			}
			output, err := c.start(t, "run", test.env, test.args...)
			if err == nil {
				t.Fatalf("launcher started a plugin that reported %q", output)
			}
			if !strings.Contains(err.Error(), test.reason) {
				t.Fatalf("expected %q, got %v", test.reason, err)
			}
		})
	}
}
