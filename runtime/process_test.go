package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const (
	execProbeID = "dev.stellwerk.exec-probe"
	// The swapped executable is this test binary with verifiedMarker patched
	// to swappedMarker. The started plugin prints the marker compiled into the
	// bytes it runs, which also works under emulation, where /proc/self/exe
	// names the emulator instead of the plugin.
	verifiedMarker = "stellwerk-exec-marker:verified-bytes"
	swappedMarker  = "stellwerk-exec-marker:swapped--bytes"
)

// TestMain lets child copies of this test binary play the launcher
// (RUNTIME_TEST_LAUNCHER) and the plugin the launcher starts. The launcher
// strips RUNTIME_TEST_* from the plugin environment, so the plugin recognises
// itself by its plugin ID instead.
func TestMain(m *testing.M) {
	if os.Getenv("PLUGIN_ID") == execProbeID {
		reportExecutedImage()
	}
	if mode := os.Getenv("RUNTIME_TEST_LAUNCHER"); mode != "" {
		runTestLauncher(mode, os.Args[1:])
	}
	os.Exit(m.Run())
}

// reportExecutedImage prints the marker compiled into the running bytes and
// what the kernel calls the executable, or with
// STELLWERK_PLUGIN_EXEC_PROBE=environment the environment it was started with.
func reportExecutedImage() {
	if os.Getenv("STELLWERK_PLUGIN_EXEC_PROBE") == "environment" {
		for _, item := range os.Environ() {
			fmt.Println(item)
		}
		os.Exit(0)
	}
	name, err := os.Readlink("/proc/self/exe")
	if err != nil {
		name = "unavailable"
	}
	fmt.Println(verifiedMarker, name)
	os.Exit(0)
}

// runTestLauncher runs the real launcher. The swap modes replace the package
// executable after verification and sealing, immediately before exec: the
// window a concurrent writer would aim for.
func runTestLauncher(mode string, args []string) {
	err := func() error {
		if mode == "run" {
			return execute(args)
		}
		in, err := parseInputs(args[0], args[1:])
		if err != nil {
			return err
		}
		plugin, err := prepareLaunch(in)
		if err != nil {
			return err
		}
		path := filepath.Join(in.packageDir, filepath.FromSlash(expectedExecutablePath(in.platform)))
		if err := swapExecutable(path, mode, os.Getenv("RUNTIME_TEST_REPLACEMENT")); err != nil {
			return err
		}
		return plugin.exec()
	}()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	os.Exit(0)
}

// swapExecutable makes path hold the replacement bytes, executable, either by
// atomically renaming a new file over it or by rewriting the same inode.
func swapExecutable(path, mode, replacement string) error {
	content, err := os.ReadFile(replacement)
	if err != nil {
		return err
	}
	switch mode {
	case "rename":
		temporary := path + ".swap"
		if err := os.WriteFile(temporary, content, 0555); err != nil {
			return err
		}
		return os.Rename(temporary, path)
	case "overwrite":
		if err := os.Chmod(path, 0644); err != nil {
			return err
		}
		if err := os.WriteFile(path, content, 0644); err != nil {
			return err
		}
		return os.Chmod(path, 0555)
	default:
		return fmt.Errorf("unknown swap mode %q", mode)
	}
}
