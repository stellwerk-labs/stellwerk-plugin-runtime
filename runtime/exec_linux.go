package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

const immutableSeals = unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE

// sealedImage copies verified executable bytes into an anonymous memory file
// and seals it. The kernel then rejects every write, truncation, growth and
// seal change from any process, this one included, so the image that
// executes is byte for byte the one that was hashed.
func sealedImage(binary []byte) (*os.File, error) {
	fd, err := unix.MemfdCreate("stellwerk-plugin", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING|unix.MFD_EXEC)
	if errors.Is(err, unix.EINVAL) {
		// Kernels before 6.3 reject MFD_EXEC; their memfds are executable.
		fd, err = unix.MemfdCreate("stellwerk-plugin", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	}
	if err != nil {
		return nil, fmt.Errorf("memfd_create: %w", err)
	}
	image := os.NewFile(uintptr(fd), "stellwerk-plugin")
	if _, err := image.Write(binary); err != nil {
		image.Close()
		return nil, err
	}
	if _, err := unix.FcntlInt(image.Fd(), unix.F_ADD_SEALS, immutableSeals); err != nil {
		image.Close()
		return nil, fmt.Errorf("seal memfd: %w", err)
	}
	return image, nil
}

// exec replaces the launcher with the sealed image. /proc/self/fd/N is the
// memfd itself, so resolving it never touches the package filesystem. The
// memfd is close-on-exec and does not leak into the plugin.
func (l launch) exec() error {
	return syscall.Exec(fmt.Sprintf("/proc/self/fd/%d", l.image.Fd()), l.argv, l.env)
}
