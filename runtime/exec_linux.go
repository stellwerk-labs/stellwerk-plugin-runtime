package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// Linux UAPI values from include/uapi/linux/memfd.h and fcntl.h. The frozen
// syscall package does not define them.
const (
	mfdCloexec      = 0x0001
	mfdAllowSealing = 0x0002
	mfdExec         = 0x0010 // Linux 6.3+: explicitly executable memfd
	fAddSeals       = 1024 + 9
	fSealSeal       = 0x0001
	fSealShrink     = 0x0002
	fSealGrow       = 0x0004
	fSealWrite      = 0x0008
	immutableSeals  = fSealSeal | fSealShrink | fSealGrow | fSealWrite
)

// sealedImage copies verified executable bytes into an anonymous memory file
// and seals it. The kernel then rejects every write, truncation, growth and
// seal change from any process, this one included, so the image that
// executes is byte for byte the one that was hashed.
func sealedImage(binary []byte) (*os.File, error) {
	fd, err := memfdCreate("stellwerk-plugin", mfdCloexec|mfdAllowSealing|mfdExec)
	if errors.Is(err, syscall.EINVAL) {
		// Kernels before 6.3 reject MFD_EXEC; their memfds are executable.
		fd, err = memfdCreate("stellwerk-plugin", mfdCloexec|mfdAllowSealing)
	}
	if err != nil {
		return nil, fmt.Errorf("memfd_create: %w", err)
	}
	image := os.NewFile(fd, "stellwerk-plugin")
	if _, err := image.Write(binary); err != nil {
		image.Close()
		return nil, err
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, image.Fd(), fAddSeals, immutableSeals); errno != 0 {
		image.Close()
		return nil, fmt.Errorf("seal memfd: %w", errno)
	}
	return image, nil
}

func memfdCreate(name string, flags uintptr) (uintptr, error) {
	pointer, err := syscall.BytePtrFromString(name)
	if err != nil {
		return 0, err
	}
	fd, _, errno := syscall.Syscall(sysMemfdCreate, uintptr(unsafe.Pointer(pointer)), flags, 0)
	if errno != 0 {
		return 0, errno
	}
	return fd, nil
}

// exec replaces the launcher with the sealed image. /proc/self/fd/N is the
// memfd itself, so resolving it never touches the package filesystem. The
// memfd is close-on-exec and does not leak into the plugin.
func (l launch) exec() error {
	return syscall.Exec(fmt.Sprintf("/proc/self/fd/%d", l.image.Fd()), l.argv, l.env)
}
