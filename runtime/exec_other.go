//go:build !linux

package main

import (
	"errors"
	"os"
)

var errNativeExecutionUnsupported = errors.New("native-static-v1 plugins execute only on Linux")

func sealedImage([]byte) (*os.File, error) { return nil, errNativeExecutionUnsupported }

func (launch) exec() error { return errNativeExecutionUnsupported }
