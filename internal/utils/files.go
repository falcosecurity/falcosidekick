// Copyright (C) 2026 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"syscall"
)

// MaxFileSize bounds every file an output reads: secrets, header values, certificates.
const MaxFileSize = 1 << 20

// ErrNotRegularFile and ErrFileTooLarge describe files ReadRegularFile refuses.
var (
	ErrNotRegularFile = errors.New("not a regular file")
	ErrFileTooLarge   = errors.New("larger than 1 MiB")
)

// ReadRegularFile reads a regular file of at most MaxFileSize. The open does not wait for
// a writer, so a FIFO is refused instead of blocking the caller.
func ReadRegularFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) //nolint:gosec // operator or API-checked path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, ErrNotRegularFile
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFileSize {
		return nil, ErrFileTooLarge
	}
	return data, nil
}

// FileProblem describes a ReadRegularFile error without the path or the OS error,
// which can disclose the file system layout.
func FileProblem(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "file does not exist"
	case errors.Is(err, ErrNotRegularFile), errors.Is(err, ErrFileTooLarge):
		return err.Error()
	default:
		return "cannot read file"
	}
}
