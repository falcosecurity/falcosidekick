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
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadRegularFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, data, 0o600))
		return path
	}
	exact := write("exact", bytes.Repeat([]byte("a"), MaxFileSize))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(exact, link))

	data, err := ReadRegularFile(write("small", []byte("token\n")))
	require.NoError(t, err)
	assert.Equal(t, "token\n", string(data))

	data, err = ReadRegularFile(link)
	require.NoError(t, err, "a symlink to a regular file is read, as Kubernetes secret mounts need")
	assert.Len(t, data, MaxFileSize)

	_, err = ReadRegularFile(write("large", bytes.Repeat([]byte("a"), MaxFileSize+1)))
	require.ErrorIs(t, err, ErrFileTooLarge)

	_, err = ReadRegularFile(dir)
	require.ErrorIs(t, err, ErrNotRegularFile)

	_, err = ReadRegularFile(filepath.Join(dir, "missing"))
	require.ErrorIs(t, err, fs.ErrNotExist)
}

func TestFileProblemNeverNamesThePath(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{&fs.PathError{Op: "open", Path: "/secret/path", Err: fs.ErrNotExist}, "file does not exist"},
		{&fs.PathError{Op: "open", Path: "/secret/path", Err: fs.ErrPermission}, "cannot read file"},
		{ErrNotRegularFile, "not a regular file"},
		{ErrFileTooLarge, "larger than 1 MiB"},
	} {
		assert.Equal(t, tc.want, FileProblem(tc.err))
	}
}

// A FIFO without a writer would block a plain read forever.
func TestReadRegularFileRefusesFIFOWithoutBlocking(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))

	done := make(chan error, 1)
	go func() {
		_, err := ReadRegularFile(fifo)
		done <- err
	}()
	select {
	case err := <-done:
		require.ErrorIs(t, err, ErrNotRegularFile)
	case <-time.After(5 * time.Second):
		t.Fatal("ReadRegularFile blocked on a FIFO")
	}
}
