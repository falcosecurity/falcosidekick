// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/types"
)

func TestResolveNatsAuthMode(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		authFiles natsAuthFiles
		wantMode  natsAuthMode
		wantErr   bool
	}{
		{
			name:      "no auth files",
			authFiles: natsAuthFiles{},
			wantMode:  natsAuthModeNone,
		},
		{
			name: "creds file only",
			authFiles: natsAuthFiles{
				credsFile: "test.creds",
			},
			wantMode: natsAuthModeCredsFile,
		},
		{
			name: "nkey seed file only",
			authFiles: natsAuthFiles{
				nkeySeedFile: "seed.nk",
			},
			wantMode: natsAuthModeNkeySeedFile,
		},
		{
			name: "jwt and nkey seed files",
			authFiles: natsAuthFiles{
				jwtFile:      "user.jwt",
				nkeySeedFile: "seed.nk",
			},
			wantMode: natsAuthModeJWTAndNkeySeedFile,
		},
		{
			name: "jwt file without nkey seed file is invalid",
			authFiles: natsAuthFiles{
				jwtFile: "user.jwt",
			},
			wantErr: true,
		},
		{
			name: "creds file with nkey seed file is invalid",
			authFiles: natsAuthFiles{
				credsFile:    "test.creds",
				nkeySeedFile: "seed.nk",
			},
			wantErr: true,
		},
		{
			name: "creds file with jwt file is invalid",
			authFiles: natsAuthFiles{
				credsFile: "test.creds",
				jwtFile:   "user.jwt",
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotMode, err := resolveNatsAuthMode(tc.authFiles)
			if tc.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.wantMode, gotMode)
		})
	}
}

func TestValidateNatsAuthConfig(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	credsFile := writeTestFile(t, tempDir, "test.creds", "credentials")
	jwtFile := writeTestFile(t, tempDir, "user.jwt", "header.payload.signature")
	nkeySeedFile := writeValidNkeySeedFile(t, tempDir)

	testCases := []struct {
		name    string
		cfg     *types.Configuration
		wantErr bool
	}{
		{
			name: "no advanced auth is valid",
			cfg:  natsConfig("", "", ""),
		},
		{
			name: "creds auth is valid",
			cfg:  natsConfig(credsFile, "", ""),
		},
		{
			name: "nkey auth is valid",
			cfg:  natsConfig("", nkeySeedFile, ""),
		},
		{
			name: "jwt auth is valid",
			cfg:  natsConfig("", nkeySeedFile, jwtFile),
		},
		{
			name:    "jwt without seed is invalid",
			cfg:     natsConfig("", "", jwtFile),
			wantErr: true,
		},
		{
			name:    "creds with nkey is invalid",
			cfg:     natsConfig(credsFile, nkeySeedFile, ""),
			wantErr: true,
		},
		{
			name:    "missing creds file is invalid",
			cfg:     natsConfig(filepath.Join(tempDir, "missing.creds"), "", ""),
			wantErr: true,
		},
		{
			name:    "missing nkey seed file is invalid",
			cfg:     natsConfig("", filepath.Join(tempDir, "missing.nk"), ""),
			wantErr: true,
		},
		{
			name:    "missing jwt file is invalid",
			cfg:     natsConfig("", nkeySeedFile, filepath.Join(tempDir, "missing.jwt")),
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateNatsAuthConfig(tc.cfg)
			if tc.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestNatsConnectOptions(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	credsFile := writeTestFile(t, tempDir, "test.creds", "credentials")
	jwtFile := writeTestFile(t, tempDir, "user.jwt", "header.payload.signature")
	nkeySeedFile := writeValidNkeySeedFile(t, tempDir)
	invalidSeedFile := writeTestFile(t, tempDir, "invalid.seed", "not-a-seed")

	testCases := []struct {
		name    string
		cfg     *types.Configuration
		wantLen int
		wantNil bool
		wantErr bool
	}{
		{
			name:    "no auth returns no options",
			cfg:     natsConfig("", "", ""),
			wantNil: true,
		},
		{
			name:    "creds auth returns one option",
			cfg:     natsConfig(credsFile, "", ""),
			wantLen: 1,
		},
		{
			name:    "nkey auth returns one option",
			cfg:     natsConfig("", nkeySeedFile, ""),
			wantLen: 1,
		},
		{
			name:    "jwt auth returns one option",
			cfg:     natsConfig("", nkeySeedFile, jwtFile),
			wantLen: 1,
		},
		{
			name:    "jwt without seed returns error",
			cfg:     natsConfig("", "", jwtFile),
			wantErr: true,
		},
		{
			name:    "invalid nkey seed returns error",
			cfg:     natsConfig("", invalidSeedFile, ""),
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			options, err := natsConnectOptions(tc.cfg)
			if tc.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			if tc.wantNil {
				require.Nil(t, options)
			} else {
				require.Len(t, options, tc.wantLen)
			}
		})
	}
}

func natsConfig(credsFile, nkeySeedFile, jwtFile string) *types.Configuration {
	cfg := &types.Configuration{}
	cfg.Nats.CredsFile = credsFile
	cfg.Nats.NkeySeedFile = nkeySeedFile
	cfg.Nats.JWTFile = jwtFile
	return cfg
}

func writeValidNkeySeedFile(t *testing.T, dir string) string {
	t.Helper()

	keyPair, err := nkeys.CreatePair(nkeys.PrefixByteUser)
	require.NoError(t, err)
	seed, err := keyPair.Seed()
	require.NoError(t, err)

	return writeTestFile(t, dir, "user.seed", string(seed))
}

func writeTestFile(t *testing.T, dir, fileName, content string) string {
	t.Helper()

	path := filepath.Join(dir, fileName)
	err := os.WriteFile(path, []byte(content), 0o600)
	require.NoError(t, err)
	return path
}
