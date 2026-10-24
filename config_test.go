// SPDX-License-Identifier: MIT OR Apache-2.0

package main

import (
	"fmt"
	"os"
	"strings"
	"testing"

	kingpin "github.com/alecthomas/kingpin/v2"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/types"
)

// TestTelegramMessageThreadIDDefaultRegistered guards against regression of #1283:
// the MessageThreadID env var (TELEGRAM_MESSAGETHREADID) and yaml key
// (telegram.messagethreadid) only bind to Configuration.Telegram.MessageThreadID
// when the key is registered in outputDefaults so viper's AutomaticEnv knows about it.
func TestTelegramMessageThreadIDDefaultRegistered(t *testing.T) {
	telegramDefaults, ok := outputDefaults["Telegram"]
	require.True(t, ok, "outputDefaults must contain Telegram entry")
	_, present := telegramDefaults["MessageThreadID"]
	require.True(t, present, "outputDefaults[\"Telegram\"] must register MessageThreadID for viper env binding to work")
}

// TestTelegramMessageThreadIDEnvBinding exercises the same viper setup getConfig()
// uses (SetDefault from outputDefaults + AutomaticEnv with "." -> "_" replacer) and
// confirms TELEGRAM_MESSAGETHREADID flows into Configuration.Telegram.MessageThreadID.
// Without the outputDefaults entry this test fails: viper's AutomaticEnv only binds
// keys it has seen via SetDefault during Unmarshal.
func TestTelegramMessageThreadIDEnvBinding(t *testing.T) {
	t.Setenv("TELEGRAM_MESSAGETHREADID", "4")

	v := viper.New()
	for prefix, m := range outputDefaults {
		for key, val := range m {
			v.SetDefault(prefix+"."+key, val)
		}
	}
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	c := &types.Configuration{}
	require.NoError(t, v.Unmarshal(c))
	require.Equal(t, "4", c.Telegram.MessageThreadID)
}

// TestEnvVarsReachConfig covers documented env vars that were ignored because
// getConfig() never registered their key with viper, and AutomaticEnv only
// binds registered keys.
func TestEnvVarsReachConfig(t *testing.T) {
	tests := []struct {
		env   string
		value string
		got   func(*types.Configuration) any
	}{
		{"YANDEX_S3_MINIMUMPRIORITY", "warning", func(c *types.Configuration) any { return c.Yandex.S3.MinimumPriority }},
		{"NATS_MINIMUMPRIORITY", "error", func(c *types.Configuration) any { return c.Nats.MinimumPriority }},
		{"STAN_MINIMUMPRIORITY", "critical", func(c *types.Configuration) any { return c.Stan.MinimumPriority }},
		{"WAVEFRONT_FLUSHINTERVALSECONDS", "5", func(c *types.Configuration) any { return c.Wavefront.FlushIntervalSeconds }},
	}
	for _, tc := range tests {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv(tc.env, tc.value)

			// getConfig parses os.Args with the global kingpin parser, which rejects the test flags.
			args, cmdLine := os.Args, kingpin.CommandLine
			os.Args, kingpin.CommandLine = []string{"falcosidekick"}, kingpin.New("falcosidekick", "")
			t.Cleanup(func() { os.Args, kingpin.CommandLine = args, cmdLine })

			require.Equal(t, tc.value, fmt.Sprint(tc.got(getConfig())))
		})
	}
}
