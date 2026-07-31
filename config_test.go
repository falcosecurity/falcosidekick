// SPDX-License-Identifier: MIT OR Apache-2.0

package main

import (
	"strings"
	"testing"

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

func TestOpenReportDefaultsRegistered(t *testing.T) {
	openReportDefaults, ok := outputDefaults["OpenReport"]
	require.True(t, ok, "outputDefaults must contain OpenReport entry")

	expected := map[string]any{
		"Enabled":         false,
		"Kubeconfig":      "",
		"FalcoNamespace":  "",
		"MinimumPriority": "",
		"MaxEvents":       1000,
	}
	for key, value := range expected {
		require.Contains(t, openReportDefaults, key)
		require.Equal(t, value, openReportDefaults[key])
	}
}

func TestOpenReportEnvBinding(t *testing.T) {
	t.Setenv("OPENREPORT_ENABLED", "true")
	t.Setenv("OPENREPORT_KUBECONFIG", "/tmp/openreport-kubeconfig")
	t.Setenv("OPENREPORT_FALCONAMESPACE", "falco")
	t.Setenv("OPENREPORT_MINIMUMPRIORITY", "warning")
	t.Setenv("OPENREPORT_MAXEVENTS", "42")

	v := viper.New()
	for prefix, defaults := range outputDefaults {
		for key, value := range defaults {
			v.SetDefault(prefix+"."+key, value)
		}
	}
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	c := &types.Configuration{}
	require.NoError(t, v.Unmarshal(c))
	require.True(t, c.OpenReport.Enabled)
	require.Equal(t, "/tmp/openreport-kubeconfig", c.OpenReport.Kubeconfig)
	require.Equal(t, "falco", c.OpenReport.FalcoNamespace)
	require.Equal(t, "warning", c.OpenReport.MinimumPriority)
	require.Equal(t, 42, c.OpenReport.MaxEvents)
}
