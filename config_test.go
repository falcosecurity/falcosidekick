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
