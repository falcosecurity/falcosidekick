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

// TestWebUIOAuth2EnvBinding verifies that WebUI OAuth2 and TokenFile env vars
// are properly bound when configured in outputDefaults.
func TestWebUIOAuth2EnvBinding(t *testing.T) {
	t.Setenv("WEBUI_OAUTH2_TOKENURL", "https://oauth.example.com/token")
	t.Setenv("WEBUI_OAUTH2_CLIENTID", "test-client")
	t.Setenv("WEBUI_OAUTH2_CLIENTSECRETFILE", "/path/to/secret")
	t.Setenv("WEBUI_TOKENFILE", "/path/to/token")

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
	require.Equal(t, "https://oauth.example.com/token", c.WebUI.OAuth2.TokenURL)
	require.Equal(t, "test-client", c.WebUI.OAuth2.ClientID)
	require.Equal(t, "/path/to/secret", c.WebUI.OAuth2.ClientSecretFile)
	require.Equal(t, "/path/to/token", c.WebUI.TokenFile)
}
