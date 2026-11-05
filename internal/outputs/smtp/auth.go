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

package smtp

import (
	mail "github.com/wneessen/go-mail"
)

const (
	authNone    = "none"
	authPlain   = "plain"
	authXOAuth2 = "xoauth2"
)

// authOptions returns the go-mail options for the configured mechanism.
// go-mail sends PLAIN only over TLS or to localhost; XOAUTH2 has no such
// check, so validation restricts it to TLS modes that cannot fall back.
func authOptions(cfg *config) []mail.Option {
	switch cfg.AuthMechanism {
	case authPlain:
		return []mail.Option{mail.WithSMTPAuth(mail.SMTPAuthPlain), mail.WithUsername(cfg.User), mail.WithPassword(cfg.Password)}
	case authXOAuth2:
		return []mail.Option{mail.WithSMTPAuth(mail.SMTPAuthXOAUTH2), mail.WithUsername(cfg.User), mail.WithPassword(cfg.Token)}
	default:
		return nil
	}
}

func isLocalhost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
