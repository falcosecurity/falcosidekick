// SPDX-License-Identifier: MIT OR Apache-2.0

package utils

import "crypto/tls"

func InsecureSkipVerifyTLSConfig() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}
