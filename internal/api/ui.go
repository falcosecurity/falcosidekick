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

package api

import (
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/static"
)

// registerStaticUI installs the static-asset middleware on app when assets
// is non-nil. API and operator paths (/api/**, /healthz, /version, /metrics)
// are always skipped so they remain served by their explicit handlers.
// A non-asset GET whose path does not match a file falls back to index.html
// so client-side router paths such as /events or /pipeline resolve on hard
// refresh. Response compression is handled globally by compress.New in
// mountRoutes; static.Config.Compress is left off because it requires
// pre-compressed files on disk (.gz/.br/.zst) which the embedded FS does
// not provide.
func registerStaticUI(app *fiber.App, assets fs.FS) {
	if assets == nil {
		return
	}
	app.Use(static.New("", static.Config{
		FS:            assets,
		IndexNames:    []string{"index.html"},
		CacheDuration: 10 * time.Second,
		Next:          skipAPIPaths,
	}))
	app.Get("/*", spaFallback(assets))
}

func skipAPIPaths(c fiber.Ctx) bool {
	p := c.Path()
	if strings.HasPrefix(p, "/api/") {
		return true
	}
	switch p {
	case "/healthz", "/version", "/metrics":
		return true
	}
	return false
}

func spaFallback(assets fs.FS) fiber.Handler {
	return func(c fiber.Ctx) error {
		if skipAPIPaths(c) {
			return c.Next()
		}
		if strings.Contains(c.Path(), ".") {
			return c.Status(http.StatusNotFound).SendString("not found")
		}
		data, err := fs.ReadFile(assets, "index.html")
		if err != nil {
			return c.Next()
		}
		c.Set(fiber.HeaderContentType, fiber.MIMETextHTMLCharsetUTF8)
		return c.Send(data)
	}
}
