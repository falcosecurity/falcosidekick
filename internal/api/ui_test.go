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
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
)

const (
	uiTestIndexBody = "<!doctype html><html><body>ui-test-index</body></html>"
	uiTestAssetBody = "console.log('ui-test-asset');\n"
)

func newUITestFS() fstest.MapFS {
	return fstest.MapFS{
		"index.html":    {Data: []byte(uiTestIndexBody)},
		"assets/app.js": {Data: []byte(uiTestAssetBody)},
	}
}

func TestRegisterStaticUI_NoAssets_NoInterception(t *testing.T) {
	srv := buildUITestServer(t, nil, nil)

	root, err := srv.app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody))
	require.NoError(t, err)
	defer root.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, root.StatusCode,
		"GET / must fall through to Fiber's 405 (POST / is registered, GET / is not) when no UI assets are configured")

	post, err := srv.app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", bytes.NewReader(createValidEventJSON())))
	require.NoError(t, err)
	defer post.Body.Close()
	assert.Equal(t, http.StatusOK, post.StatusCode, "POST / event ingest must still work when no UI assets")

	ver, err := srv.app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/version", http.NoBody))
	require.NoError(t, err)
	defer ver.Body.Close()
	assert.Equal(t, http.StatusOK, ver.StatusCode)
}

func TestRegisterStaticUI_AssetsPresent_ServesIndex(t *testing.T) {
	srv := buildUITestServer(t, newUITestFS(), nil)

	resp, err := srv.app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, readErr := io.ReadAll(resp.Body)
	require.NoError(t, readErr)
	assert.Equal(t, uiTestIndexBody, string(body))
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")
}

func TestRegisterStaticUI_AssetsPresent_ServesAsset(t *testing.T) {
	srv := buildUITestServer(t, newUITestFS(), nil)

	resp, err := srv.app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/assets/app.js", http.NoBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, readErr := io.ReadAll(resp.Body)
	require.NoError(t, readErr)
	assert.Equal(t, uiTestAssetBody, string(body))
}

func TestRegisterStaticUI_AssetsPresent_SkipsAPIPaths(t *testing.T) {
	srv := buildUITestServer(t, newUITestFS(), nil)

	resp, err := srv.app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/version", http.NoBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, readErr := io.ReadAll(resp.Body)
	require.NoError(t, readErr)
	assert.Contains(t, string(body), "version", "API path must return JSON, not index.html")
	assert.NotEqual(t, uiTestIndexBody, string(body))
}

func TestRegisterStaticUI_AssetsPresent_SkipsHealthz(t *testing.T) {
	srv := buildUITestServer(t, newUITestFS(), nil)

	resp, err := srv.app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", http.NoBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, readErr := io.ReadAll(resp.Body)
	require.NoError(t, readErr)
	assert.Contains(t, string(body), `"status":"ok"`)
}

func TestRegisterStaticUI_AssetsPresent_SkipsVersion(t *testing.T) {
	srv := buildUITestServer(t, newUITestFS(), nil)

	resp, err := srv.app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/version", http.NoBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, readErr := io.ReadAll(resp.Body)
	require.NoError(t, readErr)
	assert.Contains(t, string(body), "version", "/version must return version JSON, not index.html")
	assert.NotEqual(t, uiTestIndexBody, string(body))
}

func TestRegisterStaticUI_AssetsPresent_SkipsMetrics(t *testing.T) {
	registry := prometheus.NewRegistry()
	srv := buildUITestServer(t, newUITestFS(), registry)

	resp, err := srv.app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", http.NoBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, readErr := io.ReadAll(resp.Body)
	require.NoError(t, readErr)
	assert.NotContains(t, string(body), uiTestIndexBody, "/metrics must return Prometheus text, not index.html")
}

func TestRegisterStaticUI_AssetsPresent_PostRootStillIngests(t *testing.T) {
	srv := buildUITestServer(t, newUITestFS(), nil)

	resp, err := srv.app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", bytes.NewReader(createValidEventJSON())))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "POST / must remain the event-ingest handler even with UI assets registered")
}

func TestRegisterStaticUI_AssetsPresent_UnregisteredAPIPathReturns404(t *testing.T) {
	srv := buildUITestServer(t, newUITestFS(), nil)

	resp, err := srv.app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/this-does-not-exist", http.NoBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	body, readErr := io.ReadAll(resp.Body)
	require.NoError(t, readErr)
	assert.NotContains(t, string(body), uiTestIndexBody,
		"unregistered /api/ paths must not fall through to index.html; skipAPIPaths must skip the static middleware")
}

func TestRegisterStaticUI_AssetsPresent_UnknownRouteServesSPA(t *testing.T) {
	srv := buildUITestServer(t, newUITestFS(), nil)

	resp, err := srv.app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/does-not-exist", http.NoBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"extensionless unknown routes must fall back to index.html so React Router can resolve them client-side")
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(t, readErr)
	assert.Contains(t, string(body), uiTestIndexBody)
}

func TestRegisterStaticUI_AssetsPresent_MissingStaticFileReturns404(t *testing.T) {
	srv := buildUITestServer(t, newUITestFS(), nil)

	resp, err := srv.app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/missing-asset.png", http.NoBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode,
		"requests with an extension must never fall through to index.html")
}

func TestRegisterStaticUI_AssetsPresent_HeadMirrorsGet(t *testing.T) {
	srv := buildUITestServer(t, newUITestFS(), nil)

	resp, err := srv.app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodHead, "/", http.NoBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")
}

func TestRegisterStaticUI_AcceptEncodingGzip_Returns200(t *testing.T) {
	srv := buildUITestServer(t, newUITestFS(), nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode,
		"GET / with Accept-Encoding must return 200, not 405; real browsers always send Accept-Encoding")

	body, readErr := io.ReadAll(resp.Body)
	require.NoError(t, readErr)

	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		gr, gzErr := gzip.NewReader(bytes.NewReader(body))
		require.NoError(t, gzErr)
		defer gr.Close()
		decoded, decodeErr := io.ReadAll(gr)
		require.NoError(t, decodeErr)
		assert.Equal(t, uiTestIndexBody, string(decoded))
	case "":
		assert.Equal(t, uiTestIndexBody, string(body),
			"response without Content-Encoding must be the uncompressed index body")
	default:
		assert.Equal(t, uiTestIndexBody, string(body),
			"unexpected Content-Encoding %q; test only decodes gzip or identity", resp.Header.Get("Content-Encoding"))
	}
}

func TestServerConfigUIAssetsOptional(t *testing.T) {
	enricher, err := pipeline.NewEnricher(output.EnricherConfig{
		TruncateEventThreshold: 4096,
		TruncateFieldThreshold: 512,
	})
	require.NoError(t, err)
	p, err := pipeline.NewPipeline(enricher, pipeline.NewDispatcher(nil), nil)
	require.NoError(t, err)

	srv, err := NewServer(&ServerConfig{Pipeline: p, Catalog: newTestCatalog(t), UIAssets: nil})
	require.NoError(t, err, "NewServer must accept UIAssets: nil")
	assert.NotNil(t, srv)
}
