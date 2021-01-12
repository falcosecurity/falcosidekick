package outputs

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/falcosecurity/falcosidekick/pkg/types"

	"github.com/stretchr/testify/require"
)

var falcoTestInput = `{"output":"This is a test from falcosidekick","priority":"Debug","rule":"Test rule", "time":"2001-01-01T01:10:00Z","output_fields": {"proc.name":"falcosidekick", "proc.tty": 1234}}`

func TestNewClient(t *testing.T) {
	u, _ := url.Parse("http://localhost")

	config := &types.Configuration{}
	stats := &types.Statistics{}
	promStats := &types.PromStatistics{}

	testClientOutput := Client{OutputType: "test", EndpointURL: u, Config: config, Stats: stats, PromStats: promStats}
	_, err := NewClient("test", "localhost/%*$¨^!/:;", config, stats, promStats, nil, nil)
	require.NotNil(t, err)

	nc, err := NewClient("test", "http://localhost", config, stats, promStats, nil, nil)
	require.Nil(t, err)
	require.Equal(t, &testClientOutput, nc)
}

func TestPost(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Fatalf("expected method : POST, got %s\n", r.Method)
		}
		switch r.URL.EscapedPath() {
		case "/200":
			w.WriteHeader(http.StatusOK)
		case "/400":
			w.WriteHeader(http.StatusBadRequest)
		case "/401":
			w.WriteHeader(http.StatusUnauthorized)
		case "/403":
			w.WriteHeader(http.StatusForbidden)
		case "/404":
			w.WriteHeader(http.StatusNotFound)
		case "/422":
			w.WriteHeader(http.StatusUnprocessableEntity)
		case "/429":
			w.WriteHeader(http.StatusTooManyRequests)
		case "/502":
			w.WriteHeader(http.StatusBadGateway)
		}
	}))

	for i, j := range map[string]error{
		"/200": nil, "/400": ErrHeaderMissing,
		"/401": ErrClientAuthenticationError,
		"/403": ErrForbidden,
		"/404": ErrNotFound,
		"/422": ErrUnprocessableEntityError,
		"/429": ErrTooManyRequest,
		"/502": errors.New("502 Bad Gateway"),
	} {
		nc, err := NewClient("", ts.URL+i, &types.Configuration{}, &types.Statistics{}, &types.PromStatistics{}, nil, nil)
		require.Nil(t, err)
		require.NotEmpty(t, nc)

		errPost := nc.Post("")
		require.Equal(t, errPost, j)
	}
}
