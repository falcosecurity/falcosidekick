package outputs

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
)

var falcoTestInput = `{"output":"This is a test from falcosidekick","priority":"Debug","rule":"Test rule", "time":"2001-01-01T01:10:00Z","output_fields": {"proc.name":"falcosidekick","user.name":"falcosidekick"}}`

func TestNewClient(t *testing.T) {
	u, _ := url.Parse("http://localhost")
	testClientOutput := Client{OutputType: "test", EndpointURL: u, Debug: true}
	_, err := NewClient("test", "localhost/%*$¨^!/:;", false)
	if err == nil {
		t.Fatalf("error while creating client object : %v\n", err)
	}
	nc, _ := NewClient("test", "http://localhost", true)
	if !reflect.DeepEqual(&testClientOutput, nc) {
		t.Fatalf("expected: %v, got: %v\n", testClientOutput, nc)
	}
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
	// os.Setenv("DEBUG", "true")
	nc, _ := NewClient("", "", false)
	for i, j := range map[string]error{"/200": nil, "/400": ErrHeaderMissing, "/401": ErrClientAuthenticationError, "/403": ErrForbidden, "/404": ErrNotFound, "/422": ErrUnprocessableEntityError, "/429": ErrTooManyRequest, "/502": errors.New("502 Bad Gateway")} {
		nc, _ = NewClient("", ts.URL+i, false)
		err := nc.Post("")
		if !reflect.DeepEqual(err, j) {
			t.Fatalf("expected error: %v, got: %v\n", j, err)
		}
	}
}
