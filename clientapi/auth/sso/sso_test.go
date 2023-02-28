package sso

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/matrix-org/dendrite/setup/config"
)

func TestNewAuthenticator(t *testing.T) {
	testSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authorization_endpoint":"http://localhost/authorize",
								"token_endpoint":"http://localhost/token",
								"userinfo_endpoint":"http://localhost/userinfo",
								"issuer":"http://localhost/"}`))
	}))
	defer testSrv.Close()
	_, err := NewAuthenticator(&config.SSO{
		Providers: []config.IdentityProvider{
			{
				Type:     config.SSOTypeGitHub,
				ClientID: "aclientid",
			},
			{
				Type:         config.SSOTypeOIDC,
				ClientID:     "aclientid",
				DiscoveryURL: testSrv.URL + "/discovery",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewAuthenticator failed: %v", err)
	}
}

func TestAuthenticator(t *testing.T) {
	ctx := context.Background()

	var idp fakeIdentityProvider
	a := Authenticator{
		providers: map[string]identityProvider{
			"fake": &idp,
		},
	}

	t.Run("authorizationURL", func(t *testing.T) {
		got, err := a.AuthorizationURL(ctx, "fake", "http://matrix.example.com/continue", "anonce")
		if err != nil {
			t.Fatalf("AuthorizationURL failed: %v", err)
		}
		if want := "aurl"; got != want {
			t.Errorf("AuthorizationURL: got %q, want %q", got, want)
		}
	})

	t.Run("processCallback", func(t *testing.T) {
		got, err := a.ProcessCallback(ctx, "fake", "http://matrix.example.com/continue", "anonce", url.Values{})
		if err != nil {
			t.Fatalf("ProcessCallback failed: %v", err)
		}
		if want := (&CallbackResult{DisplayName: "aname"}); !reflect.DeepEqual(got, want) {
			t.Errorf("ProcessCallback: got %+v, want %+v", got, want)
		}
	})
}

type fakeIdentityProvider struct{}

func (idp *fakeIdentityProvider) AuthorizationURL(_ context.Context, _, _ string) (string, error) {
	return "aurl", nil
}

func (idp *fakeIdentityProvider) ProcessCallback(_ context.Context, _, _ string, _ url.Values) (*CallbackResult, error) {
	return &CallbackResult{DisplayName: "aname"}, nil
}
