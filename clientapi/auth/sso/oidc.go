// Copyright 2022 The Matrix.org Foundation C.I.C.
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

package sso

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/matrix-org/dendrite/setup/config"
	uapi "github.com/matrix-org/dendrite/userapi/api"
)

// oidcDiscoveryMaxStaleness indicates how stale the Discovery
// information is allowed to be. This will very rarely change, so
// we're just making sure even a Dendrite that isn't restarting often
// is picking this up eventually.
const oidcDiscoveryMaxStaleness = 24 * time.Hour

// An oidcIdentityProvider wraps OAuth2 with OpenID Connect Discovery.
//
// The SSO identifier is the "sub." A suggested UserID is grabbed from
// "preferred_username", though this isn't commonly provided.
//
// See https://openid.net/specs/openid-connect-core-1_0.html and https://openid.net/specs/openid-connect-discovery-1_0.html.
type oidcIdentityProvider struct {
	*oauth2IdentityProvider
	discoveryURL string
	issuer       string
	exp          time.Time
	mu           sync.Mutex
}

func newOIDCIdentityProvider(cfg *config.IdentityProvider, hc *http.Client) (identityProvider, error) {
	p := &oidcIdentityProvider{
		oauth2IdentityProvider: &oauth2IdentityProvider{
			providerID:   cfg.ID,
			clientID:     cfg.ClientID,
			clientSecret: cfg.ClientSecret,
			endpoints:    nil,

			scopes:           cfg.Scopes,
			responseMimeType: cfg.ResponseMimeType,
			claims:           &cfg.Claims, // TODO: should this require email_verified?

			hc: hc,
		},
		discoveryURL: cfg.DiscoveryURL,
	}
	if !stringSliceContains(p.scopes, "openid") {
		p.scopes = append(p.scopes, "openid")
	}
	err := p.reloadOIDCDiscovery(context.Background())
	if err != nil {
		p = nil
	}
	return p, err
}

func (p *oidcIdentityProvider) AuthorizationURL(ctx context.Context, callbackURL, nonce string) (string, error) {
	err := p.reloadOIDCDiscovery(ctx)
	if err != nil {
		return "", err
	}
	return p.oauth2IdentityProvider.AuthorizationURL(ctx, callbackURL, nonce)
}

func (p *oidcIdentityProvider) ProcessCallback(ctx context.Context, callbackURL, nonce string, query url.Values) (res *CallbackResult, err error) {
	if err = p.reloadOIDCDiscovery(ctx); err == nil {
		if res, err = p.oauth2IdentityProvider.ProcessCallback(ctx, callbackURL, nonce, query); err == nil {
			// OIDC has the notion of issuer URL, which will be more
			// stable than our configuration ID.
			res.Identifier.Namespace = uapi.OIDCNamespace
			res.Identifier.Issuer = p.issuer
		}
	}
	return
}

func (p *oidcIdentityProvider) reloadOIDCDiscovery(ctx context.Context) error {
	now := time.Now()
	if p.exp.Before(now) || p.endpoints == nil {
		p.mu.Lock()
		defer p.mu.Unlock()
		disc, err := oidcDiscover(ctx, p.discoveryURL)
		if err != nil {
			if p.endpoints != nil {
				// Prefers returning a stale entry.
				return nil
			}
			return err
		}

		p.exp = now.Add(oidcDiscoveryMaxStaleness)
		p.endpoints = &config.OAuth2Endpoints{
			Authorization: disc.AuthorizationEndpoint,
			AccessToken:   disc.TokenEndpoint,
			UserInfo:      disc.UserinfoEndpoint,
		}
		p.issuer = disc.Issuer
	}
	return nil
}

type oidcDiscovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	ScopesSupported       []string `json:"scopes_supported"`
}

func oidcDiscover(ctx context.Context, url string) (*oidcDiscovery, error) {
	hreq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Accept", "application/jrd+json,application/json;q=0.9")

	hresp, err := http.DefaultClient.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer hresp.Body.Close() // nolint:errcheck

	if hresp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("OIDC discovery request %q failed: %d %s", url, hresp.StatusCode, hresp.Status)
	}

	var disc oidcDiscovery
	if err := json.NewDecoder(hresp.Body).Decode(&disc); err != nil {
		return nil, fmt.Errorf("decoding OIDC discovery response from %q: %w", url, err)
	}

	if !validWebURL(disc.Issuer) {
		return nil, fmt.Errorf("issuer identifier is invalid in %q", url)
	}
	if !validWebURL(disc.AuthorizationEndpoint) {
		return nil, fmt.Errorf("authorization endpoint is invalid in %q", url)
	}
	if !validWebURL(disc.TokenEndpoint) {
		return nil, fmt.Errorf("token endpoint is invalid in %q", url)
	}
	if !validWebURL(disc.UserinfoEndpoint) {
		return nil, fmt.Errorf("userinfo endpoint is invalid in %q", url)
	}

	if disc.ScopesSupported != nil {
		if !stringSliceContains(disc.ScopesSupported, "openid") {
			return nil, fmt.Errorf("scope 'openid' is missing in %q", url)
		}
	}

	return &disc, nil
}

func validWebURL(s string) bool {
	if s == "" {
		return false
	}

	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return u.Scheme != "" && u.Host != ""
}

func stringSliceContains(ss []string, s string) bool {
	for _, s2 := range ss {
		if s2 == s {
			return true
		}
	}
	return false
}
