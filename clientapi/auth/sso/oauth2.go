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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/matrix-org/dendrite/clientapi/jsonerror"
	"github.com/matrix-org/dendrite/setup/config"
	uapi "github.com/matrix-org/dendrite/userapi/api"
	"github.com/matrix-org/util"
	"github.com/tidwall/gjson"
)

var (
	errNoSubject             = errors.New("no subject from SSO provider")
	errCodeParameterMissing  = jsonerror.MissingArgument("code parameter missing")
	errStateParameterMissing = jsonerror.MissingArgument("state parameter missing")
	errStateNonceMissMatch   = jsonerror.InvalidArgumentValue("state parameter not matching nonce")
)

type oauth2IdentityProvider struct {
	clientID, clientSecret string
	providerID             string
	hc                     *http.Client
	endpoints              *config.OAuth2Endpoints
	scopes                 []string
	claims                 *config.OAuth2Claims
	responseMimeType       string
}

func newOAuth2IdentityProvider(cfg *config.IdentityProvider, hc *http.Client) (identityProvider, error) {
	return &oauth2IdentityProvider{
		providerID:   cfg.ID,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		endpoints:    &cfg.OAuth2Endpoints,

		scopes:           cfg.Scopes,
		responseMimeType: cfg.ResponseMimeType,
		claims:           &cfg.Claims,

		hc: hc,
	}, nil
}

func (p *oauth2IdentityProvider) AuthorizationURL(_ context.Context, callbackURL, nonce string) (string, error) {
	u, err := resolveURL(p.endpoints.Authorization, url.Values{
		"client_id":     []string{p.clientID},
		"response_type": []string{"code"},
		"redirect_uri":  []string{callbackURL},
		"scope":         []string{strings.Join(p.scopes, " ")},
		"state":         []string{nonce},
	})
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

func (p *oauth2IdentityProvider) ProcessCallback(ctx context.Context, callbackURL, nonce string, query url.Values) (*CallbackResult, error) {
	state := query.Get("state")
	if state == "" {
		return nil, errStateParameterMissing
	}
	if state != nonce {
		return nil, errStateNonceMissMatch
	}

	if err := query.Get("error"); err != "" {
		if euri := query.Get("error_uri"); euri != "" {
			return &CallbackResult{RedirectURL: euri}, nil
		}

		desc := query.Get("error_description")
		if desc == "" {
			desc = err
		}
		switch err {
		case "unauthorized_client", "access_denied": // nolint:misspell
			return nil, jsonerror.Forbidden("SSO access denied: " + desc)
		default:
			return nil, fmt.Errorf("SSO failed: %v", err)
		}
	}

	code := query.Get("code")
	if code == "" {
		return nil, errCodeParameterMissing
	}

	at, err := p.getAccessToken(ctx, callbackURL, code)
	if err != nil {
		return nil, err
	}

	subject, displayName, suggestedLocalpart, err := p.getUserInfo(ctx, at)
	if err != nil {
		return nil, err
	}

	if subject == "" {
		return nil, errNoSubject
	}

	return &CallbackResult{
		Identifier: &UserIdentifier{
			Namespace: uapi.SSOIDNamespace,
			Issuer:    p.providerID,
			Subject:   subject,
		},
		DisplayName:     displayName,
		SuggestedUserID: suggestedLocalpart,
	}, nil
}

func (p *oauth2IdentityProvider) getAccessToken(ctx context.Context, callbackURL, code string) (string, error) {
	body := url.Values{
		"grant_type":    []string{"authorization_code"},
		"code":          []string{code},
		"redirect_uri":  []string{callbackURL},
		"client_id":     []string{p.clientID},
		"client_secret": []string{p.clientSecret},
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.endpoints.AccessToken, strings.NewReader(body.Encode()))
	if err != nil {
		return "", err
	}
	hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hreq.Header.Set("Accept", p.responseMimeType)

	hresp, err := httpDo(ctx, p.hc, hreq)
	if err != nil {
		return "", fmt.Errorf("access token: %w", err)
	}
	defer hresp.Body.Close() // nolint:errcheck

	var resp oauth2TokenResponse
	if err := json.NewDecoder(hresp.Body).Decode(&resp); err != nil {
		return "", err
	}

	if strings.ToLower(resp.TokenType) != "bearer" {
		return "", fmt.Errorf("expected bearer token, got type %q", resp.TokenType)
	}

	return resp.AccessToken, nil
}

type oauth2TokenResponse struct {
	TokenType   string `json:"token_type"`
	AccessToken string `json:"access_token"`
}

func (p *oauth2IdentityProvider) getUserInfo(ctx context.Context, accessToken string) (subject, displayName, suggestedLocalpart string, _ error) {
	hreq, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoints.UserInfo, nil)
	if err != nil {
		return "", "", "", err
	}
	hreq.Header.Set("Authorization", "Bearer "+accessToken)
	hreq.Header.Set("Accept", p.responseMimeType)

	hresp, err := httpDo(ctx, p.hc, hreq)
	if err != nil {
		return "", "", "", fmt.Errorf("user info: %w", err)
	}
	defer hresp.Body.Close() // nolint:errcheck

	body, err := io.ReadAll(hresp.Body)
	if err != nil {
		return "", "", "", err
	}

	if res := gjson.GetBytes(body, p.claims.Subject); !res.Exists() {
		return "", "", "",
			fmt.Errorf("no %q in user info response body", p.claims.Subject)
	} else {
		subject = res.String()
	}
	if subject == "" {
		return "", "", "", fmt.Errorf("empty subject in user info")
	}

	if p.claims.SuggestedUserID != "" {
		suggestedLocalpart = gjson.GetBytes(body, p.claims.SuggestedUserID).String()
	}

	if p.claims.DisplayName != "" {
		displayName = gjson.GetBytes(body, p.claims.DisplayName).String()
	}

	return
}

func httpDo(ctx context.Context, hc *http.Client, req *http.Request) (*http.Response, error) {
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode/100 != 2 {
		defer resp.Body.Close() // nolint:errcheck

		contentType := resp.Header.Get("Content-Type")
		switch {
		case strings.HasPrefix(contentType, "text/plain"):
			bs, err := io.ReadAll(resp.Body)
			if err == nil {
				if len(bs) > 80 {
					bs = bs[:80]
				}
				util.GetLogger(ctx).WithField("url", req.URL.String()).WithField("status", resp.StatusCode).Warnf("OAuth2 HTTP request failed: %s", string(bs))
			}
		case strings.HasPrefix(contentType, "application/json"):
			// https://openid.net/specs/openid-connect-core-1_0.html#TokenErrorResponse
			var body oauth2Error
			if err := json.NewDecoder(resp.Body).Decode(&body); err == nil {
				util.GetLogger(ctx).WithField("url", req.URL.String()).WithField("status", resp.StatusCode).Warnf("OAuth2 HTTP request failed: %+v", &body)
			}
			if body.Error != "" {
				return nil, fmt.Errorf("oauth2 request %q failed: %s (%s)", req.URL.String(), resp.Status, body.Error)
			}
		}

		if hdr := resp.Header.Get("WWW-Authenticate"); hdr != "" {
			// https://openid.net/specs/openid-connect-core-1_0.html#UserInfoError
			if len(hdr) > 80 {
				hdr = hdr[:80]
			}
			return nil, fmt.Errorf("oauth2 request %q failed: %s (%s)", req.URL.String(), resp.Status, hdr)
		}

		return nil, fmt.Errorf("oauth2 HTTP request %q failed: %s", req.URL.String(), resp.Status)
	}

	return resp, nil
}

type oauth2Error struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorURI         string `json:"error_uri"`
}

func resolveURL(urlString string, defaultQuery url.Values) (*url.URL, error) {
	u, err := url.Parse(urlString)
	if err != nil {
		return nil, err
	}

	if defaultQuery != nil {
		q := u.Query()
		for k, vs := range defaultQuery {
			if q.Get(k) == "" {
				q[k] = vs
			}
		}
		u.RawQuery = q.Encode()
	}

	return u, nil
}
