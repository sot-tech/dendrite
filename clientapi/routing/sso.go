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

package routing

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/matrix-org/dendrite/clientapi/auth/authtypes"
	"github.com/matrix-org/dendrite/clientapi/auth/sso"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/matrix-org/dendrite/clientapi/jsonerror"
	"github.com/matrix-org/dendrite/clientapi/userutil"
	"github.com/matrix-org/dendrite/setup/config"
	uapi "github.com/matrix-org/dendrite/userapi/api"
	"github.com/matrix-org/gomatrixserverlib"
	"github.com/matrix-org/util"
)

const ssoIdpListTemplate = `
<html>
<head>
<title>Authentication</title>
<meta name='viewport' content='width=device-width, initial-scale=1,
    user-scalable=no, minimum-scale=1.0, maximum-scale=1.0'>
<style>
p {text-align: center;}
</style>
</head>
<body>
<p>
Hello! We need to prevent computer programs and other automated
things from creating accounts on this server.
<br>
Please, select SSO provider to authenticate.
</p>
{{range $idpName, $idpURL := .}}
<p><a href="{{$idpURL}}">{{$idpName}}</a></p>
{{end}}
</body>
</html>
`

const (
	ssoCallbackPath = "/login/sso/callback"
	ssoRedirectPath = "/login/sso/redirect"
	ssoFallBackPath = "/auth/" + authtypes.LoginTypeSSO + "/fallback/web"

	ssoLoginTokenParameter      = "loginToken"
	ssoFallbackSessionParameter = "session"
	ssoProviderParameter        = "provider"
	ssoRedirectURLParameter     = "redirectUrl"
	ssoFallbackConfirmationTTL  = defaultTimeOut

	ssoNonceCookie = "sso_nonce"
)

var (
	respDisabled = util.JSONResponse{
		Code: http.StatusNotFound,
		JSON: jsonerror.NotFound("authentication method disabled"),
	}

	respMissingRedirect = util.JSONResponse{
		Code: http.StatusBadRequest,
		JSON: jsonerror.MissingArgument("redirectUrl parameter missing"),
	}
	respMissingProvider = util.JSONResponse{
		Code: http.StatusBadRequest,
		JSON: jsonerror.MissingArgument("provider parameter missing"),
	}

	respUnknownID = util.JSONResponse{
		Code: http.StatusUnauthorized,
		JSON: jsonerror.Forbidden("ID not associated with a local account"),
	}

	ssoFallbackConfirmations   = make(map[string]ssoFallbackConfirmationData)
	ssoFallbackConfirmationsMu = sync.RWMutex{}
)

type ssoFallbackConfirmationData struct {
	time.Time
	sessionID string
}

// SSORedirect implements /login/sso/redirect
// https://spec.matrix.org/v1.2/client-server-api/#redirecting-to-the-authentication-server
func SSORedirect(
	req *http.Request,
	idpID string,
	auth ssoAuthenticator,
	cfg *config.SSO,
) util.JSONResponse {
	ctx := req.Context()

	if auth == nil {
		return respDisabled
	}

	redirectURL := req.URL.Query().Get(ssoRedirectURLParameter)
	if redirectURL == "" {
		return respMissingRedirect
	}
	if _, err := url.Parse(redirectURL); err != nil {
		return util.JSONResponse{
			Code: http.StatusBadRequest,
			JSON: jsonerror.InvalidArgumentValue("Invalid redirectURL: " + err.Error()),
		}
	} /*else if ru.Scheme == "" || ru.Host == "" {
		return util.JSONResponse{
			Code: http.StatusBadRequest,
			JSON: jsonerror.InvalidArgumentValue("Invalid redirectURL: " + redirectURL),
		}
	}*/

	if idpID == "" {
		idpID = cfg.DefaultProviderID
		if idpID == "" && len(cfg.Providers) > 0 {
			idpID = cfg.Providers[0].ID
		}
	}

	callbackURL, err := buildURLFromOther(cfg, req, ssoRedirectPath, ssoCallbackPath)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("Failed to build callback URL")
		return util.JSONResponse{
			Code: http.StatusInternalServerError,
			JSON: err,
		}
	}

	callbackURL = callbackURL.ResolveReference(&url.URL{
		RawQuery: url.Values{ssoProviderParameter: []string{idpID}}.Encode(),
	})
	nonce := formatNonce(redirectURL)
	u, err := auth.AuthorizationURL(ctx, idpID, callbackURL.String(), nonce)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("Failed to get SSO authorization URL")
		return util.JSONResponse{
			Code: http.StatusInternalServerError,
			JSON: err,
		}
	}

	util.GetLogger(ctx).Infof("SSO redirect to %s.", u)

	resp := util.RedirectResponse(u)
	cookie := &http.Cookie{
		Name:     "sso_nonce",
		Value:    nonce,
		Path:     path.Dir(callbackURL.Path),
		Expires:  time.Now().Add(10 * time.Minute),
		Secure:   callbackURL.Scheme != "http",
		SameSite: http.SameSiteNoneMode,
	}
	if !cookie.Secure {
		// SameSite=None requires Secure, so we might as well remove
		// it. See https://blog.chromium.org/2019/10/developers-get-ready-for-new.html.
		cookie.SameSite = http.SameSiteDefaultMode
	}
	resp.Headers["Set-Cookie"] = cookie.String()
	return resp
}

// buildURLFromOther builds a replaced URL from another SSO
// request and configuration.
func buildURLFromOther(cfg *config.SSO, req *http.Request, expectedPath, replacePath string) (*url.URL, error) {
	u := &url.URL{
		Scheme: "https",
		Host:   req.Host,
		Path:   req.URL.Path,
	}
	if req.TLS == nil {
		u.Scheme = "http"
	}

	// Find the v3mux base, handling both `redirect` and
	// `redirect/{idp}` and not hard-coding the Matrix version.
	i := strings.Index(u.Path, expectedPath)
	if i < 0 {
		return nil, fmt.Errorf("cannot find %q to replace in URL %q", expectedPath, u.Path)
	}
	u.Path = u.Path[:i] + replacePath

	cu, err := url.Parse(cfg.CallbackURL)
	if err != nil {
		return nil, err
	}
	return u.ResolveReference(cu), nil
}

// SSOCallback implements /login/sso/callback.
// https://spec.matrix.org/v1.2/client-server-api/#handling-the-callback-from-the-authentication-server
func SSOCallback(
	req *http.Request,
	userAPI userAPIForSSO,
	auth ssoAuthenticator,
	cfg *config.SSO,
	serverName gomatrixserverlib.ServerName,
) util.JSONResponse {
	if auth == nil {
		return respDisabled
	}

	ctx := req.Context()

	query := req.URL.Query()
	idpID := query.Get(ssoProviderParameter)
	if idpID == "" {
		return respMissingProvider
	}

	nonce, err := req.Cookie(ssoNonceCookie)
	if err != nil {
		return util.JSONResponse{
			Code: http.StatusBadRequest,
			JSON: jsonerror.MissingArgument("no nonce cookie: " + err.Error()),
		}
	}
	finalRedirectURL, err := parseNonce(nonce.Value)
	if err != nil {
		return util.JSONResponse{
			Code: http.StatusBadRequest,
			JSON: err,
		}
	}

	callbackURL, err := buildURLFromOther(cfg, req, ssoCallbackPath, ssoCallbackPath)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("Failed to build callback URL")
		return util.JSONResponse{
			Code: http.StatusInternalServerError,
			JSON: err,
		}
	}

	callbackURL = callbackURL.ResolveReference(&url.URL{
		RawQuery: url.Values{ssoProviderParameter: []string{idpID}}.Encode(),
	})
	result, err := auth.ProcessCallback(ctx, idpID, callbackURL.String(), nonce.Value, query)
	if err != nil {
		util.GetLogger(ctx).WithError(err).Error("Failed to process callback")
		return util.JSONResponse{
			Code: http.StatusInternalServerError,
			JSON: err,
		}
	}
	util.GetLogger(ctx).WithField("result", result).Info("SSO callback done")

	if result.Identifier == nil {
		// Not authenticated yet.
		return util.RedirectResponse(result.RedirectURL)
	}

	localpart, err := verifySSOUserIdentifier(ctx, userAPI, result.Identifier)
	if err != nil {
		util.GetLogger(ctx).WithError(err).WithField("ssoIdentifier", result.Identifier).Error("failed to find user")
		return respUnknownID
	}

	fallback, finalRedirectQuery := strings.Index(finalRedirectURL.Path, ssoFallBackPath) >= 0, finalRedirectURL.Query()
	if localpart == "" {
		if !fallback {
			// The user doesn't exist.
			// TODO: let the user select the local part, and whether to associate email addresses.
			util.GetLogger(ctx).WithField("localpart", result.SuggestedUserID).WithField("ssoIdentifier", result.Identifier).Info("SSO registering account")
			localpart = result.SuggestedUserID
			if localpart == "" {
				util.GetLogger(ctx).WithField("ssoIdentifier", result.Identifier).Info("no suggested user ID from SSO provider")
				var res uapi.QueryNumericLocalpartResponse
				nreq := &uapi.QueryNumericLocalpartRequest{
					ServerName: serverName,
				}
				if err = userAPI.QueryNumericLocalpart(ctx, nreq, &res); err != nil {
					util.GetLogger(ctx).WithError(err).WithField("ssoIdentifier", result.Identifier).Error("failed to generate numeric localpart")
					return jsonerror.InternalServerError()
				}
				localpart = strconv.FormatInt(res.ID, 10)
			}

			ok, resp := registerSSOAccount(ctx, userAPI, result.Identifier, localpart)
			if !ok {
				util.GetLogger(ctx).WithError(err).WithField("ssoIdentifier", result.Identifier).WithField("localpart", localpart).Error("failed to register account")
				return resp
			}
		} else {
			return respUnknownID
		}
	}

	if fallback {
		fallbackSession := finalRedirectQuery.Get(ssoFallbackSessionParameter)
		if len(fallbackSession) == 0 {
			return respUnknownID
		}
		confirmCode := util.RandomString(sessionIDLength)
		ssoFallbackConfirmationsMu.Lock()
		ssoFallbackConfirmations[confirmCode] = ssoFallbackConfirmationData{
			Time:      time.Now().Add(ssoFallbackConfirmationTTL),
			sessionID: fallbackSession,
		}
		ssoFallbackConfirmationsMu.Unlock()
		finalRedirectQuery.Set(ssoLoginTokenParameter, confirmCode)
	} else {
		token, err := createLoginToken(ctx, userAPI, userutil.MakeUserID(localpart, serverName))
		if err != nil {
			util.GetLogger(ctx).WithError(err).Errorf("PerformLoginTokenCreation failed")
			return jsonerror.InternalServerError()
		}
		util.GetLogger(ctx).WithField("localpart", localpart).WithField("ssoIdentifier", result.Identifier).Info("SSO created token")

		finalRedirectQuery.Set(ssoLoginTokenParameter, token.Token)
	}

	resp := util.RedirectResponse(finalRedirectURL.ResolveReference(&url.URL{RawQuery: finalRedirectQuery.Encode()}).String())
	resp.Headers["Set-Cookie"] = (&http.Cookie{
		Name:   ssoNonceCookie,
		Value:  "",
		MaxAge: -1,
		Secure: true,
	}).String()
	return resp
}

func ssoFallback(
	req *http.Request,
	w http.ResponseWriter,
	cfg *config.SSO,
) {

	loginToken, sessionID := req.URL.Query().Get(ssoLoginTokenParameter), req.URL.Query().Get(ssoFallbackSessionParameter)
	if sessionID == "" {
		writeHTTPMessage(w, req,
			"Session ID not provided",
			http.StatusBadRequest,
		)
		return
	}
	if len(loginToken) == 0 {
		idps := make(map[string]string)
		urlValues := url.Values{
			ssoProviderParameter:    nil,
			ssoRedirectURLParameter: []string{req.URL.String()},
		}
		for _, idp := range cfg.Providers {
			idpURL, err := buildURLFromOther(cfg, req, ssoFallBackPath, ssoRedirectPath)
			if err != nil {
				writeHTTPMessage(w, req,
					err.Error(),
					http.StatusInternalServerError,
				)
				return
			}
			urlValues.Set(ssoProviderParameter, idp.ID)
			idps[idp.Name] = idpURL.ResolveReference(&url.URL{RawQuery: urlValues.Encode()}).String()
		}
		serveTemplate(w, ssoIdpListTemplate, idps)
		return
	}

	ssoFallbackConfirmationsMu.RLock()
	confirmedData, found := ssoFallbackConfirmations[loginToken]
	ssoFallbackConfirmationsMu.RUnlock()
	if found {
		ssoFallbackConfirmationsMu.Lock()
		delete(ssoFallbackConfirmations, loginToken)
		ssoFallbackConfirmationsMu.Unlock()
		if confirmedData.sessionID == sessionID && confirmedData.After(time.Now()) {
			sessions.addCompletedSessionStage(sessionID, authtypes.LoginTypeSSO)
			serveTemplate(w, successTemplate, map[string]string{})
			return
		}
	}
	writeHTTPMessage(w, req,
		"Confirmation not provided or stale",
		http.StatusBadRequest,
	)
}

type ssoAuthenticator interface {
	AuthorizationURL(ctx context.Context, providerID, callbackURL, nonce string) (string, error)
	ProcessCallback(ctx context.Context, providerID, callbackURL, nonce string, query url.Values) (*sso.CallbackResult, error)
}

type userAPIForSSO interface {
	uapi.LoginTokenInternalAPI

	PerformAccountCreation(ctx context.Context, req *uapi.PerformAccountCreationRequest, res *uapi.PerformAccountCreationResponse) error
	PerformSaveSSOAssociation(ctx context.Context, req *uapi.PerformSaveSSOAssociationRequest, res *struct{}) error
	QueryLocalpartForSSO(ctx context.Context, req *uapi.QueryLocalpartForSSORequest, res *uapi.QueryLocalpartForSSOResponse) error
	QueryNumericLocalpart(ctx context.Context, req *uapi.QueryNumericLocalpartRequest, res *uapi.QueryNumericLocalpartResponse) error
}

// formatNonce creates a random nonce that also contains the URL.
func formatNonce(redirectURL string) string {
	return util.RandomString(16) + "." + base64.RawURLEncoding.EncodeToString([]byte(redirectURL))
}

// parseNonce extracts the embedded URL from the nonce. The nonce
// should have been validated to be the original before calling this
// function. The URL is not integrity protected.
func parseNonce(s string) (redirectURL *url.URL, _ error) {
	if s == "" {
		return nil, jsonerror.MissingArgument("empty SSO nonce cookie")
	}

	ss := strings.Split(s, ".")
	if len(ss) < 2 {
		return nil, jsonerror.InvalidArgumentValue("malformed SSO nonce cookie")
	}

	urlbs, err := base64.RawURLEncoding.DecodeString(ss[1])
	if err != nil {
		return nil, jsonerror.InvalidArgumentValue("invalid redirect URL in SSO nonce cookie")
	}
	u, err := url.Parse(string(urlbs))
	if err != nil {
		return nil, jsonerror.InvalidArgumentValue("invalid redirect URL in SSO nonce cookie: " + err.Error())
	}

	return u, nil
}

// verifySSOUserIdentifier resolves an sso.UserIdentifier to a local
// part using the User API. Returns empty if there is no associated
// user.
func verifySSOUserIdentifier(ctx context.Context, userAPI userAPIForSSO, id *sso.UserIdentifier) (localpart string, _ error) {
	req := &uapi.QueryLocalpartForSSORequest{
		Namespace: id.Namespace,
		Issuer:    id.Issuer,
		Subject:   id.Subject,
	}
	var res uapi.QueryLocalpartForSSOResponse
	if err := userAPI.QueryLocalpartForSSO(ctx, req, &res); err != nil {
		return "", err
	}
	return res.Localpart, nil
}

// registerSSOAccount creates an account and associates the SSO
// identifier with it. Note that SSO login account creation doesn't
// use the standard registration API, but happens ad-hoc.
func registerSSOAccount(ctx context.Context, userAPI userAPIForSSO, ssoID *sso.UserIdentifier, localpart string) (bool, util.JSONResponse) {
	var accRes uapi.PerformAccountCreationResponse
	err := userAPI.PerformAccountCreation(ctx, &uapi.PerformAccountCreationRequest{
		Localpart:   localpart,
		AccountType: uapi.AccountTypeUser,
		OnConflict:  uapi.ConflictAbort,
	}, &accRes)
	if err != nil {
		if _, ok := err.(*uapi.ErrorConflict); ok {
			return false, util.JSONResponse{
				Code: http.StatusBadRequest,
				JSON: jsonerror.UserInUse("Desired user ID is already taken."),
			}
		}
		return false, util.JSONResponse{
			Code: http.StatusInternalServerError,
			JSON: jsonerror.Unknown("failed to create account: " + err.Error()),
		}
	}

	amtRegUsers.Inc()

	err = userAPI.PerformSaveSSOAssociation(ctx, &uapi.PerformSaveSSOAssociationRequest{
		Namespace: ssoID.Namespace,
		Issuer:    ssoID.Issuer,
		Subject:   ssoID.Subject,
		Localpart: localpart,
	}, &struct{}{})
	if err != nil {
		return false, util.JSONResponse{
			Code: http.StatusInternalServerError,
			JSON: jsonerror.Unknown("failed to associate SSO credentials with account: " + err.Error()),
		}
	}

	return true, util.JSONResponse{}
}

func createLoginToken(ctx context.Context, userAPI userAPIForSSO, userID string) (*uapi.LoginTokenMetadata, error) {
	req := uapi.PerformLoginTokenCreationRequest{Data: uapi.LoginTokenData{UserID: userID}}
	var resp uapi.PerformLoginTokenCreationResponse
	if err := userAPI.PerformLoginTokenCreation(ctx, &req, &resp); err != nil {
		return nil, err
	}
	return &resp.Metadata, nil
}
