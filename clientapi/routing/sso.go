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
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/matrix-org/dendrite/clientapi/auth/sso"
	"github.com/matrix-org/dendrite/clientapi/jsonerror"
	"github.com/matrix-org/dendrite/clientapi/userutil"
	uapi "github.com/matrix-org/dendrite/userapi/api"
	"github.com/matrix-org/gomatrixserverlib"
	"github.com/matrix-org/util"
)

// SSORedirect implements /login/sso/redirect
// https://spec.matrix.org/v1.2/client-server-api/#redirecting-to-the-authentication-server
func SSORedirect(
	req *http.Request,
	idpID string,
	auth *sso.Authenticator,
) util.JSONResponse {
	if auth == nil {
		return util.JSONResponse{
			Code: http.StatusNotFound,
			JSON: jsonerror.NotFound("authentication method disabled"),
		}
	}

	redirectURL := req.URL.Query().Get("redirectUrl")
	if redirectURL == "" {
		return util.JSONResponse{
			Code: http.StatusBadRequest,
			JSON: jsonerror.MissingArgument("redirectUrl parameter missing"),
		}
	}
	_, err := url.Parse(redirectURL)
	if err != nil {
		return util.JSONResponse{
			Code: http.StatusBadRequest,
			JSON: jsonerror.InvalidArgumentValue("Invalid redirectURL: " + err.Error()),
		}
	}

	callbackURL := req.URL.ResolveReference(&url.URL{Path: "../callback", RawQuery: url.Values{"provider": []string{idpID}}.Encode()})
	nonce := formatNonce(redirectURL)
	u, err := auth.AuthorizationURL(req.Context(), idpID, callbackURL.String(), nonce)
	if err != nil {
		return util.JSONResponse{
			Code: http.StatusInternalServerError,
			JSON: err,
		}
	}

	resp := util.RedirectResponse(u)
	resp.Headers["Set-Cookie"] = (&http.Cookie{
		Name:     "oidc_nonce",
		Value:    nonce,
		Expires:  time.Now().Add(10 * time.Minute),
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}).String()
	return resp
}

// SSOCallback implements /login/sso/callback.
// https://spec.matrix.org/v1.2/client-server-api/#handling-the-callback-from-the-authentication-server
func SSOCallback(
	req *http.Request,
	userAPI userAPIForSSO,
	auth *sso.Authenticator,
	serverName gomatrixserverlib.ServerName,
) util.JSONResponse {
	if auth == nil {
		return util.JSONResponse{
			Code: http.StatusNotFound,
			JSON: jsonerror.NotFound("authentication method disabled"),
		}
	}

	ctx := req.Context()

	query := req.URL.Query()
	idpID := query.Get("provider")
	if idpID == "" {
		return util.JSONResponse{
			Code: http.StatusBadRequest,
			JSON: jsonerror.MissingArgument("provider parameter missing"),
		}
	}

	nonce, err := req.Cookie("oidc_nonce")
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

	callbackURL := &url.URL{
		Scheme: req.URL.Scheme,
		Host:   req.URL.Host,
		Path:   req.URL.Path,
		RawQuery: url.Values{
			"provider": []string{idpID},
		}.Encode(),
	}
	result, err := auth.ProcessCallback(ctx, idpID, callbackURL.String(), nonce.Value, query)
	if err != nil {
		return util.JSONResponse{
			Code: http.StatusInternalServerError,
			JSON: err,
		}
	}

	if result.Identifier == nil {
		// Not authenticated yet.
		return util.RedirectResponse(result.RedirectURL)
	}

	localpart, err := verifySSOUserIdentifier(ctx, userAPI, result.Identifier, serverName)
	if err != nil {
		util.GetLogger(ctx).WithError(err).WithField("identifier", result.Identifier).Error("failed to find user")
		return util.JSONResponse{
			Code: http.StatusUnauthorized,
			JSON: jsonerror.Forbidden("ID not associated with a local account"),
		}
	}
	if localpart == "" {
		// The user doesn't exist.
		// TODO: let the user select the local part, and whether to associate email addresses.
		localpart = result.SuggestedUserID
		ok, resp := registerSSOAccount(ctx, userAPI, result.Identifier, localpart)
		if !ok {
			util.GetLogger(ctx).WithError(err).WithField("identifier", result.Identifier).WithField("localpart", localpart).Error("failed to create account")
			return resp
		}
	}

	token, err := createLoginToken(ctx, userAPI, userutil.MakeUserID(localpart, serverName))
	if err != nil {
		util.GetLogger(ctx).WithError(err).Errorf("PerformLoginTokenCreation failed")
		return jsonerror.InternalServerError()
	}

	rquery := finalRedirectURL.Query()
	rquery.Set("loginToken", token.Token)
	resp := util.RedirectResponse(finalRedirectURL.ResolveReference(&url.URL{RawQuery: rquery.Encode()}).String())
	resp.Headers["Set-Cookie"] = (&http.Cookie{
		Name:   "oidc_nonce",
		Value:  "",
		MaxAge: -1,
		Secure: true,
	}).String()
	return resp
}

type userAPIForSSO interface {
	uapi.LoginTokenInternalAPI

	PerformAccountCreation(ctx context.Context, req *uapi.PerformAccountCreationRequest, res *uapi.PerformAccountCreationResponse) error
	PerformSaveSSOAssociation(ctx context.Context, req *uapi.PerformSaveSSOAssociationRequest, res *struct{}) error
	QueryLocalpartForSSO(ctx context.Context, req *uapi.QueryLocalpartForSSORequest, res *uapi.QueryLocalpartForSSOResponse) error
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
		return nil, jsonerror.MissingArgument("empty OIDC nonce cookie")
	}

	ss := strings.Split(s, ".")
	if len(ss) < 2 {
		return nil, jsonerror.InvalidArgumentValue("malformed OIDC nonce cookie")
	}

	urlbs, err := base64.RawURLEncoding.DecodeString(ss[1])
	if err != nil {
		return nil, jsonerror.InvalidArgumentValue("invalid redirect URL in OIDC nonce cookie")
	}
	u, err := url.Parse(string(urlbs))
	if err != nil {
		return nil, jsonerror.InvalidArgumentValue("invalid redirect URL in OIDC nonce cookie: " + err.Error())
	}

	return u, nil
}

// verifySSOUserIdentifier resolves an sso.UserIdentifier to a local
// part using the User API. Returns empty if there is no associated
// user.
func verifySSOUserIdentifier(ctx context.Context, userAPI userAPIForSSO, id *sso.UserIdentifier, serverName gomatrixserverlib.ServerName) (localpart string, _ error) {
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
