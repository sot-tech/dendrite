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
	"net/http"

	"github.com/matrix-org/dendrite/setup/config"
)

func newGitHubIdentityProvider(cfg *config.IdentityProvider, hc *http.Client) (identityProvider, error) {
	cfg.Scopes = []string{"user:email"}
	cfg.OAuth2Endpoints = config.OAuth2Endpoints{
		Authorization: "https://github.com/login/oauth/authorize",
		AccessToken:   "https://github.com/login/oauth/access_token",
		UserInfo:      "https://api.github.com/user",
	}
	cfg.ResponseMimeType = "application/vnd.github.v3+json"
	cfg.Claims = config.OAuth2Claims{
		Subject:         "id",
		Email:           "email",
		DisplayName:     "name",
		SuggestedUserID: "login",
	}
	return newOAuth2IdentityProvider(cfg, hc)
}
