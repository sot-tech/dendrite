// Copyright 2020 The Matrix.org Foundation C.I.C.
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

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/matrix-org/dendrite/clientapi/auth/authtypes"
	"net/http"
	"sync"

	"github.com/matrix-org/dendrite/clientapi/jsonerror"
	"github.com/matrix-org/dendrite/setup/config"
	"github.com/matrix-org/dendrite/userapi/api"
	"github.com/matrix-org/util"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

// Type represents an auth type
// https://matrix.org/docs/spec/client_server/r0.6.1#authentication-types
type Type interface {
	// Name returns the name of the auth type e.g `m.login.password`
	Name() authtypes.LoginType
	// Login with the auth type, returning an error response on failure.
	// Not all types support login, only m.login.password and m.login.token
	// See https://matrix.org/docs/spec/client_server/r0.6.1#post-matrix-client-r0-login
	// This function will be called when doing login and when doing 'sudo' style
	// actions e.g deleting devices. The response must be a 401 as per:
	// "If the homeserver decides that an attempt on a stage was unsuccessful, but the
	// client may make a second attempt, it returns the same HTTP status 401 response as above,
	// with the addition of the standard errcode and error fields describing the error."
	//
	// The returned cleanup function must be non-nil on success, and will be called after
	// authorization has been completed. Its argument is the final result of authorization.
	LoginFromJSON(ctx context.Context, reqBytes []byte) (login *Login, cleanup LoginCleanupFunc, errRes *util.JSONResponse)
	// TODO: Extend to support Register() flow
	// Register(ctx context.Context, sessionID string, req interface{})
}

type LoginCleanupFunc func(context.Context, *util.JSONResponse)

// LoginIdentifier represents identifier types
// https://matrix.org/docs/spec/client_server/r0.6.1#identifier-types
type LoginIdentifier struct {
	Type string `json:"type"`
	// when type = m.id.user
	User string `json:"user"`
	// when type = m.id.thirdparty
	Medium  string `json:"medium"`
	Address string `json:"address"`
}

// Login represents the shared fields used in all forms of login/sudo endpoints.
type Login struct {
	LoginIdentifier                 // Flat fields deprecated in favour of `identifier`.
	Identifier      LoginIdentifier `json:"identifier"`

	// Both DeviceID and InitialDisplayName can be omitted, or empty strings ("")
	// Thus a pointer is needed to differentiate between the two
	InitialDisplayName *string `json:"initial_device_display_name"`
	DeviceID           *string `json:"device_id"`
}

// Username returns the user localpart/user_id in this request, if it exists.
func (r *Login) Username() string {
	if r.Identifier.Type == "m.id.user" {
		return r.Identifier.User
	}
	// deprecated but without it Element iOS won't log in
	return r.User
}

// ThirdPartyID returns the 3PID medium and address for this login, if it exists.
func (r *Login) ThirdPartyID() (medium, address string) {
	if r.Identifier.Type == "m.id.thirdparty" {
		return r.Identifier.Medium, r.Identifier.Address
	}
	// deprecated
	if r.Medium == "email" {
		return "email", r.Address
	}
	return "", ""
}

// UserInteractive checks that the user is who they claim to be, via a UI auth.
// This is used for things like device deletion and password reset where
// the user already has a valid access token, but we want to double-check
// that it isn't stolen by re-authenticating them.
type UserInteractive struct {
	sync.RWMutex
	Flows []authtypes.Flow
	// Map of login type to implementation
	Types map[authtypes.LoginType]Type
	// Map of session ID to completed login types, will need to be extended in future
	Sessions map[string][]string
}

type dummyType struct {
}

func (dummyType) Name() authtypes.LoginType {
	return authtypes.LoginTypeSSO
}

func (dummyType) LoginFromJSON(_ context.Context, in []byte) (login *Login, cleanup LoginCleanupFunc, errRes *util.JSONResponse) {
	fmt.Println(string(in))
	return nil, nil, nil
}

func NewUserInteractive(userAccountAPI api.UserLoginAPI, cfg *config.ClientAPI) *UserInteractive {
	typePassword := &LoginTypePassword{
		GetAccountByPassword: userAccountAPI.QueryAccountByPassword,
		Config:               cfg,
	}
	flows := make([]authtypes.Flow, 0, 2)
	types := make(map[authtypes.LoginType]Type)
	if cfg.Login.SSO.Enabled {
		typeSSO := &dummyType{}
		flows = append(flows, authtypes.Flow{
			Stages: []authtypes.LoginType{typeSSO.Name()},
		})
		types[authtypes.LoginTypeSSO] = typeSSO
	}
	flows = append(flows, authtypes.Flow{
		Stages: []authtypes.LoginType{typePassword.Name()},
	})
	types[typePassword.Name()] = typePassword

	return &UserInteractive{
		Flows:    flows,
		Types:    types,
		Sessions: make(map[string][]string),
	}
}

func (u *UserInteractive) HasCompletedFlows(authFlows []authtypes.Flow, completedTypes []authtypes.LoginType) bool {
	u.RLock()
	defer u.RUnlock()
	for _, f := range authFlows {
		incompleteStages := make([]authtypes.LoginType, 0, len(f.Stages))
		for _, s := range f.Stages {
			var found bool
			for _, cs := range completedTypes {
				if s == cs {
					found = true
					break
				}
			}
			if !found {
				incompleteStages = append(incompleteStages, s)
			}
		}
		if len(incompleteStages) == 0 {
			return true
		}
	}
	return false
}

func (u *UserInteractive) PasswordLessFlows() []authtypes.Flow {
	filteredFlows := make([]authtypes.Flow, 0, len(u.Flows))
	for _, f := range u.Flows {
		nonPasswordStages := make([]authtypes.LoginType, 0, len(f.Stages))
		for _, s := range f.Stages {
			if s != authtypes.LoginTypePassword {
				nonPasswordStages = append(nonPasswordStages, s)
			}
		}
		if len(nonPasswordStages) > 0 {
			filteredFlows = append(filteredFlows, f)
		}
	}
	return filteredFlows
}

func (u *UserInteractive) IsSingleStageFlow(authType authtypes.LoginType) bool {
	u.RLock()
	defer u.RUnlock()
	for _, f := range u.Flows {
		if len(f.Stages) == 1 && f.Stages[0] == authType {
			return true
		}
	}
	return false
}

func (u *UserInteractive) AddCompletedStage(sessionID, authType string) {
	u.Lock()
	// TODO: Handle multi-stage flows
	delete(u.Sessions, sessionID)
	u.Unlock()
}

type Challenge struct {
	Completed []string         `json:"completed"`
	Flows     []authtypes.Flow `json:"flows"`
	Session   string           `json:"session"`
	// TODO: Return any additional `params`
	Params map[string]interface{} `json:"params"`
}

// Challenge returns an HTTP 401 with the supported flows for authenticating
func (u *UserInteractive) challenge(sessionID string) *util.JSONResponse {
	u.RLock()
	completed := u.Sessions[sessionID]
	flows := u.Flows
	u.RUnlock()

	return &util.JSONResponse{
		Code: http.StatusUnauthorized,
		JSON: Challenge{
			Completed: completed,
			Flows:     flows,
			Session:   sessionID,
			Params:    make(map[string]interface{}),
		},
	}
}

// NewSession returns a challenge with a new session ID and remembers the session ID
func (u *UserInteractive) NewSession() *util.JSONResponse {
	sessionID, err := GenerateAccessToken()
	if err != nil {
		logrus.WithError(err).Error("failed to generate session ID")
		res := jsonerror.InternalServerError()
		return &res
	}
	u.Lock()
	u.Sessions[sessionID] = []string{}
	u.Unlock()
	return u.challenge(sessionID)
}

// ResponseWithChallenge mixes together a JSON body (e.g an error with errcode/message) with the
// standard challenge response.
func (u *UserInteractive) ResponseWithChallenge(sessionID string, response interface{}) *util.JSONResponse {
	mixedObjects := make(map[string]interface{})
	b, err := json.Marshal(response)
	if err != nil {
		ise := jsonerror.InternalServerError()
		return &ise
	}
	_ = json.Unmarshal(b, &mixedObjects)
	challenge := u.challenge(sessionID)
	b, err = json.Marshal(challenge.JSON)
	if err != nil {
		ise := jsonerror.InternalServerError()
		return &ise
	}
	_ = json.Unmarshal(b, &mixedObjects)

	return &util.JSONResponse{
		Code: 401,
		JSON: mixedObjects,
	}
}

// Verify returns an error/challenge response to send to the client, or nil if the user is authenticated.
// `bodyBytes` is the HTTP request body which must contain an `auth` key.
// Returns the login that was verified for additional checks if required.
func (u *UserInteractive) Verify(ctx context.Context, bodyBytes []byte, device *api.Device) (*Login, *util.JSONResponse) {
	// TODO: rate limit

	// "A client should first make a request with no auth parameter. The homeserver returns an HTTP 401 response, with a JSON body"
	// https://matrix.org/docs/spec/client_server/r0.6.1#user-interactive-api-in-the-rest-api
	hasResponse := gjson.GetBytes(bodyBytes, "auth").Exists()
	if !hasResponse {
		return nil, u.NewSession()
	}

	// extract the type so we know which login type to use
	authType := gjson.GetBytes(bodyBytes, "auth.type").Str

	u.RLock()
	loginType, ok := u.Types[authtypes.LoginType(authType)]
	u.RUnlock()

	if !ok {
		return nil, &util.JSONResponse{
			Code: http.StatusBadRequest,
			JSON: jsonerror.BadJSON("Unknown auth.type: " + authType),
		}
	}

	// retrieve the session
	sessionID := gjson.GetBytes(bodyBytes, "auth.session").Str

	u.RLock()
	_, ok = u.Sessions[sessionID]
	u.RUnlock()

	if !ok {
		// if the login type is part of a single stage flow then allow them to omit the session ID
		if !u.IsSingleStageFlow(authtypes.LoginType(authType)) {
			return nil, &util.JSONResponse{
				Code: http.StatusBadRequest,
				JSON: jsonerror.Unknown("The auth.session is missing or unknown."),
			}
		}
	}

	login, cleanup, resErr := loginType.LoginFromJSON(ctx, []byte(gjson.GetBytes(bodyBytes, "auth").Raw))
	if resErr != nil {
		return nil, u.ResponseWithChallenge(sessionID, resErr.JSON)
	}

	u.AddCompletedStage(sessionID, authType)
	cleanup(ctx, nil)
	// TODO: Check if there's more stages to go and return an error
	return login, nil
}
