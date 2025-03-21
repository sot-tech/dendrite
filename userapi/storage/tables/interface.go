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

package tables

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/matrix-org/dendrite/userapi/api"
	"github.com/matrix-org/gomatrixserverlib"

	"github.com/matrix-org/dendrite/clientapi/auth/authtypes"
	"github.com/matrix-org/dendrite/userapi/types"
)

type AccountDataTable interface {
	InsertAccountData(ctx context.Context, txn *sql.Tx, localpart string, serverName gomatrixserverlib.ServerName, roomID, dataType string, content json.RawMessage) error
	SelectAccountData(ctx context.Context, localpart string, serverName gomatrixserverlib.ServerName) (map[string]json.RawMessage, map[string]map[string]json.RawMessage, error)
	SelectAccountDataByType(ctx context.Context, localpart string, serverName gomatrixserverlib.ServerName, roomID, dataType string) (data json.RawMessage, err error)
}

type AccountsTable interface {
	InsertAccount(ctx context.Context, txn *sql.Tx, localpart string, serverName gomatrixserverlib.ServerName, hash, appserviceID string, accountType api.AccountType) (*api.Account, error)
	UpdatePassword(ctx context.Context, localpart string, serverName gomatrixserverlib.ServerName, passwordHash string) (err error)
	DeactivateAccount(ctx context.Context, localpart string, serverName gomatrixserverlib.ServerName) (err error)
	SelectPasswordHash(ctx context.Context, localpart string, serverName gomatrixserverlib.ServerName) (hash string, err error)
	SelectAccountByLocalpart(ctx context.Context, localpart string, serverName gomatrixserverlib.ServerName) (*api.Account, error)
	SelectNewNumericLocalpart(ctx context.Context, txn *sql.Tx, serverName gomatrixserverlib.ServerName) (id int64, err error)
}

type DevicesTable interface {
	InsertDevice(ctx context.Context, txn *sql.Tx, id, localpart string, serverName gomatrixserverlib.ServerName, accessToken string, displayName *string, ipAddr, userAgent string) (*api.Device, error)
	InsertDeviceWithSessionID(ctx context.Context, txn *sql.Tx, id, localpart string, serverName gomatrixserverlib.ServerName, accessToken string, displayName *string, ipAddr, userAgent string, sessionID int64) (*api.Device, error)
	DeleteDevice(ctx context.Context, txn *sql.Tx, id, localpart string, serverName gomatrixserverlib.ServerName) error
	DeleteDevices(ctx context.Context, txn *sql.Tx, localpart string, serverName gomatrixserverlib.ServerName, devices []string) error
	DeleteDevicesByLocalpart(ctx context.Context, txn *sql.Tx, localpart string, serverName gomatrixserverlib.ServerName, exceptDeviceID string) error
	UpdateDeviceName(ctx context.Context, txn *sql.Tx, localpart string, serverName gomatrixserverlib.ServerName, deviceID string, displayName *string) error
	SelectDeviceByToken(ctx context.Context, accessToken string) (*api.Device, error)
	SelectDeviceByID(ctx context.Context, localpart string, serverName gomatrixserverlib.ServerName, deviceID string) (*api.Device, error)
	SelectDevicesByLocalpart(ctx context.Context, txn *sql.Tx, localpart string, serverName gomatrixserverlib.ServerName, exceptDeviceID string) ([]api.Device, error)
	SelectDevicesByID(ctx context.Context, deviceIDs []string) ([]api.Device, error)
	UpdateDeviceLastSeen(ctx context.Context, txn *sql.Tx, localpart string, serverName gomatrixserverlib.ServerName, deviceID, ipAddr, userAgent string) error
}

type KeyBackupTable interface {
	CountKeys(ctx context.Context, txn *sql.Tx, userID, version string) (count int64, err error)
	InsertBackupKey(ctx context.Context, txn *sql.Tx, userID, version string, key api.InternalKeyBackupSession) (err error)
	UpdateBackupKey(ctx context.Context, txn *sql.Tx, userID, version string, key api.InternalKeyBackupSession) (err error)
	SelectKeys(ctx context.Context, txn *sql.Tx, userID, version string) (map[string]map[string]api.KeyBackupSession, error)
	SelectKeysByRoomID(ctx context.Context, txn *sql.Tx, userID, version, roomID string) (map[string]map[string]api.KeyBackupSession, error)
	SelectKeysByRoomIDAndSessionID(ctx context.Context, txn *sql.Tx, userID, version, roomID, sessionID string) (map[string]map[string]api.KeyBackupSession, error)
}

type KeyBackupVersionTable interface {
	InsertKeyBackup(ctx context.Context, txn *sql.Tx, userID, algorithm string, authData json.RawMessage, etag string) (version string, err error)
	UpdateKeyBackupAuthData(ctx context.Context, txn *sql.Tx, userID, version string, authData json.RawMessage) error
	UpdateKeyBackupETag(ctx context.Context, txn *sql.Tx, userID, version, etag string) error
	DeleteKeyBackup(ctx context.Context, txn *sql.Tx, userID, version string) (bool, error)
	SelectKeyBackup(ctx context.Context, txn *sql.Tx, userID, version string) (versionResult, algorithm string, authData json.RawMessage, etag string, deleted bool, err error)
}

type LoginTokenTable interface {
	InsertLoginToken(ctx context.Context, txn *sql.Tx, metadata *api.LoginTokenMetadata, data *api.LoginTokenData) error
	DeleteLoginToken(ctx context.Context, txn *sql.Tx, token string) error
	SelectLoginToken(ctx context.Context, token string) (*api.LoginTokenData, error)
}

type OpenIDTable interface {
	InsertOpenIDToken(ctx context.Context, txn *sql.Tx, token, localpart string, serverName gomatrixserverlib.ServerName, expiresAtMS int64) (err error)
	SelectOpenIDTokenAtrributes(ctx context.Context, token string) (*api.OpenIDTokenAttributes, error)
}

type ProfileTable interface {
	InsertProfile(ctx context.Context, txn *sql.Tx, localpart string, serverName gomatrixserverlib.ServerName) error
	SelectProfileByLocalpart(ctx context.Context, localpart string, serverName gomatrixserverlib.ServerName) (*authtypes.Profile, error)
	SetAvatarURL(ctx context.Context, txn *sql.Tx, localpart string, serverName gomatrixserverlib.ServerName, avatarURL string) (*authtypes.Profile, bool, error)
	SetDisplayName(ctx context.Context, txn *sql.Tx, localpart string, serverName gomatrixserverlib.ServerName, displayName string) (*authtypes.Profile, bool, error)
	SelectProfilesBySearch(ctx context.Context, searchString string, limit int) ([]authtypes.Profile, error)
}

type ThreePIDTable interface {
	SelectLocalpartForThreePID(ctx context.Context, txn *sql.Tx, threepid string, medium string) (localpart string, serverName gomatrixserverlib.ServerName, err error)
	SelectThreePIDsForLocalpart(ctx context.Context, localpart string, serverName gomatrixserverlib.ServerName) (threepids []authtypes.ThreePID, err error)
	InsertThreePID(ctx context.Context, txn *sql.Tx, threepid, medium, localpart string, serverName gomatrixserverlib.ServerName) (err error)
	DeleteThreePID(ctx context.Context, txn *sql.Tx, threepid string, medium string) (err error)
}

type PusherTable interface {
	InsertPusher(ctx context.Context, txn *sql.Tx, session_id int64, pushkey string, pushkeyTS int64, kind api.PusherKind, appid, appdisplayname, devicedisplayname, profiletag, lang, data, localpart string, serverName gomatrixserverlib.ServerName) error
	SelectPushers(ctx context.Context, txn *sql.Tx, localpart string, serverName gomatrixserverlib.ServerName) ([]api.Pusher, error)
	DeletePusher(ctx context.Context, txn *sql.Tx, appid, pushkey, localpart string, serverName gomatrixserverlib.ServerName) error
	DeletePushers(ctx context.Context, txn *sql.Tx, appid, pushkey string) error
}

type NotificationTable interface {
	Clean(ctx context.Context, txn *sql.Tx) error
	Insert(ctx context.Context, txn *sql.Tx, localpart string, serverName gomatrixserverlib.ServerName, eventID string, pos uint64, highlight bool, n *api.Notification) error
	DeleteUpTo(ctx context.Context, txn *sql.Tx, localpart string, serverName gomatrixserverlib.ServerName, roomID string, pos uint64) (affected bool, _ error)
	UpdateRead(ctx context.Context, txn *sql.Tx, localpart string, serverName gomatrixserverlib.ServerName, roomID string, pos uint64, v bool) (affected bool, _ error)
	Select(ctx context.Context, txn *sql.Tx, localpart string, serverName gomatrixserverlib.ServerName, fromID int64, limit int, filter NotificationFilter) ([]*api.Notification, int64, error)
	SelectCount(ctx context.Context, txn *sql.Tx, localpart string, serverName gomatrixserverlib.ServerName, filter NotificationFilter) (int64, error)
	SelectRoomCounts(ctx context.Context, txn *sql.Tx, localpart string, serverName gomatrixserverlib.ServerName, roomID string) (total int64, highlight int64, _ error)
}

type SSOTable interface {
	SelectLocalpartForSSO(ctx context.Context, txn *sql.Tx, namespace, iss, sub string) (string, error)
	InsertSSO(ctx context.Context, txn *sql.Tx, namespace, iss, sub, localpart string) error
	DeleteSSO(ctx context.Context, txn *sql.Tx, namespace, iss, sub string) error
}

type StatsTable interface {
	UserStatistics(ctx context.Context, txn *sql.Tx) (*types.UserStatistics, *types.DatabaseEngine, error)
	DailyRoomsMessages(ctx context.Context, txn *sql.Tx, serverName gomatrixserverlib.ServerName) (msgStats types.MessageStats, activeRooms, activeE2EERooms int64, err error)
	UpdateUserDailyVisits(ctx context.Context, txn *sql.Tx, startTime, lastUpdate time.Time) error
	UpsertDailyStats(ctx context.Context, txn *sql.Tx, serverName gomatrixserverlib.ServerName, stats types.MessageStats, activeRooms, activeE2EERooms int64) error
}

type NotificationFilter uint32

const (
	// HighlightNotifications returns notifications that had a
	// "highlight" tweak assigned to them from evaluating push rules.
	HighlightNotifications NotificationFilter = 1 << iota

	// NonHighlightNotifications returns notifications that don't
	// match HighlightNotifications.
	NonHighlightNotifications

	// NoNotifications is a filter to exclude all types of
	// notifications. It's useful as a zero value, but isn't likely to
	// be used in a call to Notifications.Select*.
	NoNotifications NotificationFilter = 0

	// AllNotifications is a filter to include all types of
	// notifications in Notifications.Select*. Note that PostgreSQL
	// balks if this doesn't fit in INTEGER, even though we use
	// uint32.
	AllNotifications NotificationFilter = (1 << 31) - 1
)

type OneTimeKeys interface {
	SelectOneTimeKeys(ctx context.Context, userID, deviceID string, keyIDsWithAlgorithms []string) (map[string]json.RawMessage, error)
	CountOneTimeKeys(ctx context.Context, userID, deviceID string) (*api.OneTimeKeysCount, error)
	InsertOneTimeKeys(ctx context.Context, txn *sql.Tx, keys api.OneTimeKeys) (*api.OneTimeKeysCount, error)
	// SelectAndDeleteOneTimeKey selects a single one time key matching the user/device/algorithm specified and returns the algo:key_id => JSON.
	// Returns an empty map if the key does not exist.
	SelectAndDeleteOneTimeKey(ctx context.Context, txn *sql.Tx, userID, deviceID, algorithm string) (map[string]json.RawMessage, error)
	DeleteOneTimeKeys(ctx context.Context, txn *sql.Tx, userID, deviceID string) error
}

type DeviceKeys interface {
	SelectDeviceKeysJSON(ctx context.Context, keys []api.DeviceMessage) error
	InsertDeviceKeys(ctx context.Context, txn *sql.Tx, keys []api.DeviceMessage) error
	SelectMaxStreamIDForUser(ctx context.Context, txn *sql.Tx, userID string) (streamID int64, err error)
	CountStreamIDsForUser(ctx context.Context, userID string, streamIDs []int64) (int, error)
	SelectBatchDeviceKeys(ctx context.Context, userID string, deviceIDs []string, includeEmpty bool) ([]api.DeviceMessage, error)
	DeleteDeviceKeys(ctx context.Context, txn *sql.Tx, userID, deviceID string) error
	DeleteAllDeviceKeys(ctx context.Context, txn *sql.Tx, userID string) error
}

type KeyChanges interface {
	InsertKeyChange(ctx context.Context, userID string) (int64, error)
	// SelectKeyChanges returns the set (de-duplicated) of users who have changed their keys between the two offsets.
	// Results are exclusive of fromOffset and inclusive of toOffset. A toOffset of types.OffsetNewest means no upper offset.
	SelectKeyChanges(ctx context.Context, fromOffset, toOffset int64) (userIDs []string, latestOffset int64, err error)
}

type StaleDeviceLists interface {
	InsertStaleDeviceList(ctx context.Context, userID string, isStale bool) error
	SelectUserIDsWithStaleDeviceLists(ctx context.Context, domains []gomatrixserverlib.ServerName) ([]string, error)
	DeleteStaleDeviceLists(ctx context.Context, txn *sql.Tx, userIDs []string) error
}

type CrossSigningKeys interface {
	SelectCrossSigningKeysForUser(ctx context.Context, txn *sql.Tx, userID string) (r types.CrossSigningKeyMap, err error)
	UpsertCrossSigningKeysForUser(ctx context.Context, txn *sql.Tx, userID string, keyType gomatrixserverlib.CrossSigningKeyPurpose, keyData gomatrixserverlib.Base64Bytes) error
}

type CrossSigningSigs interface {
	SelectCrossSigningSigsForTarget(ctx context.Context, txn *sql.Tx, originUserID, targetUserID string, targetKeyID gomatrixserverlib.KeyID) (r types.CrossSigningSigMap, err error)
	UpsertCrossSigningSigsForTarget(ctx context.Context, txn *sql.Tx, originUserID string, originKeyID gomatrixserverlib.KeyID, targetUserID string, targetKeyID gomatrixserverlib.KeyID, signature gomatrixserverlib.Base64Bytes) error
	DeleteCrossSigningSigsForTarget(ctx context.Context, txn *sql.Tx, targetUserID string, targetKeyID gomatrixserverlib.KeyID) error
}
