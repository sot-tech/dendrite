// Copyright 2017 Vector Creations Ltd
// Copyright 2018 New Vector Ltd
// Copyright 2019-2020 The Matrix.org Foundation C.I.C.
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

package api

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/matrix-org/gomatrixserverlib"

	"github.com/matrix-org/dendrite/clientapi/auth/authtypes"
)

// QueryLatestEventsAndStateRequest is a request to QueryLatestEventsAndState
type QueryLatestEventsAndStateRequest struct {
	// The room ID to query the latest events for.
	RoomID string `json:"room_id"`
	// The state key tuples to fetch from the room current state.
	// If this list is empty or nil then *ALL* current state events are returned.
	StateToFetch []gomatrixserverlib.StateKeyTuple `json:"state_to_fetch"`
}

// QueryLatestEventsAndStateResponse is a response to QueryLatestEventsAndState
// This is used when sending events to set the prev_events, auth_events and depth.
// It is also used to tell whether the event is allowed by the event auth rules.
type QueryLatestEventsAndStateResponse struct {
	// Does the room exist?
	// If the room doesn't exist this will be false and LatestEvents will be empty.
	RoomExists bool `json:"room_exists"`
	// The room version of the room.
	RoomVersion gomatrixserverlib.RoomVersion `json:"room_version"`
	// The latest events in the room.
	// These are used to set the prev_events when sending an event.
	LatestEvents []gomatrixserverlib.EventReference `json:"latest_events"`
	// The state events requested.
	// This list will be in an arbitrary order.
	// These are used to set the auth_events when sending an event.
	// These are used to check whether the event is allowed.
	StateEvents []*gomatrixserverlib.HeaderedEvent `json:"state_events"`
	// The depth of the latest events.
	// This is one greater than the maximum depth of the latest events.
	// This is used to set the depth when sending an event.
	Depth int64 `json:"depth"`
}

// QueryStateAfterEventsRequest is a request to QueryStateAfterEvents
type QueryStateAfterEventsRequest struct {
	// The room ID to query the state in.
	RoomID string `json:"room_id"`
	// The list of previous events to return the events after.
	PrevEventIDs []string `json:"prev_event_ids"`
	// The state key tuples to fetch from the state. If none are specified then
	// the entire resolved room state will be returned.
	StateToFetch []gomatrixserverlib.StateKeyTuple `json:"state_to_fetch"`
}

// QueryStateAfterEventsResponse is a response to QueryStateAfterEvents
type QueryStateAfterEventsResponse struct {
	// Does the room exist on this roomserver?
	// If the room doesn't exist this will be false and StateEvents will be empty.
	RoomExists bool `json:"room_exists"`
	// The room version of the room.
	RoomVersion gomatrixserverlib.RoomVersion `json:"room_version"`
	// Do all the previous events exist on this roomserver?
	// If some of previous events do not exist this will be false and StateEvents will be empty.
	PrevEventsExist bool `json:"prev_events_exist"`
	// The state events requested.
	// This list will be in an arbitrary order.
	StateEvents []*gomatrixserverlib.HeaderedEvent `json:"state_events"`
}

// QueryEventsByIDRequest is a request to QueryEventsByID
type QueryEventsByIDRequest struct {
	// The roomID to query events for. If this is empty, we first try to fetch the roomID from the database
	// as this is needed for further processing/parsing events.
	RoomID string `json:"room_id"`
	// The event IDs to look up.
	EventIDs []string `json:"event_ids"`
}

// QueryEventsByIDResponse is a response to QueryEventsByID
type QueryEventsByIDResponse struct {
	// A list of events with the requested IDs.
	// If the roomserver does not have a copy of a requested event
	// then it will omit that event from the list.
	// If the roomserver thinks it has a copy of the event, but
	// fails to read it from the database then it will fail
	// the entire request.
	// This list will be in an arbitrary order.
	Events []*gomatrixserverlib.HeaderedEvent `json:"events"`
}

// QueryMembershipForUserRequest is a request to QueryMembership
type QueryMembershipForUserRequest struct {
	// ID of the room to fetch membership from
	RoomID string `json:"room_id"`
	// ID of the user for whom membership is requested
	UserID string `json:"user_id"`
}

// QueryMembershipForUserResponse is a response to QueryMembership
type QueryMembershipForUserResponse struct {
	// The EventID of the latest "m.room.member" event for the sender,
	// if HasBeenInRoom is true.
	EventID string `json:"event_id"`
	// True if the user has been in room before and has either stayed in it or left it.
	HasBeenInRoom bool `json:"has_been_in_room"`
	// True if the user is in room.
	IsInRoom bool `json:"is_in_room"`
	// The current membership
	Membership string `json:"membership"`
	// True if the user asked to forget this room.
	IsRoomForgotten bool `json:"is_room_forgotten"`
	RoomExists      bool `json:"room_exists"`
}

// QueryMembershipsForRoomRequest is a request to QueryMembershipsForRoom
type QueryMembershipsForRoomRequest struct {
	// If true, only returns the membership events of "join" membership
	JoinedOnly bool `json:"joined_only"`
	// If true, only returns the membership events of local users
	LocalOnly bool `json:"local_only"`
	// ID of the room to fetch memberships from
	RoomID string `json:"room_id"`
	// Optional - ID of the user sending the request, for checking if the
	// user is allowed to see the memberships. If not specified then all
	// room memberships will be returned.
	Sender string `json:"sender"`
}

// QueryMembershipsForRoomResponse is a response to QueryMembershipsForRoom
type QueryMembershipsForRoomResponse struct {
	// The "m.room.member" events (of "join" membership) in the client format
	JoinEvents []gomatrixserverlib.ClientEvent `json:"join_events"`
	// True if the user has been in room before and has either stayed in it or
	// left it.
	HasBeenInRoom bool `json:"has_been_in_room"`
	// True if the user asked to forget this room.
	IsRoomForgotten bool `json:"is_room_forgotten"`
}

// QueryServerJoinedToRoomRequest is a request to QueryServerJoinedToRoom
type QueryServerJoinedToRoomRequest struct {
	// Server name of the server to find. If not specified, we will
	// default to checking if the local server is joined.
	ServerName gomatrixserverlib.ServerName `json:"server_name"`
	// ID of the room to see if we are still joined to
	RoomID string `json:"room_id"`
}

// QueryMembershipsForRoomResponse is a response to QueryServerJoinedToRoom
type QueryServerJoinedToRoomResponse struct {
	// True if the room exists on the server
	RoomExists bool `json:"room_exists"`
	// True if we still believe that the server is participating in the room
	IsInRoom bool `json:"is_in_room"`
}

// QueryServerAllowedToSeeEventRequest is a request to QueryServerAllowedToSeeEvent
type QueryServerAllowedToSeeEventRequest struct {
	// The event ID to look up invites in.
	EventID string `json:"event_id"`
	// The server interested in the event
	ServerName gomatrixserverlib.ServerName `json:"server_name"`
}

// QueryServerAllowedToSeeEventResponse is a response to QueryServerAllowedToSeeEvent
type QueryServerAllowedToSeeEventResponse struct {
	// Wether the server in question is allowed to see the event
	AllowedToSeeEvent bool `json:"can_see_event"`
}

// QueryMissingEventsRequest is a request to QueryMissingEvents
type QueryMissingEventsRequest struct {
	// Events which are known previous to the gap in the timeline.
	EarliestEvents []string `json:"earliest_events"`
	// Latest known events.
	LatestEvents []string `json:"latest_events"`
	// Limit the number of events this query returns.
	Limit int `json:"limit"`
	// The server interested in the event
	ServerName gomatrixserverlib.ServerName `json:"server_name"`
}

// QueryMissingEventsResponse is a response to QueryMissingEvents
type QueryMissingEventsResponse struct {
	// Missing events, arbritrary order.
	Events []*gomatrixserverlib.HeaderedEvent `json:"events"`
}

// QueryStateAndAuthChainRequest is a request to QueryStateAndAuthChain
type QueryStateAndAuthChainRequest struct {
	// The room ID to query the state in.
	RoomID string `json:"room_id"`
	// The list of prev events for the event. Used to calculate the state at
	// the event.
	PrevEventIDs []string `json:"prev_event_ids"`
	// The list of auth events for the event. Used to calculate the auth chain
	AuthEventIDs []string `json:"auth_event_ids"`
	// If true, the auth chain events for the auth event IDs given will be fetched only. Prev event IDs are ignored.
	// If false, state and auth chain events for the prev event IDs and entire current state will be included.
	// TODO: not a great API shape. It serves 2 main uses: false=>response for send_join, true=>response for /event_auth
	OnlyFetchAuthChain bool `json:"only_fetch_auth_chain"`
	// Should state resolution be ran on the result events?
	// TODO: check call sites and remove if we always want to do state res
	ResolveState bool `json:"resolve_state"`
}

// QueryStateAndAuthChainResponse is a response to QueryStateAndAuthChain
type QueryStateAndAuthChainResponse struct {
	// Does the room exist on this roomserver?
	// If the room doesn't exist this will be false and StateEvents will be empty.
	RoomExists bool `json:"room_exists"`
	// The room version of the room.
	RoomVersion gomatrixserverlib.RoomVersion `json:"room_version"`
	// Do all the previous events exist on this roomserver?
	// If some of previous events do not exist this will be false and StateEvents will be empty.
	PrevEventsExist bool `json:"prev_events_exist"`
	StateKnown      bool `json:"state_known"`
	// The state and auth chain events that were requested.
	// The lists will be in an arbitrary order.
	StateEvents     []*gomatrixserverlib.HeaderedEvent `json:"state_events"`
	AuthChainEvents []*gomatrixserverlib.HeaderedEvent `json:"auth_chain_events"`
	// True if the queried event was rejected earlier.
	IsRejected bool `json:"is_rejected"`
}

// QueryRoomVersionCapabilitiesRequest asks for the default room version
type QueryRoomVersionCapabilitiesRequest struct{}

// QueryRoomVersionCapabilitiesResponse is a response to QueryRoomVersionCapabilitiesRequest
type QueryRoomVersionCapabilitiesResponse struct {
	DefaultRoomVersion    gomatrixserverlib.RoomVersion            `json:"default"`
	AvailableRoomVersions map[gomatrixserverlib.RoomVersion]string `json:"available"`
}

// QueryRoomVersionForRoomRequest asks for the room version for a given room.
type QueryRoomVersionForRoomRequest struct {
	RoomID string `json:"room_id"`
}

// QueryRoomVersionForRoomResponse is a response to QueryRoomVersionForRoomRequest
type QueryRoomVersionForRoomResponse struct {
	RoomVersion gomatrixserverlib.RoomVersion `json:"room_version"`
}

type QueryPublishedRoomsRequest struct {
	// Optional. If specified, returns whether this room is published or not.
	RoomID             string
	NetworkID          string
	IncludeAllNetworks bool
}

type QueryPublishedRoomsResponse struct {
	// The list of published rooms.
	RoomIDs []string
}

type QueryAuthChainRequest struct {
	EventIDs []string
}

type QueryAuthChainResponse struct {
	AuthChain []*gomatrixserverlib.HeaderedEvent
}

type QuerySharedUsersRequest struct {
	UserID         string
	OtherUserIDs   []string
	ExcludeRoomIDs []string
	IncludeRoomIDs []string
	LocalOnly      bool
}

type QuerySharedUsersResponse struct {
	UserIDsToCount map[string]int
}

type QueryRoomsForUserRequest struct {
	UserID string
	// The desired membership of the user. If this is the empty string then no rooms are returned.
	WantMembership string
}

type QueryRoomsForUserResponse struct {
	RoomIDs []string
}

type QueryBulkStateContentRequest struct {
	// Returns state events in these rooms
	RoomIDs []string
	// If true, treats the '*' StateKey as "all state events of this type" rather than a literal value of '*'
	AllowWildcards bool
	// The state events to return. Only a small subset of tuples are allowed in this request as only certain events
	// have their content fields extracted. Specifically, the tuple Type must be one of:
	//   m.room.avatar
	//   m.room.create
	//   m.room.canonical_alias
	//   m.room.guest_access
	//   m.room.history_visibility
	//   m.room.join_rules
	//   m.room.member
	//   m.room.name
	//   m.room.topic
	// Any other tuple type will result in the query failing.
	StateTuples []gomatrixserverlib.StateKeyTuple
}
type QueryBulkStateContentResponse struct {
	// map of room ID -> tuple -> content_value
	Rooms map[string]map[gomatrixserverlib.StateKeyTuple]string
}

type QueryCurrentStateRequest struct {
	RoomID         string
	AllowWildcards bool
	// State key tuples. If a state_key has '*' and AllowWidlcards is true, returns all matching
	// state events with that event type.
	StateTuples []gomatrixserverlib.StateKeyTuple
}

type QueryCurrentStateResponse struct {
	StateEvents map[gomatrixserverlib.StateKeyTuple]*gomatrixserverlib.HeaderedEvent
}

type QueryKnownUsersRequest struct {
	UserID       string `json:"user_id"`
	SearchString string `json:"search_string"`
	Limit        int    `json:"limit"`
}

type QueryKnownUsersResponse struct {
	Users []authtypes.FullyQualifiedProfile `json:"profiles"`
}

type QueryServerBannedFromRoomRequest struct {
	ServerName gomatrixserverlib.ServerName `json:"server_name"`
	RoomID     string                       `json:"room_id"`
}

type QueryServerBannedFromRoomResponse struct {
	Banned bool `json:"banned"`
}

type QueryRestrictedJoinAllowedRequest struct {
	UserID string `json:"user_id"`
	RoomID string `json:"room_id"`
}

type QueryRestrictedJoinAllowedResponse struct {
	// True if the room membership is restricted by the join rule being set to "restricted"
	Restricted bool `json:"restricted"`
	// True if our local server is joined to all of the allowed rooms specified in the "allow"
	// key of the join rule, false if we are missing from some of them and therefore can't
	// reliably decide whether or not we can satisfy the join
	Resident bool `json:"resident"`
	// True if the restricted join is allowed because we found the membership in one of the
	// allowed rooms from the join rule, false if not
	Allowed bool `json:"allowed"`
	// Contains the user ID of the selected user ID that has power to issue invites, this will
	// get populated into the "join_authorised_via_users_server" content in the membership
	AuthorisedVia string `json:"authorised_via,omitempty"`
}

// MarshalJSON stringifies the room ID and StateKeyTuple keys so they can be sent over the wire in HTTP API mode.
func (r *QueryBulkStateContentResponse) MarshalJSON() ([]byte, error) {
	se := make(map[string]string)
	for roomID, tupleToEvent := range r.Rooms {
		for tuple, event := range tupleToEvent {
			// use 0x1F (unit separator) as the delimiter between room ID/type/state key,
			se[fmt.Sprintf("%s\x1F%s\x1F%s", roomID, tuple.EventType, tuple.StateKey)] = event
		}
	}
	return json.Marshal(se)
}

func (r *QueryBulkStateContentResponse) UnmarshalJSON(data []byte) error {
	wireFormat := make(map[string]string)
	err := json.Unmarshal(data, &wireFormat)
	if err != nil {
		return err
	}
	r.Rooms = make(map[string]map[gomatrixserverlib.StateKeyTuple]string)
	for roomTuple, value := range wireFormat {
		fields := strings.Split(roomTuple, "\x1F")
		roomID := fields[0]
		if r.Rooms[roomID] == nil {
			r.Rooms[roomID] = make(map[gomatrixserverlib.StateKeyTuple]string)
		}
		r.Rooms[roomID][gomatrixserverlib.StateKeyTuple{
			EventType: fields[1],
			StateKey:  fields[2],
		}] = value
	}
	return nil
}

// MarshalJSON stringifies the StateKeyTuple keys so they can be sent over the wire in HTTP API mode.
func (r *QueryCurrentStateResponse) MarshalJSON() ([]byte, error) {
	se := make(map[string]*gomatrixserverlib.HeaderedEvent, len(r.StateEvents))
	for k, v := range r.StateEvents {
		// use 0x1F (unit separator) as the delimiter between type/state key,
		se[fmt.Sprintf("%s\x1F%s", k.EventType, k.StateKey)] = v
	}
	return json.Marshal(se)
}

func (r *QueryCurrentStateResponse) UnmarshalJSON(data []byte) error {
	res := make(map[string]*gomatrixserverlib.HeaderedEvent)
	err := json.Unmarshal(data, &res)
	if err != nil {
		return err
	}
	r.StateEvents = make(map[gomatrixserverlib.StateKeyTuple]*gomatrixserverlib.HeaderedEvent, len(res))
	for k, v := range res {
		fields := strings.Split(k, "\x1F")
		r.StateEvents[gomatrixserverlib.StateKeyTuple{
			EventType: fields[0],
			StateKey:  fields[1],
		}] = v
	}
	return nil
}

// QueryMembershipAtEventRequest requests the membership event for a user
// for a list of eventIDs.
type QueryMembershipAtEventRequest struct {
	RoomID   string
	EventIDs []string
	UserID   string
}

// QueryMembershipAtEventResponse is the response to QueryMembershipAtEventRequest.
type QueryMembershipAtEventResponse struct {
	// Membership is a map from eventID to membership event. Events that
	// do not have known state will return a nil event, resulting in a "leave" membership
	// when calculating history visibility.
	Membership map[string]*gomatrixserverlib.HeaderedEvent `json:"membership"`
}

// QueryLeftUsersRequest is a request to calculate users that we (the server) don't share a
// a room with anymore. This is used to cleanup stale device list entries, where we would
// otherwise keep on trying to get device lists.
type QueryLeftUsersRequest struct {
	StaleDeviceListUsers []string `json:"user_ids"`
}

// QueryLeftUsersResponse is the response to QueryLeftUsersRequest.
type QueryLeftUsersResponse struct {
	LeftUsers []string `json:"user_ids"`
}
