package sync

import (
	"context"
	"errors"
	"testing"

	claims "github.com/grafana/authlib/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/login/social"
	"github.com/grafana/grafana/pkg/login/social/socialtest"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/team"
	"github.com/grafana/grafana/pkg/services/team/teamtest"
)

func TestTeamSync_SyncTeamsHook(t *testing.T) {
	const (
		engineeringGroup = "11111111-1111-1111-1111-111111111111"
		platformGroup    = "22222222-2222-2222-2222-222222222222"
	)

	tests := []struct {
		name               string
		mapping            string
		authenticatedBy    string
		groups             []string
		teams              []*team.TeamDTO
		memberships        []*team.TeamMemberDTO
		searchErr          error
		permissionErr      error
		expectedPermission map[string]string
	}{
		{
			name:            "adds mapped teams and removes stale external memberships",
			mapping:         engineeringGroup + ":Engineering " + platformGroup + ":Platform",
			authenticatedBy: "oauth_azuread",
			groups:          []string{engineeringGroup, platformGroup},
			teams: []*team.TeamDTO{
				{ID: 11, UID: "engineering", Name: "Engineering"},
				{ID: 22, UID: "platform", Name: "Platform"},
			},
			memberships: []*team.TeamMemberDTO{
				{TeamID: 33, TeamUID: "old-team", External: true},
				{TeamID: 44, TeamUID: "manual-team"},
			},
			expectedPermission: map[string]string{
				"11": "Member",
				"22": "Member",
				"33": "",
			},
		},
		{
			name:            "keeps existing memberships without rewriting them",
			mapping:         engineeringGroup + ":Engineering",
			authenticatedBy: "oauth_azuread",
			groups:          []string{engineeringGroup},
			teams:           []*team.TeamDTO{{ID: 11, UID: "engineering", Name: "Engineering"}},
			memberships: []*team.TeamMemberDTO{
				{TeamID: 11, TeamUID: "engineering", External: true, Permission: team.PermissionTypeAdmin},
				{TeamID: 33, TeamUID: "old-team", External: true},
			},
			expectedPermission: map[string]string{
				"33": "",
			},
		},
		{
			name:            "removes stale external memberships when no supplied groups match",
			mapping:         engineeringGroup + ":Engineering",
			authenticatedBy: "oauth_azuread",
			groups:          []string{platformGroup},
			memberships: []*team.TeamMemberDTO{
				{TeamID: 11, TeamUID: "engineering", External: true},
				{TeamID: 44, TeamUID: "manual-team"},
			},
			expectedPermission: map[string]string{"11": ""},
		},
		{
			name:            "does not take ownership of manual membership in a mapped team",
			mapping:         engineeringGroup + ":Engineering",
			authenticatedBy: "oauth_azuread",
			groups:          []string{engineeringGroup},
			teams:           []*team.TeamDTO{{ID: 11, UID: "engineering", Name: "Engineering"}},
			memberships: []*team.TeamMemberDTO{
				{TeamID: 11, TeamUID: "engineering", Permission: team.PermissionTypeAdmin},
			},
			expectedPermission: map[string]string{},
		},
		{
			name:            "membership write failures do not block login or remaining sync operations",
			mapping:         engineeringGroup + ":Engineering " + platformGroup + ":Platform",
			authenticatedBy: "oauth_azuread",
			groups:          []string{engineeringGroup, platformGroup},
			teams: []*team.TeamDTO{
				{ID: 11, UID: "engineering", Name: "Engineering"},
				{ID: 22, UID: "platform", Name: "Platform"},
			},
			memberships: []*team.TeamMemberDTO{
				{TeamID: 33, TeamUID: "old-team", External: true},
			},
			permissionErr: errors.New("membership write failed"),
			expectedPermission: map[string]string{
				"11": "Member",
				"22": "Member",
				"33": "",
			},
		},
		{
			name:            "skips removal when the identity has no external groups",
			mapping:         engineeringGroup + ":Engineering",
			authenticatedBy: "oauth_azuread",
			groups:          nil,
			teams:           []*team.TeamDTO{{ID: 11, UID: "engineering", Name: "Engineering"}},
			memberships: []*team.TeamMemberDTO{
				{TeamID: 33, TeamUID: "old-team", External: true},
			},
			expectedPermission: map[string]string{},
		},
		{
			name:            "skips removal when a mapped team cannot be resolved",
			mapping:         engineeringGroup + ":Missing",
			authenticatedBy: "oauth_azuread",
			groups:          []string{engineeringGroup},
			memberships: []*team.TeamMemberDTO{
				{TeamID: 33, TeamUID: "old-team", External: true},
			},
			expectedPermission: map[string]string{},
		},
		{
			name:               "does nothing without a team mapping",
			mapping:            "",
			authenticatedBy:    "oauth_azuread",
			groups:             []string{engineeringGroup},
			expectedPermission: map[string]string{},
		},
		{
			name:               "ignores non-OAuth identities",
			mapping:            engineeringGroup + ":Engineering",
			authenticatedBy:    "ldap",
			groups:             []string{engineeringGroup},
			expectedPermission: map[string]string{},
		},
		{
			name:               "ignores other OAuth providers",
			mapping:            engineeringGroup + ":Engineering",
			authenticatedBy:    "oauth_generic_oauth",
			groups:             []string{engineeringGroup},
			expectedPermission: map[string]string{},
		},
		{
			name:            "maps multiple groups to one team once",
			mapping:         engineeringGroup + ":Engineering " + platformGroup + ":Engineering",
			authenticatedBy: "oauth_azuread",
			groups:          []string{engineeringGroup, platformGroup},
			teams:           []*team.TeamDTO{{ID: 11, UID: "engineering", Name: "Engineering"}},
			expectedPermission: map[string]string{
				"11": "Member",
			},
		},
		{
			name:               "treats a malformed mapping as a configuration error",
			mapping:            engineeringGroup,
			authenticatedBy:    "oauth_azuread",
			groups:             []string{engineeringGroup},
			expectedPermission: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			teamService := &fakeTeamService{
				FakeService: teamtest.NewFakeService(),
				teams:       tt.teams,
				memberships: tt.memberships,
				searchErr:   tt.searchErr,
			}
			permissions := &fakeTeamPermissions{err: tt.permissionErr}
			socialService := &socialtest.FakeSocialService{
				ExpectedAuthInfoProvider: &social.OAuthInfo{
					Extra: map[string]string{teamMappingKey: tt.mapping},
				},
			}

			hook := ProvideTeamSync(teamService, permissions, socialService, tracing.InitializeTracerForTest())
			id := &authn.Identity{
				ID:              "7",
				Type:            claims.TypeUser,
				OrgID:           1,
				AuthenticatedBy: tt.authenticatedBy,
				ExternalGroups:  tt.groups,
			}

			err := hook.SyncTeamsHook(context.Background(), id, &authn.Request{OrgID: 1})
			require.NoError(t, err)
			assert.Equal(t, tt.expectedPermission, permissions.callsByTeam())
			assert.Len(t, permissions.calls, len(tt.expectedPermission), "each team must be updated at most once")
			for _, call := range permissions.calls {
				assert.True(t, call.user.IsExternal, "team sync must mark memberships as externally managed")
			}
		})
	}
}

func TestTeamSync_SyncTeamsHookSkipsWhenTeamLookupFails(t *testing.T) {
	teamService := &fakeTeamService{
		FakeService: teamtest.NewFakeService(),
		searchErr:   errors.New("search failed"),
	}
	permissions := &fakeTeamPermissions{}
	socialService := &socialtest.FakeSocialService{
		ExpectedAuthInfoProvider: &social.OAuthInfo{
			Extra: map[string]string{teamMappingKey: "group-a:Engineering"},
		},
	}

	hook := ProvideTeamSync(teamService, permissions, socialService, tracing.InitializeTracerForTest())
	err := hook.SyncTeamsHook(context.Background(), &authn.Identity{
		ID:              "7",
		Type:            claims.TypeUser,
		OrgID:           1,
		AuthenticatedBy: "oauth_azuread",
		ExternalGroups:  []string{"group-a"},
	}, &authn.Request{OrgID: 1})

	require.NoError(t, err)
	assert.Empty(t, permissions.calls)
}

func TestTeamSync_SyncTeamsHookSkipsWhenMembershipLookupFails(t *testing.T) {
	teamService := &fakeTeamService{
		FakeService: teamtest.NewFakeService(),
		teams:       []*team.TeamDTO{{ID: 11, UID: "engineering", Name: "Engineering"}},
		membersErr:  errors.New("lookup failed"),
	}
	permissions := &fakeTeamPermissions{}
	socialService := &socialtest.FakeSocialService{
		ExpectedAuthInfoProvider: &social.OAuthInfo{
			Extra: map[string]string{teamMappingKey: "group-a:Engineering"},
		},
	}

	hook := ProvideTeamSync(teamService, permissions, socialService, tracing.InitializeTracerForTest())
	err := hook.SyncTeamsHook(context.Background(), &authn.Identity{
		ID:              "7",
		Type:            claims.TypeUser,
		OrgID:           1,
		AuthenticatedBy: "oauth_azuread",
		ExternalGroups:  []string{"group-a"},
	}, &authn.Request{OrgID: 1})

	require.NoError(t, err)
	assert.Empty(t, permissions.calls)
}

func TestParseTeamMappings(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		expected []teamMapping
		wantErr  bool
	}{
		{
			name:     "empty",
			raw:      "",
			expected: []teamMapping{},
		},
		{
			name: "space and comma separated",
			raw:  "group-a:Engineering, group-b:Platform",
			expected: []teamMapping{
				{group: "group-a", teamName: "Engineering"},
				{group: "group-b", teamName: "Platform"},
			},
		},
		{
			name:     "quoted entry with team name containing spaces",
			raw:      `"group-a:Engineering Team"`,
			expected: []teamMapping{{group: "group-a", teamName: "Engineering Team"}},
		},
		{
			name:     "JSON list",
			raw:      `["group-a:Engineering", "group-b:Platform"]`,
			expected: []teamMapping{{group: "group-a", teamName: "Engineering"}, {group: "group-b", teamName: "Platform"}},
		},
		{
			name:    "missing team name",
			raw:     "group-a:",
			wantErr: true,
		},
		{
			name:    "missing separator",
			raw:     "group-a",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mappings, err := parseTeamMappings(tt.raw)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, mappings)
		})
	}
}

type fakeTeamService struct {
	*teamtest.FakeService
	teams       []*team.TeamDTO
	memberships []*team.TeamMemberDTO
	searchErr   error
	membersErr  error
}

func (f *fakeTeamService) SearchTeams(_ context.Context, query *team.SearchTeamsQuery) (team.SearchTeamQueryResult, error) {
	if f.searchErr != nil {
		return team.SearchTeamQueryResult{}, f.searchErr
	}

	teams := make([]*team.TeamDTO, 0, 1)
	for _, candidate := range f.teams {
		if candidate.Name == query.Name {
			teams = append(teams, candidate)
			break
		}
	}

	return team.SearchTeamQueryResult{Teams: teams}, nil
}

func (f *fakeTeamService) GetUserTeamMemberships(_ context.Context, _, _ int64, _ bool, _ bool) ([]*team.TeamMemberDTO, error) {
	return f.memberships, f.membersErr
}

type permissionCall struct {
	user       accesscontrol.User
	resourceID string
	permission string
}

type fakeTeamPermissions struct {
	calls []permissionCall
	err   error
}

func (f *fakeTeamPermissions) GetPermissions(context.Context, identity.Requester, string) ([]accesscontrol.ResourcePermission, error) {
	return nil, nil
}

func (f *fakeTeamPermissions) SetUserPermission(_ context.Context, _ int64, user accesscontrol.User, resourceID, permission string) (*accesscontrol.ResourcePermission, error) {
	f.calls = append(f.calls, permissionCall{
		user:       user,
		resourceID: resourceID,
		permission: permission,
	})
	return nil, f.err
}

func (f *fakeTeamPermissions) SetPermissions(context.Context, int64, string, ...accesscontrol.SetResourcePermissionCommand) ([]accesscontrol.ResourcePermission, error) {
	return nil, nil
}

func (f *fakeTeamPermissions) callsByTeam() map[string]string {
	result := make(map[string]string, len(f.calls))
	for _, call := range f.calls {
		result[call.resourceID] = call.permission
	}
	return result
}
