package sync

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	claims "github.com/grafana/authlib/types"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/login/social"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/team"
	"github.com/grafana/grafana/pkg/util"
)

const teamMappingKey = "team_mapping"

func ProvideTeamSync(
	teamService team.Service,
	permissions accesscontrol.TeamPermissionsService,
	socialService social.Service,
	tracer tracing.Tracer,
) *TeamSync {
	return &TeamSync{
		teamService:   teamService,
		permissions:   permissions,
		socialService: socialService,
		log:           log.New("team.sync"),
		tracer:        tracer,
	}
}

type TeamSync struct {
	teamService   team.Service
	permissions   accesscontrol.TeamPermissionsService
	socialService social.Service
	log           log.Logger
	tracer        tracing.Tracer
}

type teamMapping struct {
	group    string
	teamName string
}

// SyncTeamsHook adds and removes team memberships from the external groups
// asserted by the identity provider. It uses the groups already present on the
// identity, so it does not need a separate Graph API credential or sync job.
func (s *TeamSync) SyncTeamsHook(ctx context.Context, id *authn.Identity, r *authn.Request) error {
	ctx, span := s.tracer.Start(ctx, "team.sync.SyncTeamsHook")
	defer span.End()

	if !id.IsIdentityType(claims.TypeUser) {
		return nil
	}

	provider, ok := strings.CutPrefix(id.AuthenticatedBy, "oauth_")
	if !ok || provider != social.AzureADProviderName {
		return nil
	}

	info, err := s.socialService.GetOAuthInfoProvider(ctx, provider)
	if err != nil {
		s.log.FromContext(ctx).Warn("Failed to load OAuth settings for team sync", "provider", provider, "err", err)
		return nil
	}
	if info == nil {
		return nil
	}

	mappings, err := parseTeamMappings(info.Extra[teamMappingKey])
	if err != nil {
		s.log.FromContext(ctx).Error("Invalid team_mapping configuration", "provider", provider, "err", err)
		return nil
	}
	if len(mappings) == 0 {
		return nil
	}

	// Entra ID omits the groups claim when a user exceeds the group limit or
	// when the Graph API fallback fails. An empty list is not evidence that the
	// user left every mapped team, so keep the existing memberships.
	if len(id.ExternalGroups) == 0 {
		s.log.FromContext(ctx).Debug("Skipping team sync because the identity has no external groups")
		return nil
	}

	userID, err := id.GetInternalID()
	if err != nil {
		s.log.FromContext(ctx).Warn("Skipping team sync because the identity has no internal user ID", "id", id.ID, "err", err)
		return nil
	}

	orgID := id.OrgID
	if orgID == 0 && r != nil {
		orgID = r.OrgID
	}
	if orgID == 0 {
		s.log.FromContext(ctx).Warn("Skipping team sync because the identity has no active organization", "id", id.ID)
		return nil
	}

	logger := s.log.FromContext(ctx).New("userID", userID, "orgID", orgID)

	teamNames := mappedTeamNames(mappings, id.ExternalGroups)
	resolvedTeams, allResolved := s.resolveTeams(ctx, logger, orgID, userID, teamNames)

	memberships, err := s.teamService.GetUserTeamMemberships(ctx, orgID, userID, false, true)
	if err != nil {
		logger.Error("Failed to list user team memberships for team sync", "err", err)
		return nil
	}

	existing := make(map[int64]*team.TeamMemberDTO, len(memberships))
	for _, membership := range memberships {
		existing[membership.TeamID] = membership
	}

	desired := make(map[int64]struct{}, len(resolvedTeams))
	for _, name := range teamNames {
		mappedTeam, ok := resolvedTeams[name]
		if !ok {
			continue
		}
		desired[mappedTeam.ID] = struct{}{}

		if _, ok := existing[mappedTeam.ID]; ok {
			continue
		}

		if err := s.setTeamMembership(ctx, orgID, userID, mappedTeam, team.PermissionTypeMember.String()); err != nil {
			logger.Error("Failed to add user to team during team sync", "teamID", mappedTeam.ID, "team", mappedTeam.Name, "err", err)
		}
	}

	if !allResolved {
		logger.Debug("Skipping team membership removal because not all mapped teams could be resolved")
		return nil
	}

	for _, membership := range memberships {
		if !membership.External {
			continue
		}
		if _, ok := desired[membership.TeamID]; ok {
			continue
		}

		if err := s.setTeamMembership(ctx, orgID, userID, &team.TeamDTO{ID: membership.TeamID, Name: membership.TeamUID}, ""); err != nil {
			logger.Error("Failed to remove user from team during team sync", "teamID", membership.TeamID, "err", err)
		}
	}

	return nil
}

func (s *TeamSync) resolveTeams(
	ctx context.Context,
	logger log.Logger,
	orgID, userID int64,
	teamNames []string,
) (map[string]*team.TeamDTO, bool) {
	requester := &identity.StaticRequester{
		Type:   claims.TypeUser,
		UserID: userID,
		OrgID:  orgID,
		Permissions: map[int64]map[string][]string{
			orgID: {accesscontrol.ActionTeamsRead: {"teams:id:*"}},
		},
	}

	resolved := make(map[string]*team.TeamDTO, len(teamNames))
	allResolved := true
	for _, name := range teamNames {
		result, err := s.teamService.SearchTeams(ctx, &team.SearchTeamsQuery{
			OrgID:        orgID,
			Name:         name,
			Limit:        1,
			Page:         1,
			SignedInUser: requester,
		})
		if err != nil {
			logger.Warn("Failed to resolve team for team sync", "team", name, "err", err)
			allResolved = false
			continue
		}
		if len(result.Teams) == 0 {
			logger.Warn("Team mapped in team_mapping does not exist", "team", name)
			allResolved = false
			continue
		}
		if result.Teams[0].ID == 0 {
			logger.Warn("Team mapped in team_mapping has no legacy ID", "team", name)
			allResolved = false
			continue
		}

		resolved[name] = result.Teams[0]
	}

	return resolved, allResolved
}

func (s *TeamSync) setTeamMembership(
	ctx context.Context,
	orgID, userID int64,
	mappedTeam *team.TeamDTO,
	permission string,
) error {
	if mappedTeam.ID == 0 {
		return fmt.Errorf("team %q has no legacy ID", mappedTeam.Name)
	}

	_, err := s.permissions.SetUserPermission(
		ctx,
		orgID,
		accesscontrol.User{ID: userID, IsExternal: true},
		strconv.FormatInt(mappedTeam.ID, 10),
		permission,
	)
	return err
}

func mappedTeamNames(mappings []teamMapping, externalGroups []string) []string {
	groups := make(map[string]struct{}, len(externalGroups))
	for _, group := range externalGroups {
		groups[strings.ToLower(group)] = struct{}{}
	}

	names := make([]string, 0, len(mappings))
	seen := make(map[string]struct{}, len(mappings))
	for _, mapping := range mappings {
		if _, ok := groups[strings.ToLower(mapping.group)]; !ok {
			continue
		}
		if _, ok := seen[mapping.teamName]; ok {
			continue
		}

		seen[mapping.teamName] = struct{}{}
		names = append(names, mapping.teamName)
	}

	slices.Sort(names)
	return names
}

func parseTeamMappings(raw string) ([]teamMapping, error) {
	entries, err := util.SplitStringWithError(raw)
	if err != nil {
		return nil, err
	}

	mappings := make([]teamMapping, 0, len(entries))
	for _, entry := range entries {
		group, teamName, ok := strings.Cut(entry, ":")
		group = strings.TrimSpace(group)
		teamName = strings.TrimSpace(teamName)
		if !ok || group == "" || teamName == "" {
			return nil, fmt.Errorf("invalid entry %q, expected <group-id>:<team-name>", entry)
		}

		mappings = append(mappings, teamMapping{group: group, teamName: teamName})
	}

	return mappings, nil
}
