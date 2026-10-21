package api

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/lieyanc/FireID/internal/forwardauth"
	"github.com/lieyanc/FireID/internal/store"
)

// Admin API: apps, memberships, groups and access requests (DESIGN §8).
//
// Whether a user may manage an app is answered only by store.CanManageApp.
// An app the caller cannot manage answers 404, exactly like an unknown slug, so
// owners cannot probe which slugs exist.

// searchLimit caps the user picker's results.
const searchLimit = 20

// managedApp loads the app named by the {slug} path value and checks that the
// caller may manage it. On false the response has been written.
func (s *Server) managedApp(w http.ResponseWriter, r *http.Request, user *store.User) (*store.App, bool) {
	app, err := s.deps.Store.AppBySlug(r.PathValue("slug"))
	if err != nil {
		s.failFromStore(w, err, "could not load the application")
		return nil, false
	}
	ok, err := s.deps.Store.CanManageApp(user, app)
	if err != nil {
		s.failFromStore(w, err, "could not check permissions")
		return nil, false
	}
	if !ok {
		fail(w, http.StatusNotFound, "not_found", "no such record")
		return nil, false
	}
	return app, true
}

// managesAnyApp is the permissions.manageApps rule: a super admin, or someone
// who manages at least one app.
func (s *Server) managesAnyApp(user *store.User) (bool, error) {
	if user.IsSuperAdmin {
		return true, nil
	}
	apps, err := s.deps.Store.ManagedApps(user)
	if err != nil {
		return false, err
	}
	return len(apps) > 0, nil
}

// requireManager writes 403 unless the caller manages at least one app.
func (s *Server) requireManager(w http.ResponseWriter, user *store.User) bool {
	ok, err := s.managesAnyApp(user)
	if err != nil {
		s.failFromStore(w, err, "could not check permissions")
		return false
	}
	if !ok {
		fail(w, http.StatusForbidden, "forbidden", "you do not manage any applications")
		return false
	}
	return true
}

// canDeleteApp: deleting an app is for the super admin and the app's owner,
// not for app admins.
func canDeleteApp(user *store.User, app *store.App) bool {
	return user.IsSuperAdmin || app.OwnerUserID == user.ID
}

// pathInt is pathID for a path segment not named {id}.
func pathInt(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	if err != nil || id <= 0 {
		fail(w, http.StatusNotFound, "not_found", "no such record")
		return 0, false
	}
	return id, true
}

// noStore keeps a response that carries a secret out of every cache.
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

// ---------------------------------------------------------------------------
// Apps
// ---------------------------------------------------------------------------

// adminApps lists the apps the caller may manage.
func (s *Server) adminApps(w http.ResponseWriter, r *http.Request, user *store.User) {
	apps, err := s.deps.Store.ManagedApps(user)
	if err != nil {
		s.failFromStore(w, err, "could not list applications")
		return
	}
	out := make([]map[string]any, 0, len(apps))
	for _, a := range apps {
		out = append(out, publicApp(a))
	}
	writeJSON(w, http.StatusOK, map[string]any{"apps": out})
}

type createAppRequest struct {
	Slug                   string   `json:"slug"`
	Name                   string   `json:"name"`
	Description            string   `json:"description"`
	HomepageURL            string   `json:"homepageUrl"`
	ClientType             string   `json:"clientType"`
	TEAuthMethod           string   `json:"tokenEndpointAuthMethod"`
	RedirectURIs           []string `json:"redirectUris"`
	PostLogoutRedirectURIs []string `json:"postLogoutRedirectUris"`
	RegistrationMode       string   `json:"registrationMode"`
	DefaultAccess          string   `json:"defaultAccess"`
	OwnerUserID            int64    `json:"ownerUserId"`
}

// adminAppCreate registers an app (super admin only; owners are assigned).
// The client secret is in this response and nowhere else.
func (s *Server) adminAppCreate(w http.ResponseWriter, r *http.Request, user *store.User) {
	var req createAppRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	owner := user.ID
	if req.OwnerUserID != 0 && req.OwnerUserID != user.ID {
		if _, err := s.deps.Store.UserByID(req.OwnerUserID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				fail(w, http.StatusBadRequest, "invalid", "the owner does not exist")
				return
			}
			s.failFromStore(w, err, "could not load the owner")
			return
		}
		owner = req.OwnerUserID
	}
	app, secret, err := s.deps.Store.CreateApp(store.NewApp{
		Slug:                   strings.TrimSpace(req.Slug),
		Name:                   strings.TrimSpace(req.Name),
		Description:            req.Description,
		HomepageURL:            req.HomepageURL,
		ClientType:             req.ClientType,
		TEAuthMethod:           req.TEAuthMethod,
		OwnerUserID:            owner,
		RedirectURIs:           req.RedirectURIs,
		PostLogoutRedirectURIs: req.PostLogoutRedirectURIs,
		RegistrationMode:       req.RegistrationMode,
		DefaultAccess:          req.DefaultAccess,
	})
	if err != nil {
		s.failFromStore(w, err, "could not create the application")
		return
	}
	s.deps.Log.Info("app created", "appId", app.ID, "slug", app.Slug, "ownerUserId", owner, "by", user.ID)
	s.auditAdmin(r, user, "app.create", store.SeverityInfo, app.ID, 0, map[string]any{"slug": app.Slug})
	noStore(w)
	writeJSON(w, http.StatusCreated, map[string]any{"app": publicApp(app), "clientSecret": secret})
}

// adminApp is the detail view: the app, its members, granted groups and
// pending requests.
func (s *Server) adminApp(w http.ResponseWriter, r *http.Request, user *store.User) {
	app, ok := s.managedApp(w, r, user)
	if !ok {
		return
	}
	members, err := s.deps.Store.ListAppMembers(app.ID)
	if err != nil {
		s.failFromStore(w, err, "could not list members")
		return
	}
	groups, err := s.grantedGroups(app.ID)
	if err != nil {
		s.failFromStore(w, err, "could not list groups")
		return
	}
	requests, err := s.deps.Store.PendingAccessRequests(app.ID)
	if err != nil {
		s.failFromStore(w, err, "could not list access requests")
		return
	}
	pending, err := s.deps.Store.PendingBackchannel(app.ID)
	if err != nil {
		s.failFromStore(w, err, "could not count logout notifications")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"app":                publicApp(app),
		"members":            publicMembers(members),
		"groups":             groups,
		"pendingRequests":    publicAccessRequests(requests),
		"canDelete":          canDeleteApp(user, app),
		"backchannelPending": pending,
	})
}

// grantedGroups returns {id, name} for each group granted to the app.
func (s *Server) grantedGroups(appID int64) ([]map[string]any, error) {
	ids, err := s.deps.Store.AppGroupIDs(appID)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	all, err := s.deps.Store.ListGroups()
	if err != nil {
		return nil, err
	}
	names := make(map[int64]string, len(all))
	for _, g := range all {
		names[g.ID] = g.Name
	}
	for _, id := range ids {
		out = append(out, map[string]any{"id": id, "name": names[id]})
	}
	return out, nil
}

type updateAppRequest struct {
	Name                   *string  `json:"name"`
	Description            *string  `json:"description"`
	HomepageURL            *string  `json:"homepageUrl"`
	TEAuthMethod           *string  `json:"tokenEndpointAuthMethod"`
	RedirectURIs           []string `json:"redirectUris"`
	PostLogoutRedirectURIs []string `json:"postLogoutRedirectUris"`
	RegistrationMode       *string  `json:"registrationMode"`
	DefaultAccess          *string  `json:"defaultAccess"`
	// BackchannelLogoutURI is "" to stop logout notifications.
	BackchannelLogoutURI       *string `json:"backchannelLogoutUri"`
	BackchannelSessionRequired *bool   `json:"backchannelLogoutSessionRequired"`
}

// changedFields names, for the audit log, the request fields whose value
// differs from the app's.
func (req *updateAppRequest) changedFields(a *store.App) []string {
	out := []string{}
	text := func(name string, v *string, cur string) {
		if v != nil && strings.TrimSpace(*v) != strings.TrimSpace(cur) {
			out = append(out, name)
		}
	}
	list := func(name string, v, cur []string) {
		if v != nil && !slices.Equal(v, cur) {
			out = append(out, name)
		}
	}
	text("name", req.Name, a.Name)
	text("description", req.Description, a.Description)
	text("homepageUrl", req.HomepageURL, a.HomepageURL)
	text("tokenEndpointAuthMethod", req.TEAuthMethod, a.TEAuthMethod)
	list("redirectUris", req.RedirectURIs, a.RedirectURIs)
	list("postLogoutRedirectUris", req.PostLogoutRedirectURIs, a.PostLogoutRedirectURIs)
	text("registrationMode", req.RegistrationMode, a.RegistrationMode)
	text("defaultAccess", req.DefaultAccess, a.DefaultAccess)
	text("backchannelLogoutUri", req.BackchannelLogoutURI, a.BackchannelLogoutURI)
	if req.BackchannelSessionRequired != nil && *req.BackchannelSessionRequired != a.BackchannelSessionRequired {
		out = append(out, "backchannelLogoutSessionRequired")
	}
	return out
}

// adminAppUpdate applies a partial change; the store validates every field,
// redirect URIs included, against the app's client type.
func (s *Server) adminAppUpdate(w http.ResponseWriter, r *http.Request, user *store.User) {
	app, ok := s.managedApp(w, r, user)
	if !ok {
		return
	}
	var req updateAppRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	err := s.deps.Store.UpdateApp(app.ID, store.AppUpdate{
		Name:             req.Name,
		Description:      req.Description,
		HomepageURL:      req.HomepageURL,
		RegistrationMode: req.RegistrationMode,
		DefaultAccess:    req.DefaultAccess,
		TEAuthMethod:     req.TEAuthMethod,
		RedirectURIs:     req.RedirectURIs,
		PostLogoutURIs:   req.PostLogoutRedirectURIs,

		BackchannelLogoutURI:       req.BackchannelLogoutURI,
		BackchannelSessionRequired: req.BackchannelSessionRequired,
	})
	if err != nil {
		s.failFromStore(w, err, "could not update the application")
		return
	}
	s.deps.Log.Info("app updated", "appId", app.ID, "slug", app.Slug, "by", user.ID)
	if fields := req.changedFields(app); len(fields) > 0 {
		s.auditAdmin(r, user, "app.update", store.SeverityInfo, app.ID, 0, map[string]any{"fields": fields})
	}
	w.WriteHeader(http.StatusNoContent)
}

// adminAppDelete removes an app and everything issued to it.
func (s *Server) adminAppDelete(w http.ResponseWriter, r *http.Request, user *store.User) {
	app, ok := s.managedApp(w, r, user)
	if !ok {
		return
	}
	if !canDeleteApp(user, app) {
		fail(w, http.StatusForbidden, "forbidden", "only the owner or an administrator may delete this application")
		return
	}
	if err := s.deps.Store.DeleteApp(app.ID); err != nil {
		s.failFromStore(w, err, "could not delete the application")
		return
	}
	s.deps.Log.Info("app deleted", "appId", app.ID, "slug", app.Slug, "by", user.ID)
	// The row is gone, so app_id cannot reference it; the detail names it.
	s.auditAdmin(r, user, "app.delete", store.SeverityWarning, 0, 0,
		map[string]any{"appId": app.ID, "slug": app.Slug, "name": app.Name})
	w.WriteHeader(http.StatusNoContent)
}

// adminAppRotateSecret issues a new client secret, shown once.
func (s *Server) adminAppRotateSecret(w http.ResponseWriter, r *http.Request, user *store.User) {
	app, ok := s.managedApp(w, r, user)
	if !ok {
		return
	}
	var req struct{}
	if !decodeJSON(w, r, &req) {
		return
	}
	secret, err := s.deps.Store.RotateAppSecret(app.ID)
	if err != nil {
		s.failFromStore(w, err, "could not rotate the secret")
		return
	}
	s.deps.Log.Info("app secret rotated", "appId", app.ID, "slug", app.Slug, "by", user.ID)
	s.auditAdmin(r, user, "app.secret_rotate", store.SeverityInfo, app.ID, 0, nil)
	noStore(w)
	writeJSON(w, http.StatusOK, map[string]any{"clientSecret": secret})
}

// adminAppStatus activates or suspends an app.
func (s *Server) adminAppStatus(w http.ResponseWriter, r *http.Request, user *store.User) {
	app, ok := s.managedApp(w, r, user)
	if !ok {
		return
	}
	var req struct {
		Status string `json:"status"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.deps.Store.SetAppStatus(app.ID, req.Status); err != nil {
		s.failFromStore(w, err, "could not change the status")
		return
	}
	s.deps.Log.Info("app status changed", "appId", app.ID, "slug", app.Slug, "status", req.Status, "by", user.ID)
	s.auditAdmin(r, user, "app.status", store.SeverityInfo, app.ID, 0, map[string]any{"status": req.Status})
	w.WriteHeader(http.StatusNoContent)
}

// adminAppGroups replaces the groups granted access to an app.
func (s *Server) adminAppGroups(w http.ResponseWriter, r *http.Request, user *store.User) {
	app, ok := s.managedApp(w, r, user)
	if !ok {
		return
	}
	var req struct {
		GroupIDs []int64 `json:"groupIds"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.checkGroupIDs(req.GroupIDs); err != nil {
		s.failFromStore(w, err, "could not grant groups")
		return
	}
	ids := dedupe(req.GroupIDs)
	if err := s.deps.Store.SetAppGroups(app.ID, ids); err != nil {
		s.failFromStore(w, err, "could not grant groups")
		return
	}
	s.deps.Log.Info("app groups replaced", "appId", app.ID, "count", len(ids), "by", user.ID)
	s.auditAdmin(r, user, "app.groups_set", store.SeverityInfo, app.ID, 0, map[string]any{"groupIds": ids})
	w.WriteHeader(http.StatusNoContent)
}

// checkGroupIDs rejects IDs that name no group, so a typo is a 400 rather
// than a foreign-key 500.
func (s *Server) checkGroupIDs(ids []int64) error {
	for _, id := range ids {
		if _, err := s.deps.Store.GroupByID(id); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("%w: group %d not found", store.ErrInvalid, id)
			}
			return err
		}
	}
	return nil
}

func dedupe(ids []int64) []int64 {
	seen := make(map[int64]bool, len(ids))
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Memberships
// ---------------------------------------------------------------------------

// adminAppMembers lists an app's memberships.
func (s *Server) adminAppMembers(w http.ResponseWriter, r *http.Request, user *store.User) {
	app, ok := s.managedApp(w, r, user)
	if !ok {
		return
	}
	members, err := s.deps.Store.ListAppMembers(app.ID)
	if err != nil {
		s.failFromStore(w, err, "could not list members")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": publicMembers(members)})
}

type setMemberRequest struct {
	UserID int64  `json:"userId"`
	Role   string `json:"role"`
	Status string `json:"status"`
}

// adminAppMemberSet adds or updates a membership.
func (s *Server) adminAppMemberSet(w http.ResponseWriter, r *http.Request, user *store.User) {
	app, ok := s.managedApp(w, r, user)
	if !ok {
		return
	}
	var req setMemberRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	switch req.Role {
	case store.RoleOwner, store.RoleAdmin, store.RoleMember:
	default:
		fail(w, http.StatusBadRequest, "invalid", "role must be owner, admin or member")
		return
	}
	switch req.Status {
	case store.MemberActive, store.MemberPending, store.MemberBlocked:
	default:
		fail(w, http.StatusBadRequest, "invalid", "status must be active, pending or blocked")
		return
	}
	if req.Role == store.RoleOwner && !user.IsSuperAdmin {
		fail(w, http.StatusForbidden, "forbidden", "only an administrator may grant the owner role")
		return
	}
	if req.UserID == app.OwnerUserID {
		fail(w, http.StatusBadRequest, "invalid", "the owner's membership cannot be changed")
		return
	}
	member, err := s.deps.Store.UserByID(req.UserID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			fail(w, http.StatusBadRequest, "invalid", "that user does not exist")
			return
		}
		s.failFromStore(w, err, "could not load the user")
		return
	}
	if err := s.deps.Store.SetMembership(app.ID, member.ID, req.Role, req.Status, user.ID); err != nil {
		s.failFromStore(w, err, "could not set the membership")
		return
	}
	m, err := s.deps.Store.Membership(app.ID, member.ID)
	if err != nil {
		s.failFromStore(w, err, "could not load the membership")
		return
	}
	s.deps.Log.Info("membership set", "appId", app.ID, "userId", member.ID,
		"role", req.Role, "status", req.Status, "by", user.ID)
	s.auditAdmin(r, user, "app.member_set", store.SeverityInfo, app.ID, member.ID,
		map[string]any{"role": req.Role, "status": req.Status})
	writeJSON(w, http.StatusCreated, map[string]any{
		"member": publicMember(&store.AppMember{AppMembership: *m, User: member}),
	})
}

// adminAppMemberRemove deletes a membership. The store refuses the owner's.
func (s *Server) adminAppMemberRemove(w http.ResponseWriter, r *http.Request, user *store.User) {
	app, ok := s.managedApp(w, r, user)
	if !ok {
		return
	}
	userID, ok := pathInt(w, r, "userId")
	if !ok {
		return
	}
	if err := s.deps.Store.RemoveMembership(app.ID, userID); err != nil {
		s.failFromStore(w, err, "could not remove the membership")
		return
	}
	s.deps.Log.Info("membership removed", "appId", app.ID, "userId", userID, "by", user.ID)
	s.auditAdmin(r, user, "app.member_remove", store.SeverityInfo, app.ID, userID, nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

// adminGroups lists groups. Owners may read it too: they need the names to
// grant groups to their apps.
func (s *Server) adminGroups(w http.ResponseWriter, r *http.Request, user *store.User) {
	if !s.requireManager(w, user) {
		return
	}
	groups, err := s.deps.Store.ListGroups()
	if err != nil {
		s.failFromStore(w, err, "could not list groups")
		return
	}
	out := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		out = append(out, publicGroup(g))
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": out})
}

type groupRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// adminGroupCreate adds a group (super admin).
func (s *Server) adminGroupCreate(w http.ResponseWriter, r *http.Request, user *store.User) {
	var req groupRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	g, err := s.deps.Store.CreateGroup(req.Name, req.Description)
	if err != nil {
		s.failFromStore(w, err, "could not create the group")
		return
	}
	s.deps.Log.Info("group created", "groupId", g.ID, "by", user.ID)
	s.auditAdmin(r, user, "group.create", store.SeverityInfo, 0, 0, map[string]any{"groupId": g.ID, "name": g.Name})
	writeJSON(w, http.StatusCreated, map[string]any{"group": publicGroup(g)})
}

// adminGroupUpdate renames or redescribes a group (super admin).
func (s *Server) adminGroupUpdate(w http.ResponseWriter, r *http.Request, user *store.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req groupRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.deps.Store.UpdateGroup(id, req.Name, req.Description); err != nil {
		s.failFromStore(w, err, "could not update the group")
		return
	}
	s.deps.Log.Info("group updated", "groupId", id, "by", user.ID)
	s.auditAdmin(r, user, "group.update", store.SeverityInfo, 0, 0,
		map[string]any{"groupId": id, "name": strings.TrimSpace(req.Name)})
	w.WriteHeader(http.StatusNoContent)
}

// adminGroupDelete removes a group (super admin).
func (s *Server) adminGroupDelete(w http.ResponseWriter, r *http.Request, user *store.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	g, ok := s.loadGroup(w, id)
	if !ok {
		return
	}
	if err := s.deps.Store.DeleteGroup(id); err != nil {
		s.failFromStore(w, err, "could not delete the group")
		return
	}
	s.deps.Log.Info("group deleted", "groupId", id, "by", user.ID)
	s.auditAdmin(r, user, "group.delete", store.SeverityInfo, 0, 0, map[string]any{"groupId": id, "name": g.Name})
	w.WriteHeader(http.StatusNoContent)
}

// loadGroup answers 404 for an unknown group ID.
func (s *Server) loadGroup(w http.ResponseWriter, id int64) (*store.Group, bool) {
	g, err := s.deps.Store.GroupByID(id)
	if err != nil {
		s.failFromStore(w, err, "could not load the group")
		return nil, false
	}
	return g, true
}

// adminGroupMembers lists a group's users (super admin).
func (s *Server) adminGroupMembers(w http.ResponseWriter, r *http.Request, user *store.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if _, ok := s.loadGroup(w, id); !ok {
		return
	}
	users, err := s.deps.Store.GroupMembers(id)
	if err != nil {
		s.failFromStore(w, err, "could not list group members")
		return
	}
	out := make([]map[string]any, 0, len(users))
	for _, u := range users {
		out = append(out, publicUser(u))
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

// adminGroupSetMembers replaces a group's members (super admin).
func (s *Server) adminGroupSetMembers(w http.ResponseWriter, r *http.Request, user *store.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		UserIDs []int64 `json:"userIds"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	g, ok := s.loadGroup(w, id)
	if !ok {
		return
	}
	ids := dedupe(req.UserIDs)
	if err := s.deps.Store.SetGroupMembers(id, ids); err != nil {
		s.failFromStore(w, err, "could not set group members")
		return
	}
	s.deps.Log.Info("group members replaced", "groupId", id, "count", len(ids), "by", user.ID)
	s.auditAdmin(r, user, "group.members_set", store.SeverityInfo, 0, 0,
		map[string]any{"groupId": id, "name": g.Name, "count": len(ids)})
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Access requests
// ---------------------------------------------------------------------------

// adminAppAccessRequests lists an app's pending requests.
func (s *Server) adminAppAccessRequests(w http.ResponseWriter, r *http.Request, user *store.User) {
	app, ok := s.managedApp(w, r, user)
	if !ok {
		return
	}
	reqs, err := s.deps.Store.PendingAccessRequests(app.ID)
	if err != nil {
		s.failFromStore(w, err, "could not list access requests")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": publicAccessRequests(reqs)})
}

// adminAccessRequestDecide approves or denies a pending request. The store
// scopes the request to this app, so one app's manager cannot decide
// another's, and tells the requester by email (best effort).
func (s *Server) adminAccessRequestDecide(w http.ResponseWriter, r *http.Request, user *store.User) {
	app, ok := s.managedApp(w, r, user)
	if !ok {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		Approve bool `json:"approve"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	decided, err := s.deps.Store.DecideAccessRequest(app.ID, id, user.ID, req.Approve)
	if err != nil {
		s.failFromStore(w, err, "could not decide the request")
		return
	}
	s.deps.Log.Info("access request decided", "appId", app.ID, "requestId", id,
		"userId", decided.UserID, "approve", req.Approve, "by", user.ID)
	s.auditAdmin(r, user, "app.access_decision", store.SeverityInfo, app.ID, decided.UserID,
		map[string]any{"approved": req.Approve, "requestId": id})
	if requester, err := s.deps.Store.UserByID(decided.UserID); err == nil {
		s.deps.Auth.NotifyAccessDecision(requester, app.Name, req.Approve)
	} else {
		s.deps.Log.Error("could not load the requester for the decision notice",
			"userId", decided.UserID, "err", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// User search
// ---------------------------------------------------------------------------

// adminUsersSearch feeds the add-member picker. Delegation boundary (DESIGN
// §8): only the super admin may browse the directory by prefix; an app
// manager gets at most the one account whose username or email is exactly
// what they typed.
func (s *Server) adminUsersSearch(w http.ResponseWriter, r *http.Request, user *store.User) {
	if !s.requireManager(w, user) {
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	out := []map[string]any{}
	if q == "" {
		writeJSON(w, http.StatusOK, map[string]any{"users": out})
		return
	}
	var users []*store.User
	if user.IsSuperAdmin {
		var err error
		if users, err = s.deps.Store.SearchUsers(q, searchLimit); err != nil {
			s.failFromStore(w, err, "could not search users")
			return
		}
	} else {
		u, err := s.deps.Store.UserByLogin(q)
		switch {
		case err == nil:
			users = []*store.User{u}
		case errors.Is(err, store.ErrNotFound):
		default:
			s.failFromStore(w, err, "could not search users")
			return
		}
	}
	for _, u := range users {
		out = append(out, publicUser(u))
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

// ---------------------------------------------------------------------------
// Forward auth
// ---------------------------------------------------------------------------

// adminAppForwardAuth returns the nginx include for protecting a site with
// this app, and the hosts the app has registered for it.
func (s *Server) adminAppForwardAuth(w http.ResponseWriter, r *http.Request, user *store.User) {
	app, ok := s.managedApp(w, r, user)
	if !ok {
		return
	}
	hosts := []string{}
	for _, uri := range app.RedirectURIs {
		if origin, found := strings.CutSuffix(uri, forwardauth.CallbackPath); found {
			hosts = append(hosts, origin)
		}
	}
	srv := s.deps.Config.Get().Server
	host := srv.Host
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	upstream := "http://" + net.JoinHostPort(host, strconv.Itoa(srv.Port))
	writeJSON(w, http.StatusOK, map[string]any{
		"callbackPath":    forwardauth.CallbackPath,
		"hosts":           hosts,
		"serverSnippet":   forwardauth.NginxServerSnippet(app.Slug, upstream),
		"locationSnippet": forwardauth.NginxLocationSnippet(),
	})
}

// ---------------------------------------------------------------------------
// Response shapes
// ---------------------------------------------------------------------------

// publicApp is an app as the admin UI sees it. The secret hash never appears;
// lists are never null.
func publicApp(a *store.App) map[string]any {
	return map[string]any{
		"id":                               a.ID,
		"slug":                             a.Slug,
		"name":                             a.Name,
		"description":                      a.Description,
		"homepageUrl":                      a.HomepageURL,
		"clientId":                         a.ClientID,
		"clientType":                       a.ClientType,
		"tokenEndpointAuthMethod":          a.TEAuthMethod,
		"requirePkce":                      a.RequirePKCE,
		"ownerUserId":                      a.OwnerUserID,
		"status":                           a.Status,
		"registrationMode":                 a.RegistrationMode,
		"defaultAccess":                    a.DefaultAccess,
		"redirectUris":                     nonNil(a.RedirectURIs),
		"postLogoutRedirectUris":           nonNil(a.PostLogoutRedirectURIs),
		"scopes":                           nonNil(a.Scopes),
		"grantTypes":                       nonNil(a.GrantTypes),
		"backchannelLogoutUri":             a.BackchannelLogoutURI,
		"backchannelLogoutSessionRequired": a.BackchannelSessionRequired,
		"secretRotatedAt":                  timeText(a.SecretRotated),
		"createdAt":                        timeText(a.CreatedAt),
		"updatedAt":                        timeText(a.UpdatedAt),
	}
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func publicMember(m *store.AppMember) map[string]any {
	return map[string]any{
		"user":      publicUser(m.User),
		"role":      m.Role,
		"status":    m.Status,
		"createdAt": timeText(m.CreatedAt),
	}
}

func publicMembers(ms []*store.AppMember) []map[string]any {
	out := make([]map[string]any, 0, len(ms))
	for _, m := range ms {
		out = append(out, publicMember(m))
	}
	return out
}

func publicGroup(g *store.Group) map[string]any {
	return map[string]any{
		"id":          g.ID,
		"name":        g.Name,
		"description": g.Description,
		"memberCount": g.MemberCount,
		"createdAt":   timeText(g.CreatedAt),
	}
}

func publicAccessRequests(rs []*store.AccessRequestDetail) []map[string]any {
	out := make([]map[string]any, 0, len(rs))
	for _, r := range rs {
		out = append(out, map[string]any{
			"id":        r.ID,
			"user":      publicUser(r.User),
			"message":   r.Message,
			"createdAt": timeText(r.CreatedAt),
		})
	}
	return out
}
