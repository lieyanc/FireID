package store

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// regApp creates an app owned by the fixture's user with the given policy.
func (f *oidcFixture) regApp(t *testing.T, slug, mode, access string) *App {
	t.Helper()
	a, _, err := f.st.CreateApp(NewApp{Slug: slug, Name: slug, OwnerUserID: f.user.ID,
		RedirectURIs: []string{"https://" + slug + ".example/cb"}, RegistrationMode: mode, DefaultAccess: access})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (f *oidcFixture) newUser(t *testing.T, name string) *User {
	t.Helper()
	u, err := f.st.CreateUser(NewUser{Username: name, Email: name + "@example.com", Status: UserActive})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestCanUseAppMembershipUnderGroups(t *testing.T) {
	f := newOIDCFixture(t)
	app := f.regApp(t, "g", RegInvite, AccessGroups)
	bob := f.newUser(t, "bob")
	check := func(name string, allowed bool, reason string) {
		t.Helper()
		acc, err := f.st.CanUseApp(app, bob)
		if err != nil || acc.Allowed != allowed || acc.Reason != reason || acc.Join != "" {
			t.Fatalf("%s: %+v %v", name, acc, err)
		}
	}
	if err := f.st.SetMembership(app.ID, bob.ID, RoleMember, MemberActive, 0); err != nil {
		t.Fatal(err)
	}
	check("plain member", false, ReasonNotPermitted)
	g, err := f.st.CreateGroup("staff", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.SetAppGroups(app.ID, []int64{g.ID}); err != nil {
		t.Fatal(err)
	}
	if err := f.st.SetUserGroups(bob.ID, []int64{g.ID}); err != nil {
		t.Fatal(err)
	}
	check("member in a granted group", true, ReasonGroup)
	if err := f.st.SetUserGroups(bob.ID, nil); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{RoleAdmin, RoleOwner} {
		if err := f.st.SetMembership(app.ID, bob.ID, role, MemberActive, 0); err != nil {
			t.Fatal(err)
		}
		acc, err := f.st.CanUseApp(app, bob)
		if err != nil || !acc.Allowed || acc.Reason != ReasonMember || acc.Role != role {
			t.Fatalf("%s: %+v %v", role, acc, err)
		}
	}
	// members_only keeps the old meaning: a plain membership allows.
	mo := f.regApp(t, "mo", RegClosed, AccessMembersOnly)
	if err := f.st.SetMembership(mo.ID, bob.ID, RoleMember, MemberActive, 0); err != nil {
		t.Fatal(err)
	}
	if acc, _ := f.st.CanUseApp(mo, bob); !acc.Allowed || acc.Reason != ReasonMember {
		t.Fatalf("members_only member: %+v", acc)
	}
}

func TestCanUseAppJoin(t *testing.T) {
	f := newOIDCFixture(t)
	bob := f.newUser(t, "bob")
	for _, tc := range []struct {
		mode, access string
		allowed      bool
		join         string
	}{
		{RegClosed, AccessMembersOnly, false, ""},
		{RegInvite, AccessMembersOnly, false, ""},
		{RegOpen, AccessMembersOnly, false, JoinSelf},
		{RegAdminApproval, AccessMembersOnly, false, JoinRequest},
		{RegClosed, AccessGroups, false, ""},
		{RegInvite, AccessGroups, false, ""},
		{RegOpen, AccessAllUsers, true, ""},
		{RegAdminApproval, AccessAllUsers, true, ""},
	} {
		app := f.regApp(t, strings.ReplaceAll(tc.mode+"-"+tc.access, "_", "-"), tc.mode, tc.access)
		acc, err := f.st.CanUseApp(app, bob)
		if err != nil || acc.Allowed != tc.allowed || acc.Join != tc.join {
			t.Errorf("%s/%s: %+v %v", tc.mode, tc.access, acc, err)
		}
	}
	// Join is only offered to someone who could act on it.
	open := f.regApp(t, "open", RegOpen, AccessMembersOnly)
	if err := f.st.SetMembership(open.ID, bob.ID, RoleMember, MemberBlocked, 0); err != nil {
		t.Fatal(err)
	}
	if acc, _ := f.st.CanUseApp(open, bob); acc.Reason != ReasonBlocked || acc.Join != "" {
		t.Fatalf("blocked: %+v", acc)
	}
	if err := f.st.SetAppStatus(open.ID, AppSuspended); err != nil {
		t.Fatal(err)
	}
	open, _ = f.st.AppByID(open.ID)
	if acc, _ := f.st.CanUseApp(open, f.newUser(t, "carol")); acc.Reason != ReasonSuspended || acc.Join != "" {
		t.Fatalf("suspended: %+v", acc)
	}
}

func TestGroupsNeedsClosedOrInvite(t *testing.T) {
	f := newOIDCFixture(t)
	for _, mode := range []string{RegOpen, RegAdminApproval} {
		_, _, err := f.st.CreateApp(NewApp{Slug: "x" + mode[:2], Name: "x", OwnerUserID: f.user.ID,
			RedirectURIs: []string{"https://x.example/cb"}, RegistrationMode: mode, DefaultAccess: AccessGroups})
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("create groups/%s: %v", mode, err)
		}
	}
	app := f.regApp(t, "g", RegInvite, AccessGroups)
	open := RegOpen
	if err := f.st.UpdateApp(app.ID, AppUpdate{RegistrationMode: &open}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("update to open under groups: %v", err)
	}
	mo := AccessMembersOnly
	if err := f.st.UpdateApp(app.ID, AppUpdate{RegistrationMode: &open, DefaultAccess: &mo}); err != nil {
		t.Fatalf("open with members_only: %v", err)
	}
}

func TestCatalog(t *testing.T) {
	f := newOIDCFixture(t)
	bob := f.newUser(t, "bob")
	f.regApp(t, "a-open", RegOpen, AccessMembersOnly)
	f.regApp(t, "b-req", RegAdminApproval, AccessMembersOnly)
	f.regApp(t, "c-all", RegClosed, AccessAllUsers)
	f.regApp(t, "d-closed", RegClosed, AccessMembersOnly)
	f.regApp(t, "e-invite", RegInvite, AccessMembersOnly)
	blocked := f.regApp(t, "f-blocked", RegOpen, AccessMembersOnly)
	pending := f.regApp(t, "g-pending", RegAdminApproval, AccessMembersOnly)
	susp := f.regApp(t, "h-susp", RegOpen, AccessAllUsers)
	_ = f.st.SetMembership(blocked.ID, bob.ID, RoleMember, MemberBlocked, 0)
	if _, err := f.st.RequestAppAccess(pending.ID, bob.ID, "hi"); err != nil {
		t.Fatal(err)
	}
	_ = f.st.SetAppStatus(susp.ID, AppSuspended)

	got, err := f.st.Catalog(bob)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"a-open": "available/join", "b-req": "available/request",
		"c-all": "allowed/", "g-pending": "pending/"}
	if len(got) != len(want) {
		t.Fatalf("catalog %d entries, want %d", len(got), len(want))
	}
	for _, e := range got {
		if want[e.App.Slug] != e.State+"/"+e.Join {
			t.Errorf("%s: %s/%s", e.App.Slug, e.State, e.Join)
		}
	}
	// The super admin sees every active app as allowed.
	root, _ := f.st.CreateUser(NewUser{Username: "root", Email: "root@example.com", Status: UserActive,
		IsSuperAdmin: true})
	all, _ := f.st.Catalog(root)
	if len(all) != 8 {
		t.Fatalf("super admin catalog has %d apps", len(all))
	}
	for _, e := range all {
		if e.State != CatalogAllowed {
			t.Fatalf("super admin: %s is %s", e.App.Slug, e.State)
		}
	}
}

func TestJoinAndRequest(t *testing.T) {
	f := newOIDCFixture(t)
	bob := f.newUser(t, "bob")
	open := f.regApp(t, "open", RegOpen, AccessMembersOnly)
	if err := f.st.JoinApp(open.ID, bob.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.st.JoinApp(open.ID, bob.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("second join: %v", err)
	}
	if acc, _ := f.st.CanUseApp(open, bob); !acc.Allowed || acc.Role != RoleMember {
		t.Fatalf("after join: %+v", acc)
	}

	req := f.regApp(t, "req", RegAdminApproval, AccessMembersOnly)
	r1, err := f.st.RequestAppAccess(req.ID, bob.ID, "please")
	if err != nil {
		t.Fatal(err)
	}
	if acc, _ := f.st.CanUseApp(req, bob); acc.Reason != ReasonPending {
		t.Fatalf("after request: %+v", acc)
	}
	if _, err := f.st.RequestAppAccess(req.ID, bob.ID, "again"); !errors.Is(err, ErrConflict) {
		t.Fatalf("second request: %v", err)
	}
	// A denial removes the pending membership, so bob may ask again.
	if _, err := f.st.DecideAccessRequest(req.ID, r1.ID, f.user.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.Membership(req.ID, bob.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("membership after denial: %v", err)
	}
	if acc, _ := f.st.CanUseApp(req, bob); acc.Reason != ReasonNotPermitted || acc.Join != JoinRequest {
		t.Fatalf("after denial: %+v", acc)
	}
	r2, err := f.st.RequestAppAccess(req.ID, bob.ID, "")
	if err != nil {
		t.Fatalf("ask again: %v", err)
	}
	if _, err := f.st.DecideAccessRequest(req.ID, r2.ID, f.user.ID, true); err != nil {
		t.Fatal(err)
	}
	if acc, _ := f.st.CanUseApp(req, bob); !acc.Allowed || acc.Reason != ReasonMember {
		t.Fatalf("after approval: %+v", acc)
	}
	zed := f.newUser(t, "zed")
	if _, err := f.st.RequestAppAccess(req.ID, zed.ID, string(make([]rune, 501))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("long message: %v", err)
	}
	if _, err := f.st.Membership(req.ID, zed.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a refused request left a membership: %v", err)
	}

	// An approval does not lift a block set while the request waited.
	carol := f.newUser(t, "carol")
	r3, _ := f.st.RequestAppAccess(req.ID, carol.ID, "")
	_ = f.st.SetMembership(req.ID, carol.ID, RoleMember, MemberBlocked, f.user.ID)
	if _, err := f.st.DecideAccessRequest(req.ID, r3.ID, f.user.ID, true); err != nil {
		t.Fatal(err)
	}
	if m, _ := f.st.Membership(req.ID, carol.ID); m.Status != MemberBlocked {
		t.Fatalf("block lifted by approval: %+v", m)
	}
	// A denial leaves anything but a pending membership alone.
	dave := f.newUser(t, "dave")
	r4, _ := f.st.RequestAppAccess(req.ID, dave.ID, "")
	_ = f.st.SetMembership(req.ID, dave.ID, RoleMember, MemberBlocked, f.user.ID)
	if _, err := f.st.DecideAccessRequest(req.ID, r4.ID, f.user.ID, false); err != nil {
		t.Fatal(err)
	}
	if m, err := f.st.Membership(req.ID, dave.ID); err != nil || m.Status != MemberBlocked {
		t.Fatalf("block removed by denial: %+v %v", m, err)
	}
}

func TestInvites(t *testing.T) {
	f := newOIDCFixture(t)
	app := f.regApp(t, "inv", RegInvite, AccessMembersOnly)
	bob := f.newUser(t, "bob")
	newInvite := func(email, role string, uses int) (*Invite, string) {
		t.Helper()
		inv, token, err := f.st.CreateInvite(NewInvite{AppID: app.ID, CreatedBy: f.user.ID, Email: email,
			Role: role, TTL: 7 * 24 * time.Hour, MaxUses: uses})
		if err != nil {
			t.Fatal(err)
		}
		return inv, token
	}

	t.Run("validation", func(t *testing.T) {
		for _, in := range []NewInvite{
			{Role: RoleOwner, TTL: time.Hour, MaxUses: 1},
			{Role: RoleMember, TTL: 31 * 24 * time.Hour, MaxUses: 1},
			{Role: RoleMember, TTL: 0, MaxUses: 1},
			{Role: RoleMember, TTL: time.Hour, MaxUses: 0},
			{Role: RoleMember, TTL: time.Hour, MaxUses: 101},
			{Role: RoleMember, TTL: time.Hour, MaxUses: 1, Email: "not-an-address"},
		} {
			in.AppID = app.ID
			if _, _, err := f.st.CreateInvite(in); !errors.Is(err, ErrInvalid) {
				t.Errorf("%+v: %v", in, err)
			}
		}
	})

	t.Run("only the hash is stored and uses are counted", func(t *testing.T) {
		inv, token := newInvite("", RoleMember, 2)
		var stored string
		_ = f.st.db.QueryRow(`SELECT token_hash FROM app_invites WHERE id = ?`, inv.ID).Scan(&stored)
		if stored != HashToken(token) || stored == token {
			t.Fatalf("stored %q", stored)
		}
		if got, err := f.st.AcceptInvite(token, bob); err != nil || got.Uses != 1 {
			t.Fatalf("accept: %+v %v", got, err)
		}
		if acc, _ := f.st.CanUseApp(app, bob); !acc.Allowed || acc.Role != RoleMember {
			t.Fatalf("access: %+v", acc)
		}
		carol := f.newUser(t, "carol")
		if _, err := f.st.AcceptInvite(token, carol); err != nil {
			t.Fatal(err)
		}
		if _, err := f.st.AcceptInvite(token, f.newUser(t, "erin")); !errors.Is(err, ErrNotFound) {
			t.Fatalf("used up: %v", err)
		}
		if _, err := f.st.InviteByToken(token); !errors.Is(err, ErrNotFound) {
			t.Fatalf("lookup used up: %v", err)
		}
	})

	t.Run("expiry and revocation", func(t *testing.T) {
		_, expiring := newInvite("", RoleMember, 1)
		revoked, revokedTok := newInvite("", RoleMember, 1)
		if _, err := f.st.RevokeInvite(app.ID, revoked.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.st.InviteByToken(revokedTok); !errors.Is(err, ErrNotFound) {
			t.Fatalf("revoked: %v", err)
		}
		other := f.regApp(t, "other", RegInvite, AccessMembersOnly)
		if _, err := f.st.RevokeInvite(other.ID, revoked.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("revoked through another app: %v", err)
		}
		f.advance(7*24*time.Hour + time.Second)
		if _, err := f.st.AcceptInvite(expiring, f.newUser(t, "frank")); !errors.Is(err, ErrNotFound) {
			t.Fatalf("expired: %v", err)
		}
		list, err := f.st.ListInvites(app.ID)
		if err != nil || len(list) < 3 || list[0].ID < list[len(list)-1].ID || list[0].Creator == nil {
			t.Fatalf("list: %v %v", list, err)
		}
	})

	t.Run("email, block and no downgrade", func(t *testing.T) {
		_, bound := newInvite("Grace@Example.com", RoleMember, 5)
		if _, err := f.st.AcceptInvite(bound, f.newUser(t, "heidi")); !errors.Is(err, ErrInviteEmailMismatch) {
			t.Fatalf("mismatch: %v", err)
		}
		grace := f.newUser(t, "grace")
		if _, err := f.st.AcceptInvite(bound, grace); err != nil {
			t.Fatalf("matching address: %v", err)
		}
		ivan := f.newUser(t, "ivan")
		_ = f.st.SetMembership(app.ID, ivan.ID, RoleMember, MemberBlocked, 0)
		_, open := newInvite("", RoleAdmin, 5)
		if _, err := f.st.AcceptInvite(open, ivan); !errors.Is(err, ErrMembershipBlocked) {
			t.Fatalf("blocked: %v", err)
		}
		if m, _ := f.st.Membership(app.ID, ivan.ID); m.Status != MemberBlocked {
			t.Fatalf("block lifted: %+v", m)
		}
		// The owner stays owner; a member is promoted to the invite's role.
		if _, err := f.st.AcceptInvite(open, f.user); err != nil {
			t.Fatal(err)
		}
		if m, _ := f.st.Membership(app.ID, f.user.ID); m.Role != RoleOwner {
			t.Fatalf("owner downgraded: %+v", m)
		}
		if _, err := f.st.AcceptInvite(open, grace); err != nil {
			t.Fatal(err)
		}
		if m, _ := f.st.Membership(app.ID, grace.ID); m.Role != RoleAdmin || m.Status != MemberActive {
			t.Fatalf("member not promoted: %+v", m)
		}
		var uses int
		_ = f.st.db.QueryRow(`SELECT uses FROM app_invites WHERE token_hash = ?`, HashToken(open)).Scan(&uses)
		if uses != 2 {
			t.Fatalf("refused accept spent a use: %d", uses)
		}
	})
}

func TestActivationClosesPendingRequest(t *testing.T) {
	f := newOIDCFixture(t)
	app := f.regApp(t, "req", RegAdminApproval, AccessMembersOnly)
	decided := func(name string, u *User, by int64) {
		t.Helper()
		if p, _ := f.st.PendingAccessRequests(app.ID); len(p) != 0 {
			t.Fatalf("%s: %d requests still pending", name, len(p))
		}
		var status string
		var decidedBy int64
		if err := f.st.db.QueryRow(`SELECT status, COALESCE(decided_by, 0) FROM access_requests
			WHERE app_id = ? AND user_id = ?`, app.ID, u.ID).Scan(&status, &decidedBy); err != nil {
			t.Fatal(err)
		}
		if status != "approved" || decidedBy != by {
			t.Fatalf("%s: status %s decided_by %d, want approved by %d", name, status, decidedBy, by)
		}
	}

	bob := f.newUser(t, "bob")
	if _, err := f.st.RequestAppAccess(app.ID, bob.ID, ""); err != nil {
		t.Fatal(err)
	}
	if err := f.st.SetMembership(app.ID, bob.ID, RoleMember, MemberActive, f.user.ID); err != nil {
		t.Fatal(err)
	}
	decided("manager", bob, f.user.ID)

	carol := f.newUser(t, "carol")
	if _, err := f.st.RequestAppAccess(app.ID, carol.ID, ""); err != nil {
		t.Fatal(err)
	}
	inviter := f.newUser(t, "ivan")
	_, token, err := f.st.CreateInvite(NewInvite{AppID: app.ID, CreatedBy: inviter.ID, Role: RoleMember,
		TTL: time.Hour, MaxUses: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.AcceptInvite(token, carol); err != nil {
		t.Fatal(err)
	}
	decided("invite", carol, inviter.ID)

	// Blocking leaves the request for a manager to decide.
	dave := f.newUser(t, "dave")
	if _, err := f.st.RequestAppAccess(app.ID, dave.ID, ""); err != nil {
		t.Fatal(err)
	}
	if err := f.st.SetMembership(app.ID, dave.ID, RoleMember, MemberBlocked, f.user.ID); err != nil {
		t.Fatal(err)
	}
	if p, _ := f.st.PendingAccessRequests(app.ID); len(p) != 1 {
		t.Fatalf("block closed the request: %d pending", len(p))
	}
}
