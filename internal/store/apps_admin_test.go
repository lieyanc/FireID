package store

import (
	"errors"
	"testing"
)

func TestValidateSlug(t *testing.T) {
	for _, ok := range []string{"rp", "app-a", "x1", "a"} {
		if err := ValidateSlug(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "-a", "a-", "A", "a_b", "a b", "ä", string(make([]byte, 64))} {
		if err := ValidateSlug(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestDecideAccessRequest(t *testing.T) {
	f := newOIDCFixture(t)
	bob, err := f.st.CreateUser(NewUser{Username: "bob", Email: "bob@example.com", Status: UserActive})
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := f.st.CreateApp(NewApp{Slug: "other", Name: "Other", OwnerUserID: f.user.ID,
		RedirectURIs: []string{"https://other.example/cb"}})
	if err != nil {
		t.Fatal(err)
	}
	req, err := f.st.CreateAccessRequest(f.app.ID, bob.ID, "please")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.CreateAccessRequest(f.app.ID, bob.ID, "again"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate pending: %v", err)
	}
	pending, err := f.st.PendingAccessRequests(f.app.ID)
	if err != nil || len(pending) != 1 || pending[0].User.Username != "bob" || pending[0].Message != "please" {
		t.Fatalf("pending: %+v %v", pending, err)
	}
	if _, err := f.st.DecideAccessRequest(other.ID, req.ID, f.user.ID, true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("decided through another app: %v", err)
	}
	got, err := f.st.DecideAccessRequest(f.app.ID, req.ID, f.user.ID, true)
	if err != nil || got.Status != "approved" || got.UserID != bob.ID {
		t.Fatalf("approve: %+v %v", got, err)
	}
	if _, err := f.st.DecideAccessRequest(f.app.ID, req.ID, f.user.ID, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("second decision: %v", err)
	}
	acc, err := f.st.CanUseApp(f.app, bob)
	if err != nil || !acc.Allowed || acc.Reason != "member" {
		t.Fatalf("access after approval: %+v %v", acc, err)
	}
	if n, _ := f.st.PendingAccessRequests(f.app.ID); len(n) != 0 {
		t.Fatalf("still pending: %d", len(n))
	}
}

func TestManageAppAndMembers(t *testing.T) {
	f := newOIDCFixture(t)
	bob, _ := f.st.CreateUser(NewUser{Username: "bob", Email: "bob@example.com", Status: UserActive})
	if ok, _ := f.st.CanManageApp(f.user, f.app); !ok {
		t.Fatal("owner cannot manage")
	}
	if ok, _ := f.st.CanManageApp(bob, f.app); ok {
		t.Fatal("stranger can manage")
	}
	if err := f.st.SetMembership(f.app.ID, bob.ID, RoleAdmin, MemberActive, f.user.ID); err != nil {
		t.Fatal(err)
	}
	if ok, _ := f.st.CanManageApp(bob, f.app); !ok {
		t.Fatal("app admin cannot manage")
	}
	apps, err := f.st.ManagedApps(bob)
	if err != nil || len(apps) != 1 || apps[0].ID != f.app.ID {
		t.Fatalf("managed apps: %v %v", apps, err)
	}
	members, err := f.st.ListAppMembers(f.app.ID)
	if err != nil || len(members) != 2 || members[0].User.ID != f.user.ID || members[0].Role != RoleOwner {
		t.Fatalf("members: %+v %v", members, err)
	}
	if err := f.st.RemoveMembership(f.app.ID, f.user.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("removed the owner: %v", err)
	}
	if err := f.st.RemoveMembership(f.app.ID, bob.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.st.RemoveMembership(f.app.ID, bob.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second removal: %v", err)
	}
}

func TestUpdateApp(t *testing.T) {
	f := newOIDCFixture(t)
	name, mode, bad := "Renamed", RegOpen, "nope"
	if err := f.st.UpdateApp(f.app.ID, AppUpdate{Name: &name, RegistrationMode: &mode,
		RedirectURIs: []string{"https://rp.example/new", "https://rp.example/new"}}); err != nil {
		t.Fatal(err)
	}
	a, err := f.st.AppByID(f.app.ID)
	if err != nil || a.Name != "Renamed" || a.RegistrationMode != RegOpen ||
		len(a.RedirectURIs) != 1 || a.RedirectURIs[0] != "https://rp.example/new" {
		t.Fatalf("after update: %+v %v", a, err)
	}
	if err := f.st.UpdateApp(f.app.ID, AppUpdate{DefaultAccess: &bad}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad default access: %v", err)
	}
	none := AuthNone
	if err := f.st.UpdateApp(f.app.ID, AppUpdate{TEAuthMethod: &none}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("none on a confidential client: %v", err)
	}
	if err := f.st.UpdateApp(f.app.ID, AppUpdate{RedirectURIs: []string{}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty redirect list: %v", err)
	}
	if err := f.st.UpdateApp(f.app.ID, AppUpdate{RedirectURIs: []string{"http://evil.example/cb"}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("http redirect: %v", err)
	}
	if err := f.st.DeleteApp(f.app.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.AppByID(f.app.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
}

func TestGroupsAndSearch(t *testing.T) {
	f := newOIDCFixture(t)
	bob, _ := f.st.CreateUser(NewUser{Username: "bob_x", Email: "bob@example.com", Status: UserActive})
	_, _ = f.st.CreateUser(NewUser{Username: "bobyx", Email: "bobyx@example.com", Status: UserActive})
	g, err := f.st.CreateGroup("friends", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.SetGroupMembers(g.ID, []int64{bob.ID}); err != nil {
		t.Fatal(err)
	}
	if err := f.st.SetGroupMembers(g.ID, []int64{9999}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown user: %v", err)
	}
	if err := f.st.SetAppGroups(f.app.ID, []int64{g.ID}); err != nil {
		t.Fatal(err)
	}
	acc, _ := f.st.CanUseApp(f.app, bob)
	if !acc.Allowed || acc.Reason != "group" {
		t.Fatalf("group access: %+v", acc)
	}
	if ids, _ := f.st.AppGroupIDs(f.app.ID); len(ids) != 1 || ids[0] != g.ID {
		t.Fatalf("app groups: %v", ids)
	}
	if users, _ := f.st.GroupMembers(g.ID); len(users) != 1 || users[0].ID != bob.ID {
		t.Fatalf("group members: %v", users)
	}
	if err := f.st.DeleteGroup(g.ID); err != nil {
		t.Fatal(err)
	}
	if ids, _ := f.st.AppGroupIDs(f.app.ID); len(ids) != 0 {
		t.Fatalf("grant survived group deletion: %v", ids)
	}
	got, err := f.st.SearchUsers("bob_", 10)
	if err != nil || len(got) != 1 || got[0].ID != bob.ID {
		t.Fatalf("search escapes _: %v %v", got, err)
	}
	if u, err := f.st.UserByLogin("bob@example.com"); err != nil || u.ID != bob.ID {
		t.Fatalf("by login: %v %v", u, err)
	}
}
