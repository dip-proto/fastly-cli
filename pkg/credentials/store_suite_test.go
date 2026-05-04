package credentials_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/fastly/cli/pkg/credentials"
)

// runStoreSuite exercises the Store contract against any implementation,
// so backends cannot drift in semantics.
func runStoreSuite(t *testing.T, name string, factory func(t *testing.T) credentials.Store) {
	t.Helper()

	cases := []struct {
		name string
		run  func(t *testing.T, s credentials.Store)
	}{
		{"empty store has no names", testEmptyNames},
		{"empty store has no default", testEmptyDefault},
		{"set then get round-trips static token", testRoundTripStatic},
		{"set then get round-trips sso token", testRoundTripSSO},
		{"set does not implicitly assign default", testSetDoesNotAssignDefault},
		{"metadata returns non-secret view", testMetadataNonSecret},
		{"metadata returns ErrNotFound for missing", testMetadataMissing},
		{"get returns ErrNotFound for missing", testGetMissing},
		{"delete returns ErrNotFound for missing", testDeleteMissing},
		{"delete clears default without reassigning", testDeleteClearsDefault},
		{"delete non-default leaves default intact", testDeleteNonDefault},
		{"setdefault validates membership", testSetDefaultValidates},
		{"setdefault on existing name succeeds", testSetDefaultOnMember},
		{"set is a deep copy", testSetDeepCopy},
		{"get is a deep copy", testGetDeepCopy},
		{"names are sorted", testNamesSorted},
	}

	for _, tc := range cases {
		t.Run(name+"/"+tc.name, func(t *testing.T) {
			t.Parallel()
			s := factory(t)
			tc.run(t, s)
		})
	}
}

func staticToken() *credentials.Token {
	return &credentials.Token{
		Type:      credentials.TypeStatic,
		Token:     "tok_static_123",
		Email:     "user@example.com",
		AccountID: "cust_42",
		Label:     "work",
	}
}

func ssoToken() *credentials.Token {
	return &credentials.Token{
		Type:             credentials.TypeSSO,
		Token:            "tok_sso_api",
		AccessToken:      "access_xyz",
		RefreshToken:     "refresh_xyz",
		AccessExpiresAt:  "2099-01-01T00:00:00Z",
		RefreshExpiresAt: "2099-02-01T00:00:00Z",
		Email:            "sso@example.com",
		AccountID:        "cust_99",
		Label:            "sso (sso@example.com)",
		APITokenName:     "cli",
		APITokenScope:    "global",
		APITokenID:       "tok_id_abc",
	}
}

func testEmptyNames(t *testing.T, s credentials.Store) {
	names, err := s.Names()
	if err != nil {
		t.Fatalf("Names: %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("expected empty Names, got %v", names)
	}
}

func testEmptyDefault(t *testing.T, s credentials.Store) {
	if _, err := s.DefaultName(); !errors.Is(err, credentials.ErrNoDefault) {
		t.Fatalf("DefaultName: expected ErrNoDefault, got %v", err)
	}
	if _, _, err := credentials.GetDefault(s); !errors.Is(err, credentials.ErrNoDefault) {
		t.Fatalf("GetDefault: expected ErrNoDefault, got %v", err)
	}
}

func testRoundTripStatic(t *testing.T, s credentials.Store) {
	want := staticToken()
	if err := s.Set("work", want); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := s.Get("work")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func testRoundTripSSO(t *testing.T, s credentials.Store) {
	want := ssoToken()
	if err := s.Set("sso", want); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := s.Get("sso")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func testSetDoesNotAssignDefault(t *testing.T, s credentials.Store) {
	if err := s.Set("work", staticToken()); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, err := s.DefaultName(); !errors.Is(err, credentials.ErrNoDefault) {
		t.Fatalf("expected no default after Set, got %v", err)
	}
}

func testMetadataNonSecret(t *testing.T, s credentials.Store) {
	if err := s.Set("sso", ssoToken()); err != nil {
		t.Fatalf("Set: %v", err)
	}
	md, err := s.Metadata("sso")
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}

	mdv := reflect.ValueOf(md).Elem()
	mdType := mdv.Type()
	for i := 0; i < mdType.NumField(); i++ {
		switch mdType.Field(i).Name {
		case "Token", "AccessToken", "RefreshToken":
			t.Fatalf("Metadata struct exposes secret field %q", mdType.Field(i).Name)
		}
	}

	if md.Type != credentials.TypeSSO {
		t.Errorf("Metadata.Type = %q, want %q", md.Type, credentials.TypeSSO)
	}
	if md.Email != "sso@example.com" {
		t.Errorf("Metadata.Email = %q", md.Email)
	}
	if md.AccessExpiresAt != "2099-01-01T00:00:00Z" {
		t.Errorf("Metadata.AccessExpiresAt = %q", md.AccessExpiresAt)
	}
	if !md.HasRefreshToken {
		t.Errorf("Metadata.HasRefreshToken = false, want true (sso fixture has refresh token)")
	}
}

func testMetadataMissing(t *testing.T, s credentials.Store) {
	_, err := s.Metadata("absent")
	if !errors.Is(err, credentials.ErrNotFound) {
		t.Fatalf("Metadata: expected ErrNotFound, got %v", err)
	}
}

func testGetMissing(t *testing.T, s credentials.Store) {
	_, err := s.Get("absent")
	if !errors.Is(err, credentials.ErrNotFound) {
		t.Fatalf("Get: expected ErrNotFound, got %v", err)
	}
}

func testDeleteMissing(t *testing.T, s credentials.Store) {
	err := s.Delete("absent")
	if !errors.Is(err, credentials.ErrNotFound) {
		t.Fatalf("Delete: expected ErrNotFound, got %v", err)
	}
}

func testDeleteClearsDefault(t *testing.T, s credentials.Store) {
	if err := s.Set("a", staticToken()); err != nil {
		t.Fatalf("Set a: %v", err)
	}
	if err := s.Set("b", staticToken()); err != nil {
		t.Fatalf("Set b: %v", err)
	}
	if err := s.SetDefault("a"); err != nil {
		t.Fatalf("SetDefault a: %v", err)
	}
	if err := s.Delete("a"); err != nil {
		t.Fatalf("Delete a: %v", err)
	}
	if _, err := s.DefaultName(); !errors.Is(err, credentials.ErrNoDefault) {
		t.Fatalf("expected ErrNoDefault after deleting default, got %v", err)
	}
	names, _ := s.Names()
	if !reflect.DeepEqual(names, []string{"b"}) {
		t.Fatalf("expected [b] after delete, got %v", names)
	}
}

func testDeleteNonDefault(t *testing.T, s credentials.Store) {
	if err := s.Set("a", staticToken()); err != nil {
		t.Fatalf("Set a: %v", err)
	}
	if err := s.Set("b", staticToken()); err != nil {
		t.Fatalf("Set b: %v", err)
	}
	if err := s.SetDefault("a"); err != nil {
		t.Fatalf("SetDefault a: %v", err)
	}
	if err := s.Delete("b"); err != nil {
		t.Fatalf("Delete b: %v", err)
	}
	got, err := s.DefaultName()
	if err != nil {
		t.Fatalf("DefaultName: %v", err)
	}
	if got != "a" {
		t.Fatalf("DefaultName = %q, want %q", got, "a")
	}
}

func testSetDefaultValidates(t *testing.T, s credentials.Store) {
	err := s.SetDefault("absent")
	if !errors.Is(err, credentials.ErrNotFound) {
		t.Fatalf("SetDefault: expected ErrNotFound, got %v", err)
	}
}

func testSetDefaultOnMember(t *testing.T, s credentials.Store) {
	if err := s.Set("a", staticToken()); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.SetDefault("a"); err != nil {
		t.Fatalf("SetDefault: %v", err)
	}
	got, err := s.DefaultName()
	if err != nil {
		t.Fatalf("DefaultName: %v", err)
	}
	if got != "a" {
		t.Fatalf("DefaultName = %q, want %q", got, "a")
	}
}

func testSetDeepCopy(t *testing.T, s credentials.Store) {
	in := staticToken()
	if err := s.Set("a", in); err != nil {
		t.Fatalf("Set: %v", err)
	}
	in.Token = "mutated_after_set"
	got, err := s.Get("a")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Token == "mutated_after_set" {
		t.Fatalf("Set did not deep-copy: caller mutation leaked into store")
	}
}

func testGetDeepCopy(t *testing.T, s credentials.Store) {
	if err := s.Set("a", staticToken()); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got1, err := s.Get("a")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got1.Token = "mutated_after_get"
	got2, err := s.Get("a")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got2.Token == "mutated_after_get" {
		t.Fatalf("Get did not deep-copy: caller mutation leaked back into store")
	}
}

func testNamesSorted(t *testing.T, s credentials.Store) {
	for _, n := range []string{"charlie", "alpha", "bravo"} {
		if err := s.Set(n, staticToken()); err != nil {
			t.Fatalf("Set %s: %v", n, err)
		}
	}
	names, err := s.Names()
	if err != nil {
		t.Fatalf("Names: %v", err)
	}
	want := []string{"alpha", "bravo", "charlie"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("Names = %v, want %v", names, want)
	}
}
