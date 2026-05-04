package credentials_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/fastly/cli/pkg/credentials"
)

const authFixture = `
[auth]
default = "work"

[auth.tokens.work]
type = "static"
token = "tok_work"
email = "dev@example.com"
account_id = "cust_42"

[auth.tokens.personal]
type = "sso"
token = "tok_personal"
access_token = "access_xyz"
refresh_token = "refresh_xyz"
access_expires_at = "2099-01-01T00:00:00Z"
refresh_expires_at = "2099-02-01T00:00:00Z"
`

const profilesFixture = `
[profile.team]
default = true
token = "tok_team"
email = "team@example.com"
customer_id = "cust_team"

[profile.solo]
token = "tok_solo"
email = "solo@example.com"
`

const userFixture = `
[user]
email = "legacy@example.com"
token = "tok_legacy_user"
`

const ssoProfileFixture = `
[profile.sso-acct]
default = true
email = "sso@example.com"
customer_id = "cust_sso"
customer_name = "Acme"
access_token = "atok"
refresh_token = "rtok"
access_token_created = 1700000000
access_token_ttl = 3600
refresh_token_created = 1700000000
refresh_token_ttl = 86400
`

func writeConfig(t *testing.T, dir, contents string) string {
	t.Helper()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestMigrate_AuthSection(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	configPath := writeConfig(t, dir, authFixture)
	credsPath := filepath.Join(dir, "credentials.toml")
	store := credentials.NewFileStore(credsPath)

	migrated, err := credentials.Migrate(configPath, store)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if !migrated {
		t.Fatal("expected migrated=true")
	}

	def, err := store.DefaultName()
	if err != nil {
		t.Fatalf("DefaultName: %v", err)
	}
	if def != "work" {
		t.Fatalf("DefaultName = %q, want %q", def, "work")
	}

	work, err := store.Get("work")
	if err != nil {
		t.Fatalf("Get(work): %v", err)
	}
	if work.Token != "tok_work" || work.Email != "dev@example.com" || work.AccountID != "cust_42" {
		t.Errorf("work token mismatch: %+v", work)
	}

	personal, err := store.Get("personal")
	if err != nil {
		t.Fatalf("Get(personal): %v", err)
	}
	if personal.Type != credentials.TypeSSO || personal.AccessToken != "access_xyz" {
		t.Errorf("personal token mismatch: %+v", personal)
	}
}

func TestMigrate_ProfilesWhenAuthAbsent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	configPath := writeConfig(t, dir, profilesFixture)
	credsPath := filepath.Join(dir, "credentials.toml")
	store := credentials.NewFileStore(credsPath)

	migrated, err := credentials.Migrate(configPath, store)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if !migrated {
		t.Fatal("expected migrated=true")
	}

	def, err := store.DefaultName()
	if err != nil {
		t.Fatalf("DefaultName: %v", err)
	}
	if def != "team" {
		t.Fatalf("DefaultName = %q, want %q", def, "team")
	}

	team, err := store.Get("team")
	if err != nil {
		t.Fatalf("Get(team): %v", err)
	}
	if team.Type != credentials.TypeStatic || team.Token != "tok_team" {
		t.Errorf("team mismatch: %+v", team)
	}
	if team.AccountID != "cust_team" {
		t.Errorf("team.AccountID = %q", team.AccountID)
	}

	solo, err := store.Get("solo")
	if err != nil {
		t.Fatalf("Get(solo): %v", err)
	}
	if solo.Type != credentials.TypeStatic || solo.Token != "tok_solo" {
		t.Errorf("solo mismatch: %+v", solo)
	}
}

func TestMigrate_LegacyUserSection(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	configPath := writeConfig(t, dir, userFixture)
	credsPath := filepath.Join(dir, "credentials.toml")
	store := credentials.NewFileStore(credsPath)

	infoBefore, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	migrated, err := credentials.Migrate(configPath, store)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if !migrated {
		t.Fatal("expected migrated=true")
	}

	def, err := store.DefaultName()
	if err != nil {
		t.Fatalf("DefaultName: %v", err)
	}
	if def != "user" {
		t.Fatalf("DefaultName = %q, want %q", def, "user")
	}

	user, err := store.Get("user")
	if err != nil {
		t.Fatalf("Get(user): %v", err)
	}
	if user.Type != credentials.TypeStatic || user.Token != "tok_legacy_user" {
		t.Errorf("user mismatch: %+v", user)
	}

	infoAfter, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !infoBefore.ModTime().Equal(infoAfter.ModTime()) {
		t.Fatalf("config.toml mtime changed: before=%v after=%v", infoBefore.ModTime(), infoAfter.ModTime())
	}
	if infoBefore.Size() != infoAfter.Size() {
		t.Fatalf("config.toml size changed: before=%d after=%d", infoBefore.Size(), infoAfter.Size())
	}
}

func TestMigrate_PriorityAuthOverProfileOverUser(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	configPath := writeConfig(t, dir, authFixture+profilesFixture+userFixture)
	credsPath := filepath.Join(dir, "credentials.toml")
	store := credentials.NewFileStore(credsPath)

	if _, err := credentials.Migrate(configPath, store); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	names, err := store.Names()
	if err != nil {
		t.Fatalf("Names: %v", err)
	}
	want := []string{"personal", "solo", "team", "user", "work"}
	if len(names) != len(want) {
		t.Fatalf("Names = %v, want %v", names, want)
	}

	def, err := store.DefaultName()
	if err != nil {
		t.Fatalf("DefaultName: %v", err)
	}
	if def != "work" {
		t.Fatalf("DefaultName = %q, want %q (auth.default wins)", def, "work")
	}
}

func TestMigrate_SkipsWhenStoreNonEmpty(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	configPath := writeConfig(t, dir, authFixture)
	credsPath := filepath.Join(dir, "credentials.toml")

	store := credentials.NewFileStore(credsPath)
	if err := store.Set("preexisting", &credentials.Token{
		Type:  credentials.TypeStatic,
		Token: "preexisting-token",
	}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	migrated, err := credentials.Migrate(configPath, store)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if migrated {
		t.Fatal("expected migrated=false when store already has credentials")
	}

	if _, err := store.Get("work"); !errors.Is(err, credentials.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for unmigrated 'work', got %v", err)
	}
}

func TestMigrate_SecondCallIsNoOp(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	configPath := writeConfig(t, dir, authFixture)
	credsPath := filepath.Join(dir, "credentials.toml")
	store := credentials.NewFileStore(credsPath)

	if _, err := credentials.Migrate(configPath, store); err != nil {
		t.Fatalf("first Migrate: %v", err)
	}

	infoBefore, err := os.Stat(credsPath)
	if err != nil {
		t.Fatalf("stat credentials.toml: %v", err)
	}

	migrated, err := credentials.Migrate(configPath, store)
	if err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if migrated {
		t.Fatal("expected migrated=false on second call")
	}

	infoAfter, err := os.Stat(credsPath)
	if err != nil {
		t.Fatalf("stat credentials.toml: %v", err)
	}
	if !infoBefore.ModTime().Equal(infoAfter.ModTime()) {
		t.Fatal("credentials.toml mtime changed on no-op migration")
	}
}

func TestMigrate_FailsLoudlyOnCorruptCredentials(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	configPath := writeConfig(t, dir, authFixture)
	credsPath := filepath.Join(dir, "credentials.toml")

	if err := os.WriteFile(credsPath, []byte("not { valid toml"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	store := credentials.NewFileStore(credsPath)
	_, err := credentials.Migrate(configPath, store)
	if err == nil {
		t.Fatal("expected error from Migrate when credentials.toml is corrupt")
	}
	if !errors.Is(err, credentials.ErrCorrupt) {
		t.Fatalf("expected ErrCorrupt, got %v", err)
	}
}

func TestMigrate_FailsLoudlyOnWidePermsCredentials(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission semantics")
	}
	t.Parallel()
	dir := t.TempDir()
	configPath := writeConfig(t, dir, authFixture)
	credsPath := filepath.Join(dir, "credentials.toml")

	// #nosec G306 -- test deliberately writes wider-than-0600 perms to verify Migrate aborts loudly
	if err := os.WriteFile(credsPath, []byte("default = \"\"\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	store := credentials.NewFileStore(credsPath)
	_, err := credentials.Migrate(configPath, store)
	if err == nil {
		t.Fatal("expected error from Migrate when credentials.toml has wide permissions")
	}
	if !errors.Is(err, credentials.ErrCorrupt) {
		t.Fatalf("expected ErrCorrupt, got %v", err)
	}
}

func TestMigrate_NoConfigIsNoOp(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	credsPath := filepath.Join(dir, "credentials.toml")
	store := credentials.NewFileStore(credsPath)

	migrated, err := credentials.Migrate(configPath, store)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if migrated {
		t.Fatal("expected migrated=false when config.toml is missing")
	}
	if _, err := os.Stat(credsPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("credentials.toml should not have been created")
	}
}

func TestMigrate_UnparseableConfigIsNoOp(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	configPath := writeConfig(t, dir, "not { valid toml")
	credsPath := filepath.Join(dir, "credentials.toml")
	store := credentials.NewFileStore(credsPath)

	migrated, err := credentials.Migrate(configPath, store)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if migrated {
		t.Fatal("expected migrated=false on unparseable config")
	}
}

func TestMigrate_EmptyConfigIsNoOp(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	configPath := writeConfig(t, dir, "")
	credsPath := filepath.Join(dir, "credentials.toml")
	store := credentials.NewFileStore(credsPath)

	migrated, err := credentials.Migrate(configPath, store)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if migrated {
		t.Fatal("expected migrated=false on empty config")
	}
	if _, err := os.Stat(credsPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("credentials.toml should not have been created")
	}
}

func TestMigrate_SSOProfileTranslatesExpiries(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	configPath := writeConfig(t, dir, ssoProfileFixture)
	credsPath := filepath.Join(dir, "credentials.toml")
	store := credentials.NewFileStore(credsPath)

	if _, err := credentials.Migrate(configPath, store); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	tok, err := store.Get("sso-acct")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if tok.Type != credentials.TypeSSO {
		t.Fatalf("Type = %q, want %q", tok.Type, credentials.TypeSSO)
	}

	wantAccess := time.Unix(1700000000, 0).Add(3600 * time.Second).Format(time.RFC3339)
	if tok.AccessExpiresAt != wantAccess {
		t.Errorf("AccessExpiresAt = %q, want %q", tok.AccessExpiresAt, wantAccess)
	}
	wantRefresh := time.Unix(1700000000, 0).Add(86400 * time.Second).Format(time.RFC3339)
	if tok.RefreshExpiresAt != wantRefresh {
		t.Errorf("RefreshExpiresAt = %q, want %q", tok.RefreshExpiresAt, wantRefresh)
	}
	if !tok.NeedsReauth {
		t.Errorf("NeedsReauth = false, want true (refresh expired in 2020)")
	}
	if tok.Label != "Acme (sso@example.com)" {
		t.Errorf("Label = %q", tok.Label)
	}
}

func TestMigrate_DoesNotTouchConfigFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	configPath := writeConfig(t, dir, authFixture+profilesFixture+userFixture)
	originalContents, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	infoBefore, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	credsPath := filepath.Join(dir, "credentials.toml")
	store := credentials.NewFileStore(credsPath)

	if _, err := credentials.Migrate(configPath, store); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	afterContents, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(afterContents) != string(originalContents) {
		t.Fatal("config.toml contents changed during migration")
	}
	infoAfter, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !infoBefore.ModTime().Equal(infoAfter.ModTime()) {
		t.Fatal("config.toml mtime changed during migration")
	}
}
