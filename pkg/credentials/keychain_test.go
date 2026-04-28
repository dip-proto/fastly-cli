package credentials_test

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/fastly/cli/pkg/credentials"
	"github.com/zalando/go-keyring"
)

// fakeKeyring is an in-memory keyringClient that records every call,
// so tests can assert the no-prompt invariant (Names / Metadata /
// DefaultName never contact the keychain).
type fakeKeyring struct {
	mu      sync.Mutex
	entries map[string]string
	gets    int
	sets    int
	deletes int
}

func newFakeKeyring() *fakeKeyring {
	return &fakeKeyring{entries: map[string]string{}}
}

func (f *fakeKeyring) key(service, user string) string {
	return service + "\x00" + user
}

func (f *fakeKeyring) Set(service, user, secret string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sets++
	f.entries[f.key(service, user)] = secret
	return nil
}

func (f *fakeKeyring) Get(service, user string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets++
	v, ok := f.entries[f.key(service, user)]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return v, nil
}

func (f *fakeKeyring) Delete(service, user string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes++
	key := f.key(service, user)
	if _, ok := f.entries[key]; !ok {
		return keyring.ErrNotFound
	}
	delete(f.entries, key)
	return nil
}

// panickingKeyring fails any keychain access. KeychainStore is
// supposed to satisfy Names / Metadata / DefaultName without
// touching the keychain at all; wiring this client into those tests
// proves the no-prompt invariant is real.
type panickingKeyring struct{}

func (panickingKeyring) Set(string, string, string) error {
	panic("panickingKeyring.Set must not be called")
}

func (panickingKeyring) Get(string, string) (string, error) {
	panic("panickingKeyring.Get must not be called")
}

func (panickingKeyring) Delete(string, string) error {
	panic("panickingKeyring.Delete must not be called")
}

func keychainStoreFactory(t *testing.T) credentials.Store {
	t.Helper()
	dir := t.TempDir()
	return credentials.NewKeychainStoreForTest(filepath.Join(dir, "credentials.keychain.toml"), newFakeKeyring())
}

func TestKeychainStore(t *testing.T) {
	t.Parallel()
	runStoreSuite(t, "keychain", keychainStoreFactory)
}

// TestKeychainNamesMetadataDoesNotProbeKeychain proves the
// no-prompt invariant: Names, Metadata, and DefaultName are answered
// from the sidecar alone, even when the keychain client would panic
// on any access.
func TestKeychainNamesMetadataDoesNotProbeKeychain(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	side := filepath.Join(dir, "credentials.keychain.toml")
	fake := newFakeKeyring()
	seedStore := credentials.NewKeychainStoreForTest(side, fake)
	if err := seedStore.Set("a", &credentials.Token{Type: credentials.TypeStatic, Token: "x"}); err != nil {
		t.Fatalf("seed Set: %v", err)
	}
	if err := seedStore.Set("b", &credentials.Token{Type: credentials.TypeStatic, Token: "y"}); err != nil {
		t.Fatalf("seed Set: %v", err)
	}
	if err := seedStore.SetDefault("a"); err != nil {
		t.Fatalf("seed SetDefault: %v", err)
	}

	probe := credentials.NewKeychainStoreForTest(side, panickingKeyring{})

	names, err := probe.Names()
	if err != nil {
		t.Fatalf("Names: %v", err)
	}
	if len(names) != 2 || names[0] != "a" || names[1] != "b" {
		t.Fatalf("Names = %v, want [a b]", names)
	}

	if _, err := probe.Metadata("a"); err != nil {
		t.Fatalf("Metadata(a): %v", err)
	}
	if _, err := probe.DefaultName(); err != nil {
		t.Fatalf("DefaultName: %v", err)
	}
}

// TestKeychainGetCorruptOnMissingSecret covers drift case 1: the
// sidecar lists a credential but the keychain has no token entry.
// Get must return ErrCorrupt with a remediation message rather than
// silently producing a zero-valued Token.
func TestKeychainGetCorruptOnMissingSecret(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	side := filepath.Join(dir, "credentials.keychain.toml")
	fake := newFakeKeyring()
	store := credentials.NewKeychainStoreForTest(side, fake)
	if err := store.Set("a", &credentials.Token{Type: credentials.TypeStatic, Token: "x"}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := fake.Delete(credentials.KeychainServiceForTest, credentials.KeychainAccountForTest("a", credentials.KeychainFieldTokenForTest)); err != nil {
		t.Fatalf("seed Delete: %v", err)
	}

	_, err := store.Get("a")
	if !errors.Is(err, credentials.ErrCorrupt) {
		t.Fatalf("Get on missing secret: err = %v, want ErrCorrupt", err)
	}
}

// TestKeychainGetCorruptOnPartialSSO covers drift case 3: the
// sidecar marks a credential as SSO with a refresh token, but the
// keychain has only the API token entry.
func TestKeychainGetCorruptOnPartialSSO(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	side := filepath.Join(dir, "credentials.keychain.toml")
	fake := newFakeKeyring()
	store := credentials.NewKeychainStoreForTest(side, fake)
	sso := &credentials.Token{
		Type:         credentials.TypeSSO,
		Token:        "api",
		AccessToken:  "acc",
		RefreshToken: "ref",
		Email:        "u@example.com",
	}
	if err := store.Set("sso", sso); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := fake.Delete(credentials.KeychainServiceForTest, credentials.KeychainAccountForTest("sso", credentials.KeychainFieldRefreshTokenForTest)); err != nil {
		t.Fatalf("seed Delete: %v", err)
	}

	_, err := store.Get("sso")
	if !errors.Is(err, credentials.ErrCorrupt) {
		t.Fatalf("Get on partial SSO: err = %v, want ErrCorrupt", err)
	}
}

// TestKeychainSetUpdatesOverwriteSecret verifies that re-Setting the
// same name overwrites the keychain entries rather than appending.
func TestKeychainSetUpdatesOverwriteSecret(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	side := filepath.Join(dir, "credentials.keychain.toml")
	fake := newFakeKeyring()
	store := credentials.NewKeychainStoreForTest(side, fake)
	if err := store.Set("a", &credentials.Token{Type: credentials.TypeStatic, Token: "v1"}); err != nil {
		t.Fatalf("Set v1: %v", err)
	}
	if err := store.Set("a", &credentials.Token{Type: credentials.TypeStatic, Token: "v2"}); err != nil {
		t.Fatalf("Set v2: %v", err)
	}
	got, err := store.Get("a")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Token != "v2" {
		t.Fatalf("Token = %q, want %q", got.Token, "v2")
	}
}

// TestKeychainSetRejectsAllEmptySecrets verifies Set refuses an empty
// credential. Storing one would leave the sidecar listing it while
// every keychain entry is absent: the unrecoverable drift the design
// is meant to prevent.
func TestKeychainSetRejectsAllEmptySecrets(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	side := filepath.Join(dir, "credentials.keychain.toml")
	store := credentials.NewKeychainStoreForTest(side, newFakeKeyring())
	if err := store.Set("ghost", &credentials.Token{Type: credentials.TypeStatic}); err == nil {
		t.Fatal("expected Set to reject all-empty token, got nil")
	}
}

// TestKeychainSetSSOWithoutPrimaryToken ensures that an SSO
// credential whose primary Token has not yet been populated by a
// refresh is still acceptable, as long as access or refresh
// material is present. This covers the legacy-config migration
// path that creates SSO records without a primary token.
func TestKeychainSetSSOWithoutPrimaryToken(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	side := filepath.Join(dir, "credentials.keychain.toml")
	fake := newFakeKeyring()
	store := credentials.NewKeychainStoreForTest(side, fake)
	sso := &credentials.Token{
		Type:         credentials.TypeSSO,
		AccessToken:  "acc",
		RefreshToken: "ref",
		Email:        "u@example.com",
	}
	if err := store.Set("partial-sso", sso); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := store.Get("partial-sso")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.AccessToken != "acc" || got.RefreshToken != "ref" {
		t.Fatalf("round-trip lost SSO secrets: got %+v", got)
	}
	if got.Token != "" {
		t.Errorf("Token should remain empty until refresh, got %q", got.Token)
	}
}

// TestKeychainDeleteSavesSidecarFirst ensures that if the keychain
// cleanup phase fails after the sidecar has been rewritten, the
// store is left in the recoverable direction (orphan keychain
// entries, no listing) rather than the unrecoverable one.
func TestKeychainDeleteSavesSidecarFirst(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	side := filepath.Join(dir, "credentials.keychain.toml")
	failing := &deleteFailingKeyring{fakeKeyring: newFakeKeyring()}
	store := credentials.NewKeychainStoreForTest(side, failing)
	if err := store.Set("a", &credentials.Token{Type: credentials.TypeStatic, Token: "x"}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	failing.failOnDelete = true
	if err := store.Delete("a"); err == nil {
		t.Fatal("expected Delete to surface keychain failure")
	}

	// The sidecar should already reflect the deletion: a re-read
	// must show no credential, and a follow-up Delete must return
	// ErrNotFound.
	names, err := store.Names()
	if err != nil {
		t.Fatalf("Names after failed Delete: %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("Names = %v, want []", names)
	}
	if err := store.Delete("a"); !errors.Is(err, credentials.ErrNotFound) {
		t.Fatalf("re-Delete: err = %v, want ErrNotFound", err)
	}
}

// deleteFailingKeyring lets a test toggle a flag that forces every
// subsequent Delete to error out, to reproduce a half-finished
// keychain cleanup.
type deleteFailingKeyring struct {
	*fakeKeyring
	failOnDelete bool
}

func (f *deleteFailingKeyring) Delete(service, user string) error {
	if f.failOnDelete {
		return errSimulatedKeychainFailure
	}
	return f.fakeKeyring.Delete(service, user)
}

var errSimulatedKeychainFailure = errors.New("simulated keychain failure")

// TestKeychainDeleteToleratesMissingKeychainEntries ensures that a
// Delete after orphan-keychain drift leaves the sidecar in a
// consistent state.
func TestKeychainDeleteToleratesMissingKeychainEntries(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	side := filepath.Join(dir, "credentials.keychain.toml")
	fake := newFakeKeyring()
	store := credentials.NewKeychainStoreForTest(side, fake)
	if err := store.Set("a", &credentials.Token{Type: credentials.TypeStatic, Token: "x"}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := fake.Delete(credentials.KeychainServiceForTest, credentials.KeychainAccountForTest("a", credentials.KeychainFieldTokenForTest)); err != nil {
		t.Fatalf("seed Delete: %v", err)
	}

	if err := store.Delete("a"); err != nil {
		t.Fatalf("Delete after drift: %v", err)
	}
	names, err := store.Names()
	if err != nil {
		t.Fatalf("Names: %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("Names = %v, want []", names)
	}
}
