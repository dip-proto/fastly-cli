//go:build keychain

package credentials_test

import (
	"path/filepath"
	"testing"

	"github.com/fastly/cli/pkg/credentials"
	"github.com/zalando/go-keyring"
)

// integrationKeyring delegates to real go-keyring and tracks
// (service, user) pairs so cleanup wipes leftovers even on panic.
type integrationKeyring struct {
	t       *testing.T
	created map[string]struct{}
}

func newIntegrationKeyring(t *testing.T) *integrationKeyring {
	c := &integrationKeyring{t: t, created: map[string]struct{}{}}
	t.Cleanup(c.cleanup)
	return c
}

func (c *integrationKeyring) key(service, user string) string {
	return service + "\x00" + user
}

func (c *integrationKeyring) Set(service, user, secret string) error {
	if err := keyring.Set(service, user, secret); err != nil {
		return err
	}
	c.created[c.key(service, user)] = struct{}{}
	return nil
}

func (c *integrationKeyring) Get(service, user string) (string, error) {
	return keyring.Get(service, user)
}

func (c *integrationKeyring) Delete(service, user string) error {
	if err := keyring.Delete(service, user); err != nil {
		return err
	}
	delete(c.created, c.key(service, user))
	return nil
}

func (c *integrationKeyring) cleanup() {
	for k := range c.created {
		// Split back into service / user for delete. The key encoding
		// uses NUL as the separator, which the keychain account
		// strings never contain.
		parts := splitKey(k)
		_ = keyring.Delete(parts[0], parts[1])
	}
}

func splitKey(k string) [2]string {
	for i := 0; i < len(k); i++ {
		if k[i] == 0 {
			return [2]string{k[:i], k[i+1:]}
		}
	}
	return [2]string{k, ""}
}

// TestKeychainIntegration runs the shared store contract against
// the real go-keyring. Skipped unless the build tag is set; CI
// runs it on macOS and Linux runners where a usable secret service
// is configured.
func TestKeychainIntegration(t *testing.T) {
	dir := t.TempDir()
	side := filepath.Join(dir, "credentials.keychain.toml")
	client := newIntegrationKeyring(t)

	store := credentials.NewKeychainStoreForTest(side, client)
	tok := &credentials.Token{
		Type:  credentials.TypeStatic,
		Token: "integration-token",
		Email: "user@example.com",
	}
	if err := store.Set("integration-static", tok); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := store.Get("integration-static")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Token != "integration-token" {
		t.Fatalf("Token = %q, want %q", got.Token, "integration-token")
	}
	if err := store.Delete("integration-static"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}
