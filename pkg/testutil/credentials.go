package testutil

import (
	"fmt"
	"time"

	"github.com/fastly/cli/pkg/config"
	"github.com/fastly/cli/pkg/credentials"
	"github.com/fastly/cli/pkg/global"
)

// SyncCredentialsWithConfigAuth populates d.Credentials from
// d.Config.Auth, so legacy fixtures that author tokens via config.Auth
// land in the credential store before the command runs.
func SyncCredentialsWithConfigAuth(d *global.Data) {
	if d.Credentials == nil {
		d.Credentials = credentials.NewMemoryStore()
	}
	names, err := d.Credentials.Names()
	if err == nil {
		for _, n := range names {
			_ = d.Credentials.Delete(n)
		}
	}
	for name, at := range d.Config.Auth.Tokens {
		if at == nil {
			continue
		}
		_ = d.Credentials.Set(name, tokenFromAuthToken(at))
	}
	if d.Config.Auth.Default != "" {
		_ = d.Credentials.SetDefault(d.Config.Auth.Default)
	}
}

func tokenFromAuthToken(at *config.AuthToken) *credentials.Token {
	if at == nil {
		return nil
	}
	return &credentials.Token{
		Type:              at.Type,
		Token:             at.Token,
		Label:             at.Label,
		AccountID:         at.AccountID,
		Email:             at.Email,
		APITokenName:      at.APITokenName,
		APITokenScope:     at.APITokenScope,
		APITokenExpiresAt: at.APITokenExpiresAt,
		APITokenID:        at.APITokenID,
		AccessToken:       at.AccessToken,
		RefreshToken:      at.RefreshToken,
		AccessExpiresAt:   at.AccessExpiresAt,
		RefreshExpiresAt:  at.RefreshExpiresAt,
		NeedsReauth:       at.NeedsReauth,
	}
}

// CredentialOrNil returns the named credential, or nil on any error.
func CredentialOrNil(d *global.Data, name string) *credentials.Token {
	if d == nil {
		return nil
	}
	t, err := d.Credentials.Get(name)
	if err != nil {
		return nil
	}
	return t
}

// DefaultCredentialName returns the default credential name, or "".
func DefaultCredentialName(d *global.Data) string {
	if d == nil {
		return ""
	}
	name, err := d.Credentials.DefaultName()
	if err != nil {
		return ""
	}
	return name
}

// MockTokenAPIExpiry sets APITokenExpiresAt on the named credential.
func MockTokenAPIExpiry(d *global.Data, name string, when time.Time) {
	expires := when.Format(time.RFC3339)
	ct, err := d.Credentials.Get(name)
	if err == nil && ct != nil {
		ct.APITokenExpiresAt = expires
		_ = d.Credentials.Set(name, ct)
	}
}

// NewMockCredentialStore returns a MemoryStore preloaded with a default
// "user" token, so commands resolve credentials without per-test setup.
func NewMockCredentialStore() *credentials.MemoryStore {
	s := credentials.NewMemoryStore()
	if err := s.Set("user", &credentials.Token{
		Type:  credentials.TypeStatic,
		Token: "mock-token",
		Email: "test@example.com",
	}); err != nil {
		panic(fmt.Sprintf("testutil: seeding mock credential store: %v", err))
	}
	if err := s.SetDefault("user"); err != nil {
		panic(fmt.Sprintf("testutil: setting default on mock credential store: %v", err))
	}
	return s
}
