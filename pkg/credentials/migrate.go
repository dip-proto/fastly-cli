package credentials

import (
	"fmt"
	"os"
	"sort"
	"time"

	toml "github.com/pelletier/go-toml"
)

const (
	// legacyUserName is the credential name for a migrated [user]
	// section. legacyUserCollisionName is the fallback when "user"
	// already exists in [auth] or [profile].
	legacyUserName          = "user"
	legacyUserCollisionName = "legacy"
)

// Migrate copies legacy credential data from configPath into store as a
// one-shot, read-only operation. configPath is never modified.
//
// Per-name source priority is [auth], then [profile.<name>], then
// [user]. Migrate is a no-op when the store already has credentials.
// A corrupt store is fatal; a missing or unparseable configPath is
// silently treated as nothing to migrate.
//
// Returns true if any tokens were written.
func Migrate(configPath string, store Store) (bool, error) {
	names, err := store.Names()
	if err != nil {
		return false, fmt.Errorf("inspecting credential store: %w", err)
	}
	if len(names) > 0 {
		return false, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return false, nil //nolint:nilerr
	}

	var lc legacyConfig
	if err := toml.Unmarshal(data, &lc); err != nil {
		// cfg.Read surfaces the parse error to the user separately.
		return false, nil //nolint:nilerr
	}

	tokens, defaultName := collectLegacyCredentials(&lc)
	if len(tokens) == 0 {
		return false, nil
	}

	for name, tok := range tokens {
		if err := store.Set(name, tok); err != nil {
			return false, fmt.Errorf("migrate credential %q: %w", name, err)
		}
	}
	if defaultName != "" {
		if err := store.SetDefault(defaultName); err != nil {
			return false, fmt.Errorf("migrate default credential: %w", err)
		}
	}
	return true, nil
}

// legacyConfig is a permissive subset of the historical config.toml,
// scoped to the fields migration cares about.
type legacyConfig struct {
	Auth     legacyAuth                `toml:"auth"`
	Profiles map[string]*legacyProfile `toml:"profile"`
	User     legacyUser                `toml:"user"`
}

type legacyAuth struct {
	Default string                      `toml:"default"`
	Tokens  map[string]*legacyAuthToken `toml:"tokens"`
}

type legacyAuthToken struct {
	Type              string `toml:"type"`
	Token             string `toml:"token"`
	Label             string `toml:"label"`
	Email             string `toml:"email"`
	AccountID         string `toml:"account_id"`
	APITokenName      string `toml:"api_token_name"`
	APITokenScope     string `toml:"api_token_scope"`
	APITokenExpiresAt string `toml:"api_token_expires_at"`
	APITokenID        string `toml:"api_token_id"`
	AccessToken       string `toml:"access_token"`
	RefreshToken      string `toml:"refresh_token"`
	AccessExpiresAt   string `toml:"access_expires_at"`
	RefreshExpiresAt  string `toml:"refresh_expires_at"`
	NeedsReauth       bool   `toml:"needs_reauth"`
}

type legacyProfile struct {
	Default             bool   `toml:"default"`
	Token               string `toml:"token"`
	Email               string `toml:"email"`
	CustomerID          string `toml:"customer_id"`
	CustomerName        string `toml:"customer_name"`
	AccessToken         string `toml:"access_token"`
	AccessTokenCreated  int64  `toml:"access_token_created"`
	AccessTokenTTL      int    `toml:"access_token_ttl"`
	RefreshToken        string `toml:"refresh_token"`
	RefreshTokenCreated int64  `toml:"refresh_token_created"`
	RefreshTokenTTL     int    `toml:"refresh_token_ttl"`
}

type legacyUser struct {
	Email string `toml:"email"`
	Token string `toml:"token"`
}

func collectLegacyCredentials(c *legacyConfig) (map[string]*Token, string) {
	out := map[string]*Token{}
	var defaultName string

	for name, at := range c.Auth.Tokens {
		if at == nil {
			continue
		}
		out[name] = legacyAuthTokenToToken(at)
	}
	if c.Auth.Default != "" {
		if _, ok := out[c.Auth.Default]; ok {
			defaultName = c.Auth.Default
		}
	}

	for name, p := range c.Profiles {
		if p == nil {
			continue
		}
		if _, exists := out[name]; exists {
			continue
		}
		out[name] = legacyProfileToToken(p)
		if p.Default && defaultName == "" {
			defaultName = name
		}
	}

	if c.User.Email != "" || c.User.Token != "" {
		name := legacyUserName
		if _, exists := out[name]; exists {
			name = legacyUserCollisionName
		}
		if _, exists := out[name]; !exists {
			out[name] = &Token{
				Type:  TypeStatic,
				Token: c.User.Token,
				Email: c.User.Email,
			}
			if defaultName == "" {
				defaultName = name
			}
		}
	}

	if defaultName == "" && len(out) > 0 {
		names := make([]string, 0, len(out))
		for n := range out {
			names = append(names, n)
		}
		sort.Strings(names)
		defaultName = names[0]
	}

	return out, defaultName
}

func legacyAuthTokenToToken(at *legacyAuthToken) *Token {
	return &Token{
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

func legacyProfileToToken(p *legacyProfile) *Token {
	t := &Token{
		Token:     p.Token,
		Email:     p.Email,
		AccountID: p.CustomerID,
	}

	hasSSO := p.AccessToken != "" || p.RefreshToken != "" ||
		p.AccessTokenCreated != 0 || p.RefreshTokenCreated != 0

	if hasSSO {
		t.Type = TypeSSO
		t.AccessToken = p.AccessToken
		t.RefreshToken = p.RefreshToken
		if p.AccessTokenCreated != 0 && p.AccessTokenTTL != 0 {
			expiresAt := time.Unix(p.AccessTokenCreated, 0).
				Add(time.Duration(p.AccessTokenTTL) * time.Second)
			t.AccessExpiresAt = expiresAt.Format(time.RFC3339)
		}
		if p.RefreshTokenCreated != 0 && p.RefreshTokenTTL != 0 {
			expiresAt := time.Unix(p.RefreshTokenCreated, 0).
				Add(time.Duration(p.RefreshTokenTTL) * time.Second)
			t.RefreshExpiresAt = expiresAt.Format(time.RFC3339)
		}
		if t.RefreshExpiresAt != "" {
			if rt, err := time.Parse(time.RFC3339, t.RefreshExpiresAt); err == nil && time.Now().After(rt) {
				t.NeedsReauth = true
			}
		}
	} else {
		t.Type = TypeStatic
	}

	if p.CustomerName != "" {
		t.Label = fmt.Sprintf("%s (%s)", p.CustomerName, p.Email)
	}

	return t
}
