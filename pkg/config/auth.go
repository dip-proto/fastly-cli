package config

// Auth represents the new auth configuration section.
// It stores named tokens and tracks which one is the default.
type Auth struct {
	// Default is the name of the default token entry.
	Default string `toml:"default" json:"default"`
	// Tokens is a map of named token entries.
	Tokens AuthTokens `toml:"tokens" json:"tokens"`
}

// AuthTokens is a map of token name to token entry.
type AuthTokens map[string]*AuthToken

// AuthToken represents a single stored credential.
type AuthToken struct {
	// Type is "static" for API tokens or "sso" for OAuth-backed tokens.
	Type string `toml:"type" json:"type"`
	// Token is the Fastly API token used for API calls.
	Token string `toml:"token" json:"token"`
	// Label is an optional human-friendly description.
	Label string `toml:"label,omitempty" json:"label,omitempty"`
	// AccountID is the Fastly account/customer ID, if known.
	AccountID string `toml:"account_id,omitempty" json:"account_id,omitempty"`
	// Email is the email address associated with this token, if known.
	Email string `toml:"email,omitempty" json:"email,omitempty"`
	// Allow is the stored policy for this token (e.g. ["readonly"]).
	Allow []string `toml:"allow" json:"allow"`

	// API token metadata (populated from /tokens/self when available).

	// APITokenName is the name of the API token as set in the Fastly UI.
	APITokenName string `toml:"api_token_name,omitempty" json:"api_token_name,omitempty"`
	// APITokenScope is the scope string of the API token (e.g. "global", "global:read").
	APITokenScope string `toml:"api_token_scope,omitempty" json:"api_token_scope,omitempty"`
	// APITokenExpiresAt is when the API token expires (RFC 3339), if it has an expiry.
	APITokenExpiresAt string `toml:"api_token_expires_at,omitempty" json:"api_token_expires_at,omitempty"`
	// APITokenID is the unique identifier of the API token.
	APITokenID string `toml:"api_token_id,omitempty" json:"api_token_id,omitempty"`

	// SSO-specific fields (only populated when Type == "sso").

	// RefreshToken is the OAuth refresh token.
	RefreshToken string `toml:"refresh_token,omitempty" json:"refresh_token,omitempty"`
	// AccessExpiresAt is when the access token expires (RFC 3339).
	AccessExpiresAt string `toml:"access_expires_at,omitempty" json:"access_expires_at,omitempty"`
	// RefreshExpiresAt is when the refresh token expires (RFC 3339).
	RefreshExpiresAt string `toml:"refresh_expires_at,omitempty" json:"refresh_expires_at,omitempty"`
	// AccessToken is the OAuth access token (used to obtain API tokens).
	AccessToken string `toml:"access_token,omitempty" json:"access_token,omitempty"`
	// NeedsReauth indicates the SSO session could not be refreshed during migration.
	NeedsReauth bool `toml:"needs_reauth,omitempty" json:"needs_reauth,omitempty"`
}

// AuthTokenTypeStatic is the type value for static API tokens.
const AuthTokenTypeStatic = "static"

// AuthTokenTypeSSO is the type value for SSO/OAuth-backed tokens.
const AuthTokenTypeSSO = "sso"
