package credentials

import "errors"

const (
	// TypeStatic identifies a long-lived API token entered by the user.
	TypeStatic = "static"
	// TypeSSO identifies a token issued by the SSO flow, with refresh state.
	TypeSSO = "sso"
)

// Token is a single named credential.
type Token struct {
	Type      string `toml:"type" json:"type"`
	Token     string `toml:"token" json:"token"`
	Label     string `toml:"label,omitempty" json:"label,omitempty"`
	AccountID string `toml:"account_id,omitempty" json:"account_id,omitempty"`
	Email     string `toml:"email,omitempty" json:"email,omitempty"`

	APITokenName      string `toml:"api_token_name,omitempty" json:"api_token_name,omitempty"`
	APITokenScope     string `toml:"api_token_scope,omitempty" json:"api_token_scope,omitempty"`
	APITokenExpiresAt string `toml:"api_token_expires_at,omitempty" json:"api_token_expires_at,omitempty"`
	APITokenID        string `toml:"api_token_id,omitempty" json:"api_token_id,omitempty"`

	AccessToken      string `toml:"access_token,omitempty" json:"access_token,omitempty"`
	RefreshToken     string `toml:"refresh_token,omitempty" json:"refresh_token,omitempty"`
	AccessExpiresAt  string `toml:"access_expires_at,omitempty" json:"access_expires_at,omitempty"`
	RefreshExpiresAt string `toml:"refresh_expires_at,omitempty" json:"refresh_expires_at,omitempty"`
	NeedsReauth      bool   `toml:"needs_reauth,omitempty" json:"needs_reauth,omitempty"`
}

// Metadata is the non-secret view of a credential. Backends that hold
// secrets in an external system (e.g. a keychain) can answer Names and
// Metadata queries without touching the secret store, so listing and
// expiry checks do not prompt the user.
type Metadata struct {
	Type      string
	Label     string
	AccountID string
	Email     string

	APITokenName      string
	APITokenScope     string
	APITokenExpiresAt string
	APITokenID        string

	AccessExpiresAt  string
	RefreshExpiresAt string
	NeedsReauth      bool
	// HasRefreshToken signals that an SSO token carries refresh material
	// without exposing the secret. Expiry classification uses it to tell
	// "refresh metadata not yet populated" (no warning) from "no refresh
	// token at all" (fall back to access-token expiry).
	HasRefreshToken bool
}

// Metadata returns the non-secret view of t. Returns nil if t is nil.
func (t *Token) Metadata() *Metadata {
	if t == nil {
		return nil
	}
	return &Metadata{
		Type:              t.Type,
		Label:             t.Label,
		AccountID:         t.AccountID,
		Email:             t.Email,
		APITokenName:      t.APITokenName,
		APITokenScope:     t.APITokenScope,
		APITokenExpiresAt: t.APITokenExpiresAt,
		APITokenID:        t.APITokenID,
		AccessExpiresAt:   t.AccessExpiresAt,
		RefreshExpiresAt:  t.RefreshExpiresAt,
		NeedsReauth:       t.NeedsReauth,
		HasRefreshToken:   t.RefreshToken != "",
	}
}

// Sentinel errors matched with errors.Is. Token resolution treats
// ErrNotFound as a signal to retry --token <value> as a raw API token;
// ErrUnavailable and ErrCorrupt must propagate so credential names are
// never sent as bearer tokens.
var (
	ErrNotFound    = errors.New("credentials: credential not found")
	ErrNoDefault   = errors.New("credentials: no default credential set")
	ErrUnavailable = errors.New("credentials: store unavailable")
	ErrCorrupt     = errors.New("credentials: store corrupt")
)

// Store is the credential backend interface.
//
// Names and Metadata never expose secret material and must not contact a
// secret-bearing system; only Get may. Delete does not reassign the
// default. SetDefault on an unknown name returns ErrNotFound.
type Store interface {
	Names() ([]string, error)
	Metadata(name string) (*Metadata, error)
	Get(name string) (*Token, error)

	Set(name string, t *Token) error
	Delete(name string) error

	DefaultName() (string, error)
	SetDefault(name string) error
}

// GetDefault is a convenience that returns the default credential name and
// its Token. Returns ErrNoDefault when no default is set.
func GetDefault(s Store) (string, *Token, error) {
	name, err := s.DefaultName()
	if err != nil {
		return "", nil, err
	}
	t, err := s.Get(name)
	if err != nil {
		return "", nil, err
	}
	return name, t, nil
}

// Lookup returns the named token, or (nil, nil) if it is not in the
// store. Use this when "missing" is a non-error outcome at the call site.
func Lookup(s Store, name string) (*Token, error) {
	t, err := s.Get(name)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return t, nil
}

// LookupMetadata is the metadata-only counterpart to Lookup.
func LookupMetadata(s Store, name string) (*Metadata, error) {
	md, err := s.Metadata(name)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return md, nil
}

// DefaultOrEmpty returns the default credential name, or "" when none is
// configured. ErrUnavailable and ErrCorrupt still surface so callers
// never silently degrade on a broken store.
func DefaultOrEmpty(s Store) (string, error) {
	name, err := s.DefaultName()
	if err != nil {
		if errors.Is(err, ErrNoDefault) {
			return "", nil
		}
		return "", err
	}
	return name, nil
}

// AllMetadata returns metadata for every credential, keyed by name. It
// reads metadata only, so a keychain-backed store does not prompt.
func AllMetadata(s Store) (map[string]*Metadata, error) {
	names, err := s.Names()
	if err != nil {
		return nil, err
	}
	out := make(map[string]*Metadata, len(names))
	for _, name := range names {
		md, err := s.Metadata(name)
		if err != nil {
			return nil, err
		}
		out[name] = md
	}
	return out, nil
}

// SetAndPromote stores t under name and, if no default is set, promotes
// name to default. Returns the previous default ("" if none).
func SetAndPromote(s Store, name string, t *Token) (previousDefault string, err error) {
	previousDefault, err = DefaultOrEmpty(s)
	if err != nil {
		return "", err
	}
	if err := s.Set(name, t); err != nil {
		return previousDefault, err
	}
	if previousDefault == "" {
		if err := s.SetDefault(name); err != nil {
			return previousDefault, err
		}
	}
	return previousDefault, nil
}
