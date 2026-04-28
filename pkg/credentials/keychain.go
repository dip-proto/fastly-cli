package credentials

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"

	toml "github.com/pelletier/go-toml"
	"github.com/zalando/go-keyring"
)

// keychainService is the OS keychain service string for every Fastly
// CLI credential. Visible to users in macOS Keychain Access,
// secret-tool, or `cmdkey /list`.
const keychainService = "fastly-cli"

const (
	keychainFieldToken        = "token"
	keychainFieldAccessToken  = "access_token"
	keychainFieldRefreshToken = "refresh_token"
)

// keyringClient is the minimal go-keyring surface KeychainStore needs.
// Production wires goKeyring; tests substitute an in-memory fake.
type keyringClient interface {
	Set(service, user, secret string) error
	Get(service, user string) (string, error)
	Delete(service, user string) error
}

// goKeyring delegates to the go-keyring package functions.
type goKeyring struct{}

func (goKeyring) Set(service, user, secret string) error {
	return keyring.Set(service, user, secret)
}

func (goKeyring) Get(service, user string) (string, error) {
	return keyring.Get(service, user)
}

func (goKeyring) Delete(service, user string) error {
	return keyring.Delete(service, user)
}

// KeychainStore puts secrets in the OS secret service and tracks
// credential names, the default pointer, and non-secret metadata in a
// sidecar TOML file. The sidecar is the source of truth for Names,
// Metadata, and DefaultName, so listing and expiry checks never
// unlock the keychain.
type KeychainStore struct {
	sidecar string
	mu      sync.Mutex
	client  keyringClient
}

// NewKeychainStore returns a KeychainStore with sidecar at path,
// using go-keyring for keychain operations.
func NewKeychainStore(path string) *KeychainStore {
	return &KeychainStore{
		sidecar: path,
		client:  goKeyring{},
	}
}

// newKeychainStoreWithClient is the test entry point taking a
// caller-supplied keyringClient so tests bypass the host keychain.
func newKeychainStoreWithClient(path string, client keyringClient) *KeychainStore {
	return &KeychainStore{sidecar: path, client: client}
}

// Path returns the on-disk sidecar path.
func (s *KeychainStore) Path() string {
	return s.sidecar
}

// keychainSidecarFormat mirrors fileFormat but stores metadata only.
// Every Metadata field is persisted so Names and Metadata never
// contact the keychain. HasRefreshToken is stored explicitly so
// callers can tell "no refresh token at all" from "refresh metadata
// not yet populated" without probing the keychain.
type keychainSidecarFormat struct {
	Default string                       `toml:"default"`
	Tokens  map[string]*keychainTokenRow `toml:"tokens"`
}

type keychainTokenRow struct {
	Type              string `toml:"type"`
	Label             string `toml:"label,omitempty"`
	AccountID         string `toml:"account_id,omitempty"`
	Email             string `toml:"email,omitempty"`
	APITokenName      string `toml:"api_token_name,omitempty"`
	APITokenScope     string `toml:"api_token_scope,omitempty"`
	APITokenExpiresAt string `toml:"api_token_expires_at,omitempty"`
	APITokenID        string `toml:"api_token_id,omitempty"`
	AccessExpiresAt   string `toml:"access_expires_at,omitempty"`
	RefreshExpiresAt  string `toml:"refresh_expires_at,omitempty"`
	NeedsReauth       bool   `toml:"needs_reauth,omitempty"`
	HasRefreshToken   bool   `toml:"has_refresh_token,omitempty"`
}

func rowFromToken(t *Token) *keychainTokenRow {
	md := t.Metadata()
	return &keychainTokenRow{
		Type:              md.Type,
		Label:             md.Label,
		AccountID:         md.AccountID,
		Email:             md.Email,
		APITokenName:      md.APITokenName,
		APITokenScope:     md.APITokenScope,
		APITokenExpiresAt: md.APITokenExpiresAt,
		APITokenID:        md.APITokenID,
		AccessExpiresAt:   md.AccessExpiresAt,
		RefreshExpiresAt:  md.RefreshExpiresAt,
		NeedsReauth:       md.NeedsReauth,
		HasRefreshToken:   md.HasRefreshToken,
	}
}

func (r *keychainTokenRow) Metadata() *Metadata {
	return &Metadata{
		Type:              r.Type,
		Label:             r.Label,
		AccountID:         r.AccountID,
		Email:             r.Email,
		APITokenName:      r.APITokenName,
		APITokenScope:     r.APITokenScope,
		APITokenExpiresAt: r.APITokenExpiresAt,
		APITokenID:        r.APITokenID,
		AccessExpiresAt:   r.AccessExpiresAt,
		RefreshExpiresAt:  r.RefreshExpiresAt,
		NeedsReauth:       r.NeedsReauth,
		HasRefreshToken:   r.HasRefreshToken,
	}
}

func keychainAccount(name, field string) string {
	return name + ":" + field
}

// load reads the sidecar from disk. A missing sidecar yields an empty
// store. On Unix, permissions wider than 0600 return ErrCorrupt; the
// sidecar names every credential even though the secrets live in the
// keychain.
func (s *KeychainStore) load() (*keychainSidecarFormat, error) {
	info, err := os.Stat(s.sidecar)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &keychainSidecarFormat{Tokens: map[string]*keychainTokenRow{}}, nil
		}
		return nil, fmt.Errorf("%w: stat %s: %v", ErrUnavailable, s.sidecar, err)
	}
	if runtime.GOOS != "windows" {
		if mode := info.Mode().Perm(); mode&^FilePermissions != 0 {
			return nil, fmt.Errorf("%w: %s has permissions %#o, expected 0600 or stricter",
				ErrCorrupt, s.sidecar, mode)
		}
	}
	data, err := os.ReadFile(s.sidecar)
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %v", ErrUnavailable, s.sidecar, err)
	}
	f := &keychainSidecarFormat{}
	if err := toml.Unmarshal(data, f); err != nil {
		return nil, fmt.Errorf("%w: parse %s: %v", ErrCorrupt, s.sidecar, err)
	}
	if f.Tokens == nil {
		f.Tokens = map[string]*keychainTokenRow{}
	}
	return f, nil
}

func (s *KeychainStore) save(f *keychainSidecarFormat) error {
	dir := filepath.Dir(s.sidecar)
	if err := os.MkdirAll(dir, DirectoryPermissions); err != nil {
		return fmt.Errorf("%w: mkdir %s: %v", ErrUnavailable, dir, err)
	}
	data, err := toml.Marshal(f)
	if err != nil {
		return fmt.Errorf("%w: encode: %v", ErrUnavailable, err)
	}
	tmp := fmt.Sprintf("%s.tmp.%d", s.sidecar, os.Getpid())
	fp, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, FilePermissions)
	if err != nil {
		return fmt.Errorf("%w: create %s: %v", ErrUnavailable, tmp, err)
	}
	cleanup := func() { _ = os.Remove(tmp) }
	if _, err := fp.Write(data); err != nil {
		_ = fp.Close()
		cleanup()
		return fmt.Errorf("%w: write %s: %v", ErrUnavailable, tmp, err)
	}
	if err := fp.Sync(); err != nil {
		_ = fp.Close()
		cleanup()
		return fmt.Errorf("%w: fsync %s: %v", ErrUnavailable, tmp, err)
	}
	if err := fp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("%w: close %s: %v", ErrUnavailable, tmp, err)
	}
	if err := os.Rename(tmp, s.sidecar); err != nil {
		cleanup()
		return fmt.Errorf("%w: rename %s -> %s: %v", ErrUnavailable, tmp, s.sidecar, err)
	}
	syncDir(dir)
	return nil
}

func (s *KeychainStore) acquireLock() (*fileLock, error) {
	return acquireLockAt(s.sidecar + ".lock")
}

// Names returns all credential names in deterministic order
// (sidecar only).
func (s *KeychainStore) Names() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(f.Tokens))
	for n := range f.Tokens {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

// Metadata returns the non-secret view of name (sidecar only).
func (s *KeychainStore) Metadata(name string) (*Metadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return nil, err
	}
	row, ok := f.Tokens[name]
	if !ok {
		return nil, ErrNotFound
	}
	return row.Metadata(), nil
}

// Get returns a copy of the named credential, reading both the
// sidecar and the keychain. ErrNotFound only signals an absent
// sidecar entry; a sidecar entry with missing keychain secrets
// returns ErrCorrupt rather than a half-populated token.
func (s *KeychainStore) Get(name string) (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return nil, err
	}
	row, ok := f.Tokens[name]
	if !ok {
		return nil, ErrNotFound
	}

	tok, err := s.readSecret(name, keychainFieldToken)
	if err != nil {
		if errors.Is(err, errKeychainMissing) {
			return nil, fmt.Errorf("%w: credential %q listed in sidecar but missing from system keychain. Run `fastly auth delete %s` to forget it, or re-add it", ErrCorrupt, name, name)
		}
		return nil, err
	}

	t := &Token{
		Type:              row.Type,
		Token:             tok,
		Label:             row.Label,
		AccountID:         row.AccountID,
		Email:             row.Email,
		APITokenName:      row.APITokenName,
		APITokenScope:     row.APITokenScope,
		APITokenExpiresAt: row.APITokenExpiresAt,
		APITokenID:        row.APITokenID,
		AccessExpiresAt:   row.AccessExpiresAt,
		RefreshExpiresAt:  row.RefreshExpiresAt,
		NeedsReauth:       row.NeedsReauth,
	}

	if row.Type == TypeSSO {
		access, err := s.readSecretOptional(name, keychainFieldAccessToken)
		if err != nil {
			return nil, err
		}
		t.AccessToken = access

		if row.HasRefreshToken {
			refresh, err := s.readSecret(name, keychainFieldRefreshToken)
			if err != nil {
				if errors.Is(err, errKeychainMissing) {
					return nil, fmt.Errorf("%w: credential %q lists has_refresh_token but :refresh_token is missing from the system keychain", ErrCorrupt, name)
				}
				return nil, err
			}
			t.RefreshToken = refresh
		}
	}

	return t, nil
}

// errKeychainMissing is returned by readSecret for a missing keychain
// entry. Callers map it to ErrCorrupt, or ignore it for optional fields.
var errKeychainMissing = errors.New("keychain entry missing")

func (s *KeychainStore) readSecret(name, field string) (string, error) {
	v, err := s.client.Get(keychainService, keychainAccount(name, field))
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", errKeychainMissing
		}
		return "", fmt.Errorf("%w: keychain get %s/%s: %v", ErrUnavailable, name, field, err)
	}
	return v, nil
}

func (s *KeychainStore) readSecretOptional(name, field string) (string, error) {
	v, err := s.readSecret(name, field)
	if err != nil {
		if errors.Is(err, errKeychainMissing) {
			return "", nil
		}
		return "", err
	}
	return v, nil
}

// Set stores a copy of t under name. It writes the keychain entries
// first, then atomically rewrites the sidecar; if the sidecar write
// fails, keychain writes are rolled back. The sidecar is always the
// conservative observer: a sidecar entry implies the keychain has
// the named secret.
func (s *KeychainStore) Set(name string, t *Token) error {
	if t == nil {
		return fmt.Errorf("credentials: Set requires a non-nil token")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	lock, err := s.acquireLock()
	if err != nil {
		return fmt.Errorf("%w: acquire lock: %v", ErrUnavailable, err)
	}
	defer lock.Release()

	f, err := s.load()
	if err != nil {
		return err
	}

	type rollback struct {
		field string
		had   bool
		prev  string
	}
	var written []rollback

	writeSecret := func(field, value string) error {
		account := keychainAccount(name, field)
		prev, getErr := s.client.Get(keychainService, account)
		had := true
		if getErr != nil {
			if errors.Is(getErr, keyring.ErrNotFound) {
				had = false
				prev = ""
			} else {
				return fmt.Errorf("%w: keychain probe %s/%s: %v", ErrUnavailable, name, field, getErr)
			}
		}
		if value == "" {
			if had {
				if err := s.client.Delete(keychainService, account); err != nil {
					return fmt.Errorf("%w: keychain delete %s/%s: %v", ErrUnavailable, name, field, err)
				}
			}
			written = append(written, rollback{field: field, had: had, prev: prev})
			return nil
		}
		if err := s.client.Set(keychainService, account, value); err != nil {
			return fmt.Errorf("%w: keychain set %s/%s: %v", ErrUnavailable, name, field, err)
		}
		written = append(written, rollback{field: field, had: had, prev: prev})
		return nil
	}

	rollbackKeychain := func() {
		for _, w := range written {
			account := keychainAccount(name, w.field)
			if w.had {
				_ = s.client.Set(keychainService, account, w.prev)
			} else {
				_ = s.client.Delete(keychainService, account)
			}
		}
	}

	if err := writeSecret(keychainFieldToken, t.Token); err != nil {
		rollbackKeychain()
		return err
	}
	if err := writeSecret(keychainFieldAccessToken, t.AccessToken); err != nil {
		rollbackKeychain()
		return err
	}
	if err := writeSecret(keychainFieldRefreshToken, t.RefreshToken); err != nil {
		rollbackKeychain()
		return err
	}

	f.Tokens[name] = rowFromToken(t)
	if err := s.save(f); err != nil {
		rollbackKeychain()
		return err
	}
	return nil
}

// Delete removes name. Absent keychain entries are tolerated so the
// store stays consistent regardless of pre-existing drift.
func (s *KeychainStore) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	lock, err := s.acquireLock()
	if err != nil {
		return fmt.Errorf("%w: acquire lock: %v", ErrUnavailable, err)
	}
	defer lock.Release()

	f, err := s.load()
	if err != nil {
		return err
	}
	if _, ok := f.Tokens[name]; !ok {
		return ErrNotFound
	}

	for _, field := range []string{keychainFieldToken, keychainFieldAccessToken, keychainFieldRefreshToken} {
		if err := s.client.Delete(keychainService, keychainAccount(name, field)); err != nil {
			if errors.Is(err, keyring.ErrNotFound) {
				continue
			}
			return fmt.Errorf("%w: keychain delete %s/%s: %v", ErrUnavailable, name, field, err)
		}
	}

	delete(f.Tokens, name)
	if f.Default == name {
		f.Default = ""
	}
	return s.save(f)
}

// DefaultName returns the current default credential name (sidecar only).
func (s *KeychainStore) DefaultName() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return "", err
	}
	if f.Default == "" {
		return "", ErrNoDefault
	}
	return f.Default, nil
}

// SetDefault sets the default to name (sidecar only).
func (s *KeychainStore) SetDefault(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	lock, err := s.acquireLock()
	if err != nil {
		return fmt.Errorf("%w: acquire lock: %v", ErrUnavailable, err)
	}
	defer lock.Release()

	f, err := s.load()
	if err != nil {
		return err
	}
	if _, ok := f.Tokens[name]; !ok {
		return ErrNotFound
	}
	f.Default = name
	return s.save(f)
}
