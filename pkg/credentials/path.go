package credentials

import (
	"os"
	"path/filepath"
)

const (
	// FileName is the basename of the on-disk credentials file.
	FileName = "credentials.toml"

	// KeychainSidecarFileName is the keychain backend's sidecar file,
	// holding credential names, the default pointer, and non-secret
	// metadata.
	KeychainSidecarFileName = "credentials.keychain.toml"

	// BackendSelectionFileName is the one-line file recording the
	// user's preferred backend (file|keychain|auto). Kept out of
	// config.toml so config.toml stays read-only at runtime.
	BackendSelectionFileName = "credentials.backend"

	// DirectoryPermissions is the mode applied to the parent directory.
	DirectoryPermissions = 0o700

	// FilePermissions is the strict mode required of the credentials file.
	// Any wider permissions cause the FileStore to refuse to read it.
	FilePermissions = 0o600

	// BackendSelectionFilePermissions is the mode for the
	// backend-selection file, looser than FilePermissions because the
	// file holds no secrets.
	BackendSelectionFilePermissions = 0o644
)

// FilePath is the resolved path to credentials.toml, alongside
// config.toml under $XDG_CONFIG_HOME/fastly.
var FilePath = resolveConfigPath(FileName)

// KeychainSidecarPath is the resolved path to the keychain backend's
// metadata sidecar. Only meaningful when the keychain backend is in use.
var KeychainSidecarPath = resolveConfigPath(KeychainSidecarFileName)

// BackendSelectionPath is the resolved path to the backend selection
// file.
var BackendSelectionPath = resolveConfigPath(BackendSelectionFileName)

func resolveConfigPath(name string) string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "fastly", name)
	}
	if dir, err := os.UserHomeDir(); err == nil {
		return filepath.Join(dir, ".fastly", name)
	}
	panic("unable to deduce user config dir or user home dir")
}
