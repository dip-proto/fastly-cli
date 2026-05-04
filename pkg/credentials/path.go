package credentials

import (
	"os"
	"path/filepath"
)

const (
	// FileName is the basename of the on-disk credentials file.
	FileName = "credentials.toml"

	// DirectoryPermissions is the mode applied to the parent directory.
	DirectoryPermissions = 0o700

	// FilePermissions is the strict mode required of the credentials file.
	// Any wider permissions cause the FileStore to refuse to read it.
	FilePermissions = 0o600
)

// FilePath is the resolved path to credentials.toml, alongside
// config.toml under $XDG_CONFIG_HOME/fastly.
var FilePath = func() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "fastly", FileName)
	}
	if dir, err := os.UserHomeDir(); err == nil {
		return filepath.Join(dir, ".fastly", FileName)
	}
	panic("unable to deduce user config dir or user home dir")
}()
