package credentials

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ReadBackendSelection reads the backend selection file and returns
// the parsed Backend along with the raw trimmed contents. A missing
// file returns ("", "", nil); that is unconfigured, not an error.
//
// A file with an unrecognised value returns (BackendAuto, raw, nil),
// so SelectBackend can treat it as "no value" and `auth backend show`
// can warn the user using the raw bytes.
func ReadBackendSelection() (Backend, string, error) {
	data, err := os.ReadFile(BackendSelectionPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", "", nil
		}
		return "", "", fmt.Errorf("%w: read %s: %v", ErrUnavailable, BackendSelectionPath, err)
	}
	raw := strings.TrimSpace(string(data))
	if raw == "" {
		return "", "", nil
	}
	if b, ok := parseBackend(raw); ok {
		return b, raw, nil
	}
	return BackendAuto, raw, nil
}

// WriteBackendSelection atomically writes b to BackendSelectionPath.
// The directory is created with DirectoryPermissions if missing.
// The file is written via temp-file + rename so a partial write
// never leaves an inconsistent selection.
func WriteBackendSelection(b Backend) error {
	if _, ok := parseBackend(string(b)); !ok {
		return fmt.Errorf("credentials: unknown backend %q", b)
	}
	dir := filepath.Dir(BackendSelectionPath)
	if err := os.MkdirAll(dir, DirectoryPermissions); err != nil {
		return fmt.Errorf("%w: mkdir %s: %v", ErrUnavailable, dir, err)
	}
	tmp := fmt.Sprintf("%s.tmp.%d", BackendSelectionPath, os.Getpid())
	fp, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, BackendSelectionFilePermissions)
	if err != nil {
		return fmt.Errorf("%w: create %s: %v", ErrUnavailable, tmp, err)
	}
	cleanup := func() { _ = os.Remove(tmp) }
	if _, err := fp.WriteString(string(b) + "\n"); err != nil {
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
	if err := os.Rename(tmp, BackendSelectionPath); err != nil {
		cleanup()
		return fmt.Errorf("%w: rename %s -> %s: %v", ErrUnavailable, tmp, BackendSelectionPath, err)
	}
	syncDir(dir)
	return nil
}
