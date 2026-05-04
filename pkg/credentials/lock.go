package credentials

import (
	"os"
	"path/filepath"
)

// fileLock holds an advisory lock on the sidecar lock file for one
// FileStore read-modify-write transaction.
type fileLock struct {
	f *os.File
}

func (s *FileStore) lockPath() string {
	return s.path + ".lock"
}

// openLockFile creates the parent directory, opens the sidecar lock file
// with the strict mode, and returns the handle. Platform-specific
// acquireLock layers flock or LockFileEx on top.
func (s *FileStore) openLockFile() (*os.File, error) {
	path := s.lockPath()
	if err := os.MkdirAll(filepath.Dir(path), DirectoryPermissions); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE, FilePermissions)
}
