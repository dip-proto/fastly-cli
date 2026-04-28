package credentials

import (
	"os"
	"path/filepath"
)

// fileLock holds an advisory lock on a sidecar lock file for one
// read-modify-write transaction.
type fileLock struct {
	f *os.File
}

// openLockFileAt creates the parent directory, opens the sidecar lock
// file at path with the strict mode, and returns the handle.
// Platform-specific acquireLockAt layers flock or LockFileEx on top.
func openLockFileAt(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), DirectoryPermissions); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE, FilePermissions)
}

func (s *FileStore) acquireLock() (*fileLock, error) {
	return acquireLockAt(s.path + ".lock")
}
